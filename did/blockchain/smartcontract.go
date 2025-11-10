package blockchain

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
)

// The ABI path constant is restored as requested.
const smc_abi_path = "did/blockchain/did-contract/did_registry_smc_abi.json"
const AttributeName = "type"

// HardhatArtifact struct is restored to parse the ABI file.
type HardhatArtifact struct {
	Format       string          `json:"_format"`
	ContractName string          `json:"contractName"`
	SourceName   string          `json:"sourceName"`
	ABI          json.RawMessage `json:"abi"`
}

type EthereumDIDRegistry struct {
	contract *bind.BoundContract
	client   *ethclient.Client // Store the client for fetching nonce/gas
	chainID  int64
}
type SubmitTxResult struct {
	TxHex  string // Hex-encoded RLP transaction
	TxHash string // Transaction hash
}

// NewEthereumDIDRegistry creates a new instance of the Ethereum DID Registry client
func NewEthereumDIDRegistry(DIDAddress string, chainID int64) (*EthereumDIDRegistry, error) {
	if DIDAddress == "" {
		return nil, fmt.Errorf("invalid configuration: RPC URL or DID address missing")
	}

	contractAddr := common.HexToAddress(DIDAddress)

	// --- File-based ABI loading (restored from original) ---
	file, err := os.Open(smc_abi_path)
	if err != nil {
		return nil, fmt.Errorf("error opening abi file: %v", err)
	}
	defer file.Close()

	// Read file contents
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("error reading abi file: %v", err)
	}

	// Parse JSON into the HardhatArtifact struct
	var artifact HardhatArtifact
	err = json.Unmarshal(data, &artifact)
	if err != nil {
		return nil, fmt.Errorf("error parsing smc abi JSON: %v", err)
	}

	// Parse the ABI from the artifact
	parsedABI, err := abi.JSON(strings.NewReader(string(artifact.ABI)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ABI: %v", err)
	}
	// --- End of file-based ABI loading ---

	// Create a new bound contract
	contract := bind.NewBoundContract(contractAddr, parsedABI, nil, nil, nil)

	return &EthereumDIDRegistry{
		contract: contract,
		client:   nil, // Store the client
		chainID:  chainID,
	}, nil
}

// GenerateSetAttributeTx generates a raw, unsigned transaction for setting an attribute.
// This function retains the optimizations (accepts *ecdsa.PrivateKey and *big.Int validity).
func (e *EthereumDIDRegistry) GenerateSetAttributeTx(ctx context.Context, privKey, address, value string) (*SubmitTxResult, error) {

	result := SubmitTxResult{}
	privateKey, err := ParsePrivateKey(privKey)
	if err != nil {
		return &result, err
	}

	// Prepare inputs
	didAddress, nameBytes, valueBytes, validity, err := PrepareAttributeInputs(address, AttributeName, value)
	if err != nil {
		return &result, err
	}

	// Get the auth object with dynamic nonce and gas
	auth, err := e.newSignedTransactOpts(ctx, privateKey)
	if err != nil {
		return &result, fmt.Errorf("failed to create transaction options: %w", err)
	}

	// We are only generating, not sending
	auth.NoSend = true

	// Use the contract's Transact method
	tx, err := e.contract.Transact(auth, "setAttribute", didAddress, nameBytes, valueBytes, validity)
	if err != nil {
		return &result, fmt.Errorf("failed to generate setAttribute Tx: %v", err)
	}

	// Serialize transaction to hex.
	var buf bytes.Buffer
	if err := rlp.Encode(&buf, tx); err != nil {
		return &result, fmt.Errorf("failed to serialize transaction: %w", err)
	}

	txBytes := buf.Bytes()
	rawTxHex := hex.EncodeToString(txBytes)
	result.TxHex = rawTxHex
	result.TxHash = tx.Hash().Hex()

	return &result, nil
}

// newSignedTransactOpts creates a *bind.TransactOpts with a signer function
// and dynamically fetches the nonce and suggested gas price.
// (This is the optimized function from the previous step)
func (e *EthereumDIDRegistry) newSignedTransactOpts(ctx context.Context, privateKey *ecdsa.PrivateKey) (*bind.TransactOpts, error) {
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("error casting public key to ECDSA")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	chainID := big.NewInt(e.chainID)

	// Create a signer function
	signer := func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
		signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
		if err != nil {
			return nil, err
		}
		return signedTx, nil
	}

	// Create the auth object
	auth := &bind.TransactOpts{
		From:     fromAddress,
		Nonce:    big.NewInt(0),
		Value:    big.NewInt(0), // Assuming no ETH is sent
		GasLimit: uint64(80000), // Set to 0 for automatic gas estimation
		GasPrice: big.NewInt(0),
		Context:  ctx,
		Signer:   signer,
	}

	return auth, nil
}

//TODO: Implement a function sign tx with get nonce and gas price from rpc
