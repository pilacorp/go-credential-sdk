package blockchain

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

const AttributeName = "type"

//go:embed did-contract/did_registry_smc_abi.json
var smcABIJSON []byte

// HardhatArtifact struct is restored to parse the ABI file.
type HardhatArtifact struct {
	Format       string          `json:"_format"`
	ContractName string          `json:"contractName"`
	SourceName   string          `json:"sourceName"`
	ABI          json.RawMessage `json:"abi"`
}

type EthereumDIDRegistry struct {
	contract  *bind.BoundContract
	rpcClient string // Store the client for fetching nonce/gas
	chainID   int64
}
type SubmitDIDTX struct {
	TxHex  string // Hex-encoded RLP transaction
	TxHash string // Transaction hash
}

// NewEthereumDIDRegistry creates a new instance of the Ethereum DID Registry client
func NewEthereumDIDRegistry(rpcURL string, didAddress string, chainID int64) (*EthereumDIDRegistry, error) {
	if didAddress == "" {
		return nil, fmt.Errorf("invalid configuration: RPC URL or DID address missing")
	}

	contractAddr := common.HexToAddress(didAddress)

	// Parse JSON from embedded ABI file
	var artifact HardhatArtifact
	err := json.Unmarshal(smcABIJSON, &artifact)
	if err != nil {
		slog.ErrorContext(context.Background(), "Error parsing smc abi JSON", "error", err)
		return nil, fmt.Errorf("error parsing smc abi JSON: %v", err)
	}

	// Parse the ABI from the artifact
	parsedABI, err := abi.JSON(strings.NewReader(string(artifact.ABI)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ABI: %v", err)
	}

	// Create a new bound contract
	contract := bind.NewBoundContract(contractAddr, parsedABI, nil, nil, nil)

	return &EthereumDIDRegistry{
		contract:  contract,
		rpcClient: rpcURL, // Store the client
		chainID:   chainID,
	}, nil
}

// GenerateSetAttributeTx generates a raw, unsigned transaction for setting an attribute.
// This function retains the optimizations (accepts *ecdsa.PrivateKey and *big.Int validity).
func (e *EthereumDIDRegistry) GenerateSetAttributeTx(ctx context.Context, privKey, address, value string) (*SubmitDIDTX, error) {

	result := SubmitDIDTX{}
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
	auth, err := e.newDefaultTransactionOpts(ctx, privateKey)
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

// newDefaultTransactionOpts creates a *bind.TransactOpts with a signer function and default config
// and dynamically fetches the nonce and suggested gas price.
// (This is the optimized function from the previous step)
func (e *EthereumDIDRegistry) newDefaultTransactionOpts(ctx context.Context, privateKey *ecdsa.PrivateKey) (*bind.TransactOpts, error) {
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

// TODO: Implement a function sign tx with get nonce and gas price from rpc

// GenerateSetAttributeTx generates a raw, unsigned transaction for setting an attribute.
// This function retains the optimizations (accepts *ecdsa.PrivateKey and *big.Int validity).
func (e *EthereumDIDRegistry) ReGenerateSetAttributeTx(ctx context.Context, privKey, value string) (*SubmitDIDTX, error) {

	result := SubmitDIDTX{}
	privateKey, err := ParsePrivateKey(privKey)
	publicKeyECDSA, ok := privateKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("-----error casting public key to ECDSA")
	}
	address := strings.ToLower(crypto.PubkeyToAddress(*publicKeyECDSA).Hex())
	if err != nil {
		return &result, err
	}

	// Prepare inputs
	didAddress, nameBytes, valueBytes, validity, err := PrepareAttributeInputs(address, AttributeName, value)
	if err != nil {
		return &result, err
	}

	// Get the auth object with dynamic nonce and gas
	auth, err := e.newTransactionOpts(ctx, privateKey)
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
	result.TxHex = hex.EncodeToString(txBytes)
	result.TxHash = tx.Hash().Hex()

	return &result, nil
}

// Get nonce and gas price from rpc
func (e *EthereumDIDRegistry) newTransactionOpts(ctx context.Context, privateKey *ecdsa.PrivateKey) (*bind.TransactOpts, error) {
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("error casting public key to ECDSA")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	client, err := ethclient.Dial(e.rpcClient)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NDAChain client: %w", err)
	}

	// Fetch the pending nonce
	nonce, err := client.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending nonce: %w", err)
	}

	// Fetch the suggested gas price
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to suggest gas price: %w", err)
	}

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
		Nonce:    big.NewInt(int64(nonce)),
		Value:    big.NewInt(0), // Assuming no ETH is sent
		GasLimit: uint64(0),     // Set to 0 for automatic gas estimation
		GasPrice: gasPrice,
		Context:  ctx,
		Signer:   signer,
	}

	return auth, nil
}
