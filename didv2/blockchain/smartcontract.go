package blockchain

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

const smc_abi_path = "didv2/blockchain/did-contract/did_registry_smc_abi.json"

type DIDType uint8

const (
	DIDTypePeople   DIDType = 0
	DIDTypeItem     DIDType = 1
	DIDTypeActivity DIDType = 3
	DIDTypeLocation DIDType = 4
)

// Signature represents the signature of a transaction
type Signature struct {
	V *big.Int
	R *big.Int
	S *big.Int
}

// hardhatArtifact represents the structure of a Hardhat artifact JSON
type hardhatArtifact struct {
	Format       string          `json:"_format"`
	ContractName string          `json:"contractName"`
	SourceName   string          `json:"sourceName"`
	ABI          json.RawMessage `json:"abi"`
}

type EthereumDIDRegistry struct {
	contract     *bind.BoundContract
	chainID      int64
	contractAddr common.Address
}

// NewEthereumDIDRegistry creates a new instance of the Ethereum DID Registry client
func NewEthereumDIDRegistry(address string, chainID int64) (*EthereumDIDRegistry, error) {
	if address == "" {
		return nil, fmt.Errorf("invalid configuration: RPC URL or DID address missing")
	}

	contractAddr := common.HexToAddress(address)

	file, err := os.Open(smc_abi_path)
	if err != nil {
		slog.ErrorContext(context.Background(), "Error opening abi file", "error", err)
		return nil, fmt.Errorf("error opening abi file: %v", err)
	}
	defer file.Close()

	// Read file contents
	data, err := io.ReadAll(file)
	if err != nil {
		slog.ErrorContext(context.Background(), "Error reading abi file", "error", err)
		return nil, fmt.Errorf("error reading abi file: %v", err)
	}

	// Parse JSON into an array of DIDRegistry
	var artifact hardhatArtifact
	err = json.Unmarshal(data, &artifact)
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
		contract:     contract,
		chainID:      chainID,
		contractAddr: contractAddr,
	}, nil
}

// CreateDIDTx creates a new DID transaction.
func (e *EthereumDIDRegistry) CreateDIDTx(
	ctx context.Context,
	issuerSig *Signature,
	issuerAddress, didPriv, didAddress, docHash string,
	didType DIDType,
	deadline uint,
) (*SubmitTxResult, error) {
	// 1. create auth with didPrv.
	privateKey, err := ParsePrivateKey(didPriv)
	if err != nil {
		return nil, err
	}

	auth, err := e.getAuthFirstSubmit(ctx, privateKey)
	if err != nil {
		return nil, err
	}

	// only build transaciton, not send transaction to chain.
	auth.NoSend = true

	// 2. use contract to build create did transaction.
	tx, err := e.contract.Transact(auth, "createDID", issuerAddress, didType, docHash, deadline, issuerSig.V, issuerSig.R, issuerSig.S)
	if err != nil {
		return nil, fmt.Errorf("failed to generate createDID Tx: %v", err)
	}

	// 3. serialize transaction to hex.
	var buf bytes.Buffer
	if err := rlp.Encode(&buf, tx); err != nil {
		return nil, fmt.Errorf("failed to serialize transaction: %w", err)
	}

	return &SubmitTxResult{
		TxHex:  hex.EncodeToString(buf.Bytes()),
		TxHash: tx.Hash().Hex(),
	}, nil
}

// IssueDIDPayload creates a payload for the create DID transaction, which is signed by the issuer.
func (e *EthereumDIDRegistry) IssueDIDPayload(issuerAddress, didAddress, docHash string, didType DIDType, deadline uint) ([]byte, error) {
	payload, err := SolidityPacked(
		[]string{"string", "address", "address", "uint8", "bytes32", "uint256"},
		[]string{"CREATE_DID", issuerAddress, didAddress, strconv.Itoa(int(didType)), docHash, strconv.FormatUint(uint64(deadline), 10)},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to pack solidity values: %w", err)
	}

	return CreateEIP191Payload(e.contractAddr, payload)
}

// This function is used to submit the first transaction to the blockchain only (set attributes)
func (e *EthereumDIDRegistry) getAuthFirstSubmit(ctx context.Context, privateKey *ecdsa.PrivateKey) (*bind.TransactOpts, error) {
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("error casting public key to ECDSA")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	// Hardcoded chain ID - replace with your network's chain ID
	chainID := big.NewInt(e.chainID) // 1

	// Create a signer function that will use the private key for signing
	signer := func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
		// This function will be called when a transaction needs to be signed
		signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
		if err != nil {
			return nil, err
		}
		return signedTx, nil
	}

	// Create the auth with hardcoded values
	auth := &bind.TransactOpts{
		From:     fromAddress, // This should be derived from your private key
		Nonce:    big.NewInt(0),
		Value:    big.NewInt(0),
		GasLimit: uint64(80000),
		GasPrice: big.NewInt(0),
		Context:  ctx,
		Signer:   signer, // Use our custom signer function
	}

	return auth, nil
}
