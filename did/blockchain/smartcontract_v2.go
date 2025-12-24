package blockchain

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/pilacorp/go-credential-sdk/did/signer"
)

//go:embed did-contract/did_registry_smc_abi_v2.json
var smcABIJSONV2 []byte

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

type EthereumDIDRegistryV2 struct {
	contract     *bind.BoundContract
	chainID      *big.Int
	contractAddr common.Address
}

// NewEthereumDIDRegistry creates a new instance of the Ethereum DID Registry client
func NewEthereumDIDRegistryV2(address string, chainID int64) (*EthereumDIDRegistryV2, error) {
	if address == "" {
		return nil, fmt.Errorf("invalid configuration: RPC URL or DID address missing")
	}

	contractAddr := common.HexToAddress(address)

	// Parse JSON from embedded ABI file
	var artifact HardhatArtifact
	err := json.Unmarshal(smcABIJSONV2, &artifact)
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

	return &EthereumDIDRegistryV2{
		contract:     contract,
		chainID:      big.NewInt(chainID),
		contractAddr: contractAddr,
	}, nil
}

// CreateDIDTx creates a new DID transaction.
func (e *EthereumDIDRegistryV2) CreateDIDTx(
	ctx context.Context,
	issuerSig *Signature,
	issuerAddress, didAddress, docHash string,
	txSigner signer.Signer,
	didType DIDType,
	deadline uint,
) (*SubmitTxResult, error) {
	// 1. create auth using a generic signer based on the DID private key.
	fromAddress := common.HexToAddress(didAddress)
	auth := e.getAuthV2(ctx, fromAddress, signer.TxSignerFn(e.chainID, txSigner))

	docHash = strings.TrimPrefix(docHash, "0x")
	docHashBytes, err := hex.DecodeString(docHash)
	if err != nil {
		return nil, fmt.Errorf("failed to decode doc hash: %w", err)
	}

	var docHashBytes32 [32]byte
	copy(docHashBytes32[:], docHashBytes)

	v := uint8(issuerSig.V.Uint64())

	var rBytes, sBytes []byte
	rBytes = issuerSig.R.Bytes()
	sBytes = issuerSig.S.Bytes()
	var r, s [32]byte
	copy(r[32-len(rBytes):], rBytes)
	copy(s[32-len(sBytes):], sBytes)

	deadlineBigInt := big.NewInt(int64(deadline))

	issuerAddr := common.HexToAddress(issuerAddress)

	// 2. use contract to build create did transaction.
	tx, err := e.contract.Transact(auth, "createDID", issuerAddr, didType, docHashBytes32, deadlineBigInt, v, r, s)
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

// CreateIssuerTx builds an unsigned transaction for the createIssuer admin call.
// - txSigner is the signer for the transaction.
// - didAddress is the address that will receive ISSUER_ROLE.
// - permissions is the list of DIDType values the issuer is allowed to issue.
func (e *EthereumDIDRegistryV2) CreateIssuerTx(
	ctx context.Context,
	txSigner signer.Signer,
	didAddress string,
	permissions []DIDType,
) (*SubmitTxResult, error) {
	// 1. create auth using the transaction signer.
	didAdrr := common.HexToAddress(didAddress)
	auth := e.getAuthV2(ctx, didAdrr, signer.TxSignerFn(e.chainID, txSigner))

	// 2. use contract to build createIssuer transaction.
	tx, err := e.contract.Transact(auth, "createIssuer", didAdrr, permissions)
	if err != nil {
		return nil, fmt.Errorf("failed to generate createIssuer Tx: %v", err)
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
func (e *EthereumDIDRegistryV2) IssueDIDPayload(issuerAddress, didAddress, docHash string, didType DIDType, deadline uint) ([]byte, error) {
	payload, err := SolidityPacked(
		[]string{"string", "address", "address", "uint8", "bytes32", "uint256"},
		[]string{"CREATE_DID", issuerAddress, didAddress, strconv.Itoa(int(didType)), docHash, strconv.FormatUint(uint64(deadline), 10)},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to pack solidity values: %w", err)
	}

	return CreateEIP191Payload(e.contractAddr, payload)
}

// getAuth gets the auth for the transaction using an abstract signer function.
func (e *EthereumDIDRegistryV2) getAuthV2(ctx context.Context, fromAddress common.Address, signerFn bind.SignerFn) *bind.TransactOpts {
	// Create the auth with no send transaction to chain.
	return &bind.TransactOpts{
		From:     fromAddress,
		Nonce:    big.NewInt(0),
		Value:    big.NewInt(0),
		GasLimit: uint64(80000),
		GasPrice: big.NewInt(0),
		Context:  ctx,
		Signer:   signerFn,
		NoSend:   true,
	}
}
