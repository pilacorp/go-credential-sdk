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
	"github.com/ethereum/go-ethereum/ethclient"
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
	rpcURL       string
}

// NewEthereumDIDRegistry creates a new instance of the Ethereum DID Registry client
func NewEthereumDIDRegistryV2(address string, chainID int64, rpcURL string) (*EthereumDIDRegistryV2, error) {
	if address == "" {
		return nil, fmt.Errorf("invalid configuration: RPC URL or DID address missing")
	}

	if rpcURL == "" {
		return nil, fmt.Errorf("invalid configuration: RPC URL missing")
	}

	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to dial RPC: %w", err)
	}

	contractAddr := common.HexToAddress(address)

	// Parse JSON from embedded ABI file
	var artifact HardhatArtifact
	err = json.Unmarshal(smcABIJSONV2, &artifact)
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
	contract := bind.NewBoundContract(contractAddr, parsedABI, client, client, nil)

	return &EthereumDIDRegistryV2{
		contract:     contract,
		chainID:      big.NewInt(chainID),
		contractAddr: contractAddr,
		rpcURL:       rpcURL,
	}, nil
}

// CreateDIDTx creates a new DID transaction.
func (e *EthereumDIDRegistryV2) CreateDIDTx(
	ctx context.Context,
	issuerSig *Signature,
	signerAddress, didAddress, docHash, capId string, // capId NEW, deadline removed
	txSigner signer.Signer,
	didType DIDType,
) (*SubmitTxResult, error) {

	// 1. Auth for msg.sender = didAddress
	fromAddress := common.HexToAddress(didAddress)
	auth := e.getAuthV2(ctx, fromAddress, signer.TxSignerFn(e.chainID, txSigner))

	// 2. docHash -> bytes32
	docHash = strings.TrimPrefix(docHash, "0x")
	docHashBytes, err := hex.DecodeString(docHash)
	if err != nil {
		return nil, fmt.Errorf("failed to decode doc hash: %w", err)
	}
	if len(docHashBytes) != 32 {
		return nil, fmt.Errorf("invalid docHash length: expected 32 bytes, got %d", len(docHashBytes))
	}
	var docHashBytes32 [32]byte
	copy(docHashBytes32[:], docHashBytes)

	// 3. capId -> bytes32
	capId = strings.TrimPrefix(capId, "0x")
	capIdBytes, err := hex.DecodeString(capId)
	if err != nil {
		return nil, fmt.Errorf("failed to decode capId: %w", err)
	}
	if len(capIdBytes) != 32 {
		return nil, fmt.Errorf("invalid capId length: expected 32 bytes, got %d", len(capIdBytes))
	}
	var capIdBytes32 [32]byte
	copy(capIdBytes32[:], capIdBytes)

	// 4. signature v,r,s (pad r,s to 32 bytes)
	v := uint8(issuerSig.V.Uint64())

	rBytes := issuerSig.R.Bytes()
	sBytes := issuerSig.S.Bytes()

	var r, s [32]byte
	copy(r[32-len(rBytes):], rBytes)
	copy(s[32-len(sBytes):], sBytes)

	signerAddr := common.HexToAddress(signerAddress)

	// 5. Transact with NEW arg list:
	// createDID(address signer, DIDType didType, bytes32 docHash, bytes32 capId, uint8 v, bytes32 r, bytes32 s)
	tx, err := e.contract.Transact(
		auth,
		"createDID",
		signerAddr,
		didType,
		docHashBytes32,
		capIdBytes32,
		v,
		r,
		s,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate createDID Tx: %w", err)
	}

	// 6. Serialize tx
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

func (e *EthereumDIDRegistryV2) GetCapabilityEpoch(
	ctx context.Context,
	signerAddr string,
) (uint64, error) {
	if signerAddr == "" {
		return 0, fmt.Errorf("invalid configuration: signer address missing")
	}

	if e.rpcURL == "" {
		return 0, fmt.Errorf("invalid configuration: RPC URL missing")
	}

	signer := common.HexToAddress(signerAddr)

	var out []interface{}
	callOpts := &bind.CallOpts{
		Context: ctx,
	}

	if err := e.contract.Call(callOpts, &out, "getCapabilityEpoch", signer); err != nil {
		return 0, fmt.Errorf("getCapabilityEpoch call failed: %w", err)
	}

	if len(out) != 1 {
		return 0, fmt.Errorf("unexpected outputs len=%d", len(out))
	}

	epoch, ok := out[0].(uint64)
	if !ok {
		return 0, fmt.Errorf("unexpected output type: %T (value=%v)", out[0], out[0])
	}

	return epoch, nil
}

// IssueDIDPayload creates the signed payload used by _requireValidCapCreate(...).
// It MUST match the Solidity hashing layout (type order + encodePacked).
func (e *EthereumDIDRegistryV2) IssueDIDPayload(
	_ context.Context,
	signerAddress, didAddress string,
	didType DIDType,
	capId string,
	epoch uint64,
) ([]byte, error) {
	// Normalize bytes32 hex inputs
	capId = strings.TrimSpace(capId)
	if !strings.HasPrefix(capId, "0x") {
		capId = "0x" + capId
	}
	// Basic sanity: bytes32 is 32 bytes = 64 hex chars + "0x" => len 66
	if len(capId) != 66 {
		return nil, fmt.Errorf("invalid capId length: expected bytes32 hex (66 chars with 0x), got %d", len(capId))
	}

	// IMPORTANT: this action string must match the contract verifier exactly.
	const Action = "CAP_CREATE"

	// print all
	slog.Info("IssueDIDPayload", "signerAddress", signerAddress, "didAddress", didAddress, "didType", didType, "epoch", epoch, "capId", capId)

	payload, err := SolidityPacked(
		[]string{"string", "address", "address", "uint8", "uint64", "bytes32"},
		[]string{Action, signerAddress, didAddress, strconv.Itoa(int(didType)), strconv.FormatUint(epoch, 10), capId},
	)

	if err != nil {
		return nil, fmt.Errorf("failed to pack solidity values: %w", err)
	}

	// Same EIP-191 wrapper you used previously
	return CreateEIP191Payload(e.contractAddr, payload)
}

// getAuth gets the auth for the transaction using an abstract signer function.
func (e *EthereumDIDRegistryV2) getAuthV2(ctx context.Context, fromAddress common.Address, signerFn bind.SignerFn) *bind.TransactOpts {
	// Create the auth with no send transaction to chain.
	return &bind.TransactOpts{
		From:     fromAddress,
		Nonce:    big.NewInt(0),
		Value:    big.NewInt(0),
		GasLimit: uint64(200000),
		GasPrice: big.NewInt(0),
		Context:  ctx,
		Signer:   signerFn,
		NoSend:   true,
	}
}
