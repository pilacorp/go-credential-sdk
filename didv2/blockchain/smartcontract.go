package blockchain

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/pilacorp/go-credential-sdk/didv2/signer"
)

// -- Embeds & ABI Handling --

//go:embed did-contract/did_registry_smc_abi.json
var smcABIJSON []byte

var (
	parsedABI    abi.ABI
	parseABIOnce sync.Once
	errParseABI  error
)

// loadABI ensures the ABI is parsed exactly once.
func loadABI() (abi.ABI, error) {
	parseABIOnce.Do(func() {
		type hardhatArtifact struct {
			ABI json.RawMessage `json:"abi"`
		}
		var artifact hardhatArtifact
		if err := json.Unmarshal(smcABIJSON, &artifact); err != nil {
			errParseABI = fmt.Errorf("failed to unmarshal artifact JSON: %w", err)
			return
		}
		parsedABI, errParseABI = abi.JSON(strings.NewReader(string(artifact.ABI)))
	})
	return parsedABI, errParseABI
}

// -- Types --

type DIDType uint8

const (
	DIDTypePeople   DIDType = 0
	DIDTypeItem     DIDType = 1
	DIDTypeActivity DIDType = 2
	DIDTypeLocation DIDType = 3
)

func (d DIDType) String() string {
	switch d {
	case DIDTypePeople:
		return "people"
	case DIDTypeItem:
		return "item"
	case DIDTypeActivity:
		return "activity"
	case DIDTypeLocation:
		return "location"
	default:
		return "unknown"
	}
}

// ParseDIDType converts a string to a DIDType.
func ParseDIDType(s string) (DIDType, error) {
	switch strings.ToLower(s) {
	case "people":
		return DIDTypePeople, nil
	case "item":
		return DIDTypeItem, nil
	case "activity":
		return DIDTypeActivity, nil
	case "location":
		return DIDTypeLocation, nil
	default:
		return 0, fmt.Errorf("invalid DID type: %s", s)
	}
}

type Signature struct {
	V *big.Int
	R *big.Int
	S *big.Int
}

// ClientConfig holds configuration for the DIDContract client.
type ClientConfig struct {
	ContractAddress string
	ChainID         int64
	// Optional: defaults to 0 if not set, suitable for gas-free subnets.
	// For mainnet/L2, these should be configured or estimated dynamically.
	GasPrice *big.Int
	GasLimit uint64
}

type DIDContract struct {
	contract     *bind.BoundContract
	chainID      *big.Int
	contractAddr common.Address
	gasPrice     *big.Int
	gasLimit     uint64
}

// -- Constructor --

// NewDIDContract creates a new instance of the Ethereum DID Registry client.
func NewDIDContract(cfg ClientConfig) (*DIDContract, error) {
	if cfg.ContractAddress == "" {
		return nil, errors.New("contract address is required")
	}

	contractABI, err := loadABI()
	if err != nil {
		return nil, err
	}

	addr := common.HexToAddress(cfg.ContractAddress)
	contract := bind.NewBoundContract(addr, contractABI, nil, nil, nil)

	// Set defaults if zero
	gasLimit := cfg.GasLimit
	if gasLimit == 0 {
		gasLimit = 200000 // Default safety limit
	}
	gasPrice := cfg.GasPrice
	if gasPrice == nil {
		gasPrice = big.NewInt(0)
	}

	return &DIDContract{
		contract:     contract,
		chainID:      big.NewInt(cfg.ChainID),
		contractAddr: addr,
		gasPrice:     gasPrice,
		gasLimit:     gasLimit,
	}, nil
}

// -- Transaction Methods --

type CreateDIDRequest struct {
	IssuerSig     *Signature
	IssuerAddress string
	DocHash       string
	CapID         string
	TxProvider    signer.SignerProvider
	DIDType       DIDType
	Nonce         uint64
}

// CreateDIDTx creates a new DID transaction.
func (e *DIDContract) CreateDIDTx(ctx context.Context, req CreateDIDRequest) (*SubmitTxResult, error) {
	// 1. Prepare Auth
	auth, err := e.getTransactOpts(ctx, req.TxProvider, int64(req.Nonce))
	if err != nil {
		return nil, err
	}

	// 2. Parse Hex Inputs
	docHashBytes, err := hexToBytes32(req.DocHash)
	if err != nil {
		return nil, fmt.Errorf("invalid docHash: %w", err)
	}
	capIdBytes, err := hexToBytes32(req.CapID)
	if err != nil {
		return nil, fmt.Errorf("invalid capId: %w", err)
	}

	// 3. Prepare Signature Components
	v := uint8(req.IssuerSig.V.Uint64())
	r := bytesToBytes32(req.IssuerSig.R.Bytes())
	s := bytesToBytes32(req.IssuerSig.S.Bytes())

	// 4. Build Transaction
	// createDID(address,uint8,bytes32,bytes32,uint8,bytes32,bytes32)
	tx, err := e.contract.Transact(
		auth,
		"createDID",
		common.HexToAddress(req.IssuerAddress),
		req.DIDType,
		docHashBytes,
		capIdBytes,
		v,
		r,
		s,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate createDID Tx: %w", err)
	}

	return serializeTx(tx)
}

// AddIssuerTx creates a new addIssuer transaction.
func (e *DIDContract) AddIssuerTx(ctx context.Context, txProvider signer.SignerProvider, issuerAddress string, permissions []DIDType, nonce int) (*SubmitTxResult, error) {
	auth, err := e.getTransactOpts(ctx, txProvider, int64(nonce))
	if err != nil {
		return nil, err
	}

	tx, err := e.contract.Transact(auth, "addIssuer", common.HexToAddress(issuerAddress), permissions)
	if err != nil {
		return nil, fmt.Errorf("failed to generate addIssuer Tx: %w", err)
	}

	return serializeTx(tx)
}

// -- Helpers --

// hexToBytes32 decodes a hex string (with or without 0x) into a 32-byte array.
func hexToBytes32(s string) ([32]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		return [32]byte{}, err
	}
	if len(b) != 32 {
		return [32]byte{}, fmt.Errorf("length must be 32 bytes, got %d", len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

// bytesToBytes32 copies a slice into a 32-byte array, left-padding if necessary is handled by standard big.Int behavior usually,
// but here we align strictly to the end for standard Ethereum signatures (r/s).
func bytesToBytes32(in []byte) [32]byte {
	var out [32]byte
	if len(in) > 32 {
		// Truncate if too long (unlikely for standard R/S but safe to handle)
		copy(out[:], in[len(in)-32:])
	} else {
		// Right-align (standard for numbers, though R/S usually come as exactly 32 bytes)
		copy(out[32-len(in):], in)
	}
	return out
}

func serializeTx(tx *types.Transaction) (*SubmitTxResult, error) {
	var buf bytes.Buffer
	if err := rlp.Encode(&buf, tx); err != nil {
		return nil, fmt.Errorf("failed to serialize transaction: %w", err)
	}
	return &SubmitTxResult{
		TxHex:  hex.EncodeToString(buf.Bytes()),
		TxHash: tx.Hash().Hex(),
	}, nil
}

// getTransactOpts creates the auth options for a transaction.
func (e *DIDContract) getTransactOpts(ctx context.Context, provider signer.SignerProvider, nonce int64) (*bind.TransactOpts, error) {
	fromAddress := common.HexToAddress(provider.GetAddress())
	signerFn := func(addr common.Address, tx *types.Transaction) (*types.Transaction, error) {
		eip155Signer := types.NewEIP155Signer(e.chainID)
		h := eip155Signer.Hash(tx)
		sig, err := provider.Sign(h.Bytes())
		if err != nil {
			return nil, err
		}
		return tx.WithSignature(eip155Signer, sig)
	}

	return &bind.TransactOpts{
		From:     fromAddress,
		Nonce:    big.NewInt(nonce),
		Value:    big.NewInt(0),
		GasLimit: e.gasLimit,
		GasPrice: e.gasPrice,
		Context:  ctx,
		Signer:   signerFn,
		NoSend:   true, // We are returning the raw TX, not sending it immediately
	}, nil
}
