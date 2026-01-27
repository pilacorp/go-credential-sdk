// Package didcontract provides functionality for interacting with the DID Registry smart contract.
//
// This package handles:
//   - Building transaction data for creating DIDs on-chain
//   - Signing transactions to create raw transactions
//   - Querying contract state (epoch, nonce)
//
// The SDK does not submit transactions to the blockchain. It only creates raw
// transactions that must be submitted separately.
package didcontract

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
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/pilacorp/go-credential-sdk/didv2/signer"
)

//go:embed did_registry_smc_abi.json
var smcABIJSON []byte

var (
	parsedABI    abi.ABI
	parseABIOnce sync.Once
	errParseABI  error
)

// loadABI loads and parses the DID Registry smart contract ABI exactly once.
//
// The ABI is embedded at compile time and parsed lazily on first use.
// Returns the parsed ABI or an error if parsing fails.
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

// Contract is a client for interacting with the DID Registry smart contract.
//
// It provides methods for:
//   - Creating signed transactions for DID creation
//   - Querying contract state (capability epoch, nonce)
//
// The RPC client is optional. If not available, read operations will fail
// but transaction creation can still work with manual nonce/epoch values.
type Contract struct {
	contract  *bind.BoundContract
	rpcClient *ethclient.Client
	cfg       *Config
}

// NewContract creates a new Contract client for the DID Registry smart contract.
//
// The config parameter must contain a valid contract address and chain ID.
// The RPC URL is optional but required for read operations (GetCapabilityEpoch, GetNonce).
// If RPC connection fails, the client is still created but read operations will fail.
//
// Returns a Contract instance or an error if configuration is invalid or ABI loading fails.
func NewContract(cfg *Config) (*Contract, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	cfg.Standardize()

	// ignore error when connect RPC fail.
	client, err := ethclient.Dial(cfg.RPCURL)
	if err != nil {
		fmt.Println("failed to init RPC client, some features may not work: ", err.Error())
	}

	contractABI, err := loadABI()
	if err != nil {
		return nil, err
	}

	contract := bind.NewBoundContract(common.HexToAddress(cfg.ContractAddress), contractABI, client, client, nil)

	return &Contract{
		contract:  contract,
		rpcClient: client,
		cfg:       cfg,
	}, nil
}

// CreateDIDTx creates a signed raw transaction for creating a DID on-chain.
//
// This method:
//   - Validates the request parameters
//   - Builds the transaction data according to the smart contract ABI
//   - Signs the transaction using the provided txSigner
//   - Serializes the transaction to raw hex format
//
// The SDK does not submit the transaction. The returned Transaction.TxHex
// must be submitted to the blockchain separately.
//
// The ctx parameter is used for transaction signing context.
// The req parameter contains all the data needed for DID creation.
// The txSigner parameter must be a valid SignerProvider with the DID's private key.
//
// Returns a Transaction containing the raw transaction hex and transaction hash,
// or an error if transaction creation fails.
func (e *Contract) CreateDIDTx(ctx context.Context, req *CreateDIDRequest, txSigner signer.SignerProvider) (*Transaction, error) {
	if txSigner == nil {
		return nil, fmt.Errorf("tx signer is required")
	}

	// 1. Prepare Auth
	auth, err := e.getTransactOpts(ctx, txSigner, int64(req.Nonce))
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
		uint8(req.DIDType),
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

// GetCapabilityEpoch retrieves the current capability epoch for an issuer from the blockchain.
//
// The capability epoch is used to validate issuer signatures. Issuers can revoke
// all previous signatures by incrementing the epoch on-chain.
//
// The ctx parameter is used for the blockchain query context.
// The signerAddr parameter is the Ethereum address of the Issuer.
//
// Requires a valid RPC client. Returns the current epoch or an error if the query fails.
func (e *Contract) GetCapabilityEpoch(ctx context.Context, signerAddr string) (uint64, error) {
	if signerAddr == "" {
		return 0, errors.New("signer address is required")
	}

	if e.rpcClient == nil {
		return 0, fmt.Errorf("RPC client is not initialized, please check RPC URL and try again")
	}

	var out []interface{}
	err := e.contract.Call(&bind.CallOpts{Context: ctx}, &out, "getCapabilityEpoch", common.HexToAddress(signerAddr))
	if err != nil {
		return 0, fmt.Errorf("contract call failed: %w", err)
	}

	if len(out) == 0 {
		return 0, errors.New("contract returned no data")
	}

	epoch, ok := out[0].(uint64)
	if !ok {
		return 0, fmt.Errorf("unexpected output type: %T", out[0])
	}

	return epoch, nil
}

// GetNonce retrieves the current transaction nonce for an address from the blockchain.
//
// The nonce is a sequential number that ensures each transaction is unique.
// It must be incremented for each new transaction from the same address.
//
// The ctx parameter is used for the blockchain query context.
// The address parameter is the Ethereum address to query the nonce for.
//
// Requires a valid RPC client. Returns the current nonce or an error if the query fails.
func (e *Contract) GetNonce(ctx context.Context, address common.Address) (uint64, error) {
	if e.rpcClient == nil {
		return 0, fmt.Errorf("RPC client is not initialized, please check RPC URL and try again")
	}

	nonce, err := e.rpcClient.PendingNonceAt(ctx, address)
	if err != nil {
		return 0, fmt.Errorf("failed to get nonce: %w", err)
	}

	return nonce, nil
}

// getTransactOpts creates transaction authorization options for signing.
//
// This is an internal method that sets up the transaction signer function
// using EIP-155 signing with the provided chain ID.
func (e *Contract) getTransactOpts(ctx context.Context, provider signer.SignerProvider, nonce int64) (*bind.TransactOpts, error) {
	fromAddress := common.HexToAddress(provider.GetAddress())
	signerFn := func(addr common.Address, tx *types.Transaction) (*types.Transaction, error) {
		eip155Signer := types.NewEIP155Signer(big.NewInt(e.cfg.ChainID))
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
		GasLimit: e.cfg.GasLimit,
		GasPrice: e.cfg.GasPrice,
		Context:  ctx,
		Signer:   signerFn,
		NoSend:   true, // We are returning the raw TX, not sending it immediately
	}, nil
}

// hexToBytes32 decodes a hex string into a 32-byte array.
//
// The input can include or omit the "0x" prefix.
// Returns an error if the hex string is invalid or not exactly 32 bytes.
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

// bytesToBytes32 converts a byte slice to a 32-byte array.
//
// For Ethereum signatures (R/S components), the bytes are right-aligned.
// If the input is longer than 32 bytes, it is truncated from the left.
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

// serializeTx serializes a transaction to RLP-encoded hex format and computes its hash.
//
// The transaction is encoded using RLP (Recursive Length Prefix) encoding,
// which is the standard format for Ethereum transactions.
// Returns a Transaction with the hex-encoded transaction and its hash.
func serializeTx(tx *types.Transaction) (*Transaction, error) {
	var buf bytes.Buffer

	if err := rlp.Encode(&buf, tx); err != nil {
		return nil, fmt.Errorf("failed to serialize transaction: %w", err)
	}

	return &Transaction{
		TxHex:  hex.EncodeToString(buf.Bytes()),
		TxHash: tx.Hash().Hex(),
	}, nil
}
