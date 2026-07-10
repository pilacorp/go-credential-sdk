package vccontract

import (
	"context"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

//go:embed smartcontract/credential_registry_smc_abi.json
var credentialRegistryABIJSON []byte

var (
	parsedABI    abi.ABI
	parseABIOnce sync.Once
	errParseABI  error
)

// loadABI parses the embedded Credential Registry ABI exactly once.
func loadABI() (abi.ABI, error) {
	parseABIOnce.Do(func() {
		parsedABI, errParseABI = abi.JSON(strings.NewReader(string(credentialRegistryABIJSON)))
	})

	return parsedABI, errParseABI
}

// CredentialRegistry is a read-only client for the Credential Registry smart
// contract.
//
// It performs on-chain reads only (eth_call) and therefore needs neither a
// private key nor gas. Construct one with NewCredentialRegistry and release it with Close.
type CredentialRegistry struct {
	client   *ethclient.Client
	contract *bind.BoundContract
}

// NewCredentialRegistry connects to the chain and returns a client for the
// Credential Registry contract at contractAddress.
//
// rpcURL and contractAddress are required. Unlike a transaction client, a working
// RPC connection is mandatory here because every operation is an on-chain read.
func NewCredentialRegistry(rpcURL, contractAddress string) (*CredentialRegistry, error) {
	if rpcURL == "" {
		return nil, errors.New("RPC URL is required")
	}

	if !common.IsHexAddress(contractAddress) {
		return nil, fmt.Errorf("invalid contract address: %q", contractAddress)
	}

	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RPC %q: %w", rpcURL, err)
	}

	contractABI, err := loadABI()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to load contract ABI: %w", err)
	}

	return &CredentialRegistry{
		client: client,
		contract: bind.NewBoundContract(
			common.HexToAddress(contractAddress),
			contractABI,
			client,
			client,
			client,
		),
	}, nil
}

// Close releases the underlying RPC connection.
func (v *CredentialRegistry) Close() {
	if v.client != nil {
		v.client.Close()
	}
}

// VerifyVCHashOnChain checks whether a VC hash (the leaf) is anchored in the
// issuer's on-chain Merkle tree.
//
// Returns true when the leaf is proven to be in the tree, false when the proof
// does not validate (both with a nil error). A non-nil error means the call
// itself failed — malformed input, RPC failure, or the tree does not exist.
func (v *CredentialRegistry) VerifyVCHashOnChain(ctx context.Context, req *VerifyRequest) (bool, error) {
	if err := req.Validate(); err != nil {
		return false, err
	}

	leaf, proof, err := decodeLeafAndProof(req)
	if err != nil {
		return false, err
	}

	var out []interface{}
	err = v.contract.Call(
		&bind.CallOpts{Context: ctx},
		&out,
		"verifyVC",
		common.HexToAddress(req.IssuerAddress),
		new(big.Int).SetUint64(req.TreeIndex),
		leaf,
		proof,
	)
	if err != nil {
		return false, fmt.Errorf("verifyVC call failed: %w", err)
	}

	if len(out) == 0 {
		return false, errors.New("verifyVC returned no data")
	}

	ok, isBool := out[0].(bool)
	if !isBool {
		return false, fmt.Errorf("unexpected verifyVC output type: %T", out[0])
	}

	return ok, nil
}

// GetTreeRoot returns the on-chain Merkle root for the given issuer and tree
// index. A zero value means no such tree has been anchored.
func (v *CredentialRegistry) GetTreeRoot(ctx context.Context, issuerAddress string, treeIndex uint64) ([32]byte, error) {
	if !common.IsHexAddress(issuerAddress) {
		return [32]byte{}, fmt.Errorf("invalid issuer address: %q", issuerAddress)
	}

	var out []interface{}
	err := v.contract.Call(
		&bind.CallOpts{Context: ctx},
		&out,
		"getTreeRoot",
		common.HexToAddress(issuerAddress),
		new(big.Int).SetUint64(treeIndex),
	)
	if err != nil {
		return [32]byte{}, fmt.Errorf("getTreeRoot call failed: %w", err)
	}

	if len(out) == 0 {
		return [32]byte{}, errors.New("getTreeRoot returned no data")
	}

	root, ok := out[0].([32]byte)
	if !ok {
		return [32]byte{}, fmt.Errorf("unexpected getTreeRoot output type: %T", out[0])
	}

	return root, nil
}

// HasTree reports whether the issuer has an anchored tree at the given index.
func (v *CredentialRegistry) HasTree(ctx context.Context, issuerAddress string, treeIndex uint64) (bool, error) {
	if !common.IsHexAddress(issuerAddress) {
		return false, fmt.Errorf("invalid issuer address: %q", issuerAddress)
	}

	var out []interface{}
	err := v.contract.Call(
		&bind.CallOpts{Context: ctx},
		&out,
		"treeExists",
		common.HexToAddress(issuerAddress),
		new(big.Int).SetUint64(treeIndex),
	)
	if err != nil {
		return false, fmt.Errorf("treeExists call failed: %w", err)
	}

	if len(out) == 0 {
		return false, errors.New("treeExists returned no data")
	}

	exists, ok := out[0].(bool)
	if !ok {
		return false, fmt.Errorf("unexpected treeExists output type: %T", out[0])
	}

	return exists, nil
}

// decodeLeafAndProof converts the hex request fields into the byte forms the
// contract call expects.
func decodeLeafAndProof(req *VerifyRequest) ([32]byte, [][32]byte, error) {
	leaf, err := hexToBytes32(req.Leaf)
	if err != nil {
		return [32]byte{}, nil, fmt.Errorf("invalid leaf: %w", err)
	}

	proof, err := parseProof(req.Proof)
	if err != nil {
		return [32]byte{}, nil, err
	}

	return leaf, proof, nil
}

// hexToBytes32 decodes a hex string (with or without a "0x" prefix) into a
// 32-byte array. It returns an error if the input is not valid hex or is not
// exactly 32 bytes long.
func hexToBytes32(s string) ([32]byte, error) {
	s = strings.TrimPrefix(s, "0x")

	b, err := hex.DecodeString(s)
	if err != nil {
		return [32]byte{}, fmt.Errorf("invalid hex: %w", err)
	}

	if len(b) != 32 {
		return [32]byte{}, fmt.Errorf("length must be 32 bytes, got %d", len(b))
	}

	var out [32]byte
	copy(out[:], b)

	return out, nil
}

// parseProof decodes each hex-encoded sibling into a 32-byte array.
func parseProof(proof []string) ([][32]byte, error) {
	out := make([][32]byte, len(proof))

	for i, p := range proof {
		b, err := hexToBytes32(p)
		if err != nil {
			return nil, fmt.Errorf("proof element %d: %w", i, err)
		}

		out[i] = b
	}

	return out, nil
}
