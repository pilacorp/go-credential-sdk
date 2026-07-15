package vccontract

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

//go:embed smartcontract/credential_registry_smc_abi.json
var credentialRegistryABIJSON []byte

// anchoredRootEvent is the log emitted by the Credential Registry when one
// transaction anchors new roots for a batch of trees at once. Its three parallel
// arrays are read to recover the root a specific transaction recorded.
const anchoredRootEvent = "BatchTreesUpdated"

var (
	parsedABI    abi.ABI
	parseABIOnce sync.Once
	errParseABI  error
)

var (
	// ErrTxNotFound is returned when the chain has no receipt for the tx hash,
	// either because it is unknown or because it has not been mined yet.
	ErrTxNotFound = errors.New("transaction not found")
	// ErrTxReverted is returned when the tx exists but failed, so it anchored
	// nothing.
	ErrTxReverted = errors.New("transaction reverted")
	// ErrRootNotAnchored is returned when the tx succeeded but carries no root
	// for the requested issuer and tree index.
	ErrRootNotAnchored = errors.New("transaction did not anchor a root for this issuer and tree index")
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
// It performs on-chain reads only (eth_call and receipt reads) and therefore
// needs neither a private key nor gas. Construct one with NewCredentialRegistry
// and release it with Close.
type CredentialRegistry struct {
	client   *ethclient.Client
	contract *bind.BoundContract
	abi      abi.ABI
	address  common.Address
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

	address := common.HexToAddress(contractAddress)

	return &CredentialRegistry{
		client:  client,
		address: address,
		abi:     contractABI,
		contract: bind.NewBoundContract(
			address,
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

	leaf, proof, err := decodeLeafAndProof(req.Leaf, req.Proof)
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

// VerifyVCHashByTx checks the client-supplied Merkle proof components against the
// root that a specific transaction anchored on-chain, read from that
// transaction's receipt logs.
//
// This is the counterpart to VerifyVCHashOnChain for proofs that the tree's
// current state can no longer confirm: an unsealed tree's root is overwritten by
// each later anchoring, so a proof taken at an earlier anchoring only ever matches
// the root recorded in that anchoring's transaction. The proof and the tx hash
// must therefore come from the same anchoring.
//
// Returns true when the leaf, folded with its proof, reproduces the root that
// req.TxHash anchored for the issuer and tree index. Returns false with a nil
// error when the proof does not validate, when the transaction reverted, or when
// the transaction anchored no root for this issuer and tree index. A non-nil error
// means the check could not be completed — malformed input, RPC failure, or the
// transaction not found / not yet mined (ErrTxNotFound).
func (v *CredentialRegistry) VerifyVCHashByTx(ctx context.Context, req *VerifyByTxRequest) (bool, error) {
	if err := req.Validate(); err != nil {
		return false, err
	}

	leaf, proof, err := decodeLeafAndProof(req.Leaf, req.Proof)
	if err != nil {
		return false, err
	}

	txHash, err := hexToBytes32(req.TxHash)
	if err != nil {
		return false, fmt.Errorf("invalid tx hash: %w", err)
	}

	root, err := v.GetAnchoredRoot(
		ctx,
		common.Hash(txHash),
		common.HexToAddress(req.IssuerAddress),
		req.TreeIndex,
	)
	switch {
	// The transaction reverted or records no root for this tree, so it cannot
	// attest the leaf: a definitive "not verified", not a failure to check.
	case errors.Is(err, ErrTxReverted), errors.Is(err, ErrRootNotAnchored):
		return false, nil
	case err != nil:
		return false, err
	}

	return verifyMerkleProof(leaf, proof, root), nil
}

// GetAnchoredRoot returns the Merkle root that txHash anchored on-chain for the
// given issuer and tree index, read from the BatchTreesUpdated logs of the
// transaction's receipt.
//
// A single transaction anchors many trees at once, so the event carries parallel
// arrays and only the entry matching both the issuer and the tree index belongs
// to the caller's tree. Returns ErrTxNotFound when no receipt exists (unknown or
// unmined), ErrTxReverted when the transaction failed, and ErrRootNotAnchored when
// it succeeded but recorded no root for this issuer and tree index.
func (v *CredentialRegistry) GetAnchoredRoot(ctx context.Context, txHash common.Hash, issuer common.Address, treeIndex uint64) ([32]byte, error) {
	var root [32]byte

	receipt, err := v.client.TransactionReceipt(ctx, txHash)
	if err != nil {
		if errors.Is(err, ethereum.NotFound) {
			return root, ErrTxNotFound
		}

		return root, fmt.Errorf("failed to get transaction receipt: %w", err)
	}

	if receipt.Status != types.ReceiptStatusSuccessful {
		return root, ErrTxReverted
	}

	eventID := v.abi.Events[anchoredRootEvent].ID
	treeIndexBig := new(big.Int).SetUint64(treeIndex)

	for _, log := range receipt.Logs {
		// Unpacking a log does not check which contract emitted it, so a
		// lookalike event from any other address must be rejected here.
		if log.Address != v.address {
			continue
		}

		if len(log.Topics) == 0 || log.Topics[0] != eventID {
			continue
		}

		event, err := unpackAnchoredRoot(v.abi, log)
		if err != nil {
			continue
		}

		for i := range event.Issuers {
			if i >= len(event.TreeIndices) || i >= len(event.NewRoots) {
				break
			}

			if event.Issuers[i] == issuer && event.TreeIndices[i].Cmp(treeIndexBig) == 0 {
				return event.NewRoots[i], nil
			}
		}
	}

	return root, ErrRootNotAnchored
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

// batchTreesUpdated mirrors the non-indexed fields of the BatchTreesUpdated
// event, in declaration order.
type batchTreesUpdated struct {
	Issuers     []common.Address
	TreeIndices []*big.Int
	NewRoots    [][32]byte
}

// unpackAnchoredRoot decodes a BatchTreesUpdated log's data into its parallel
// arrays. All three event fields are non-indexed, so they live entirely in the
// log's data section.
func unpackAnchoredRoot(contractABI abi.ABI, log *types.Log) (batchTreesUpdated, error) {
	var event batchTreesUpdated

	err := contractABI.UnpackIntoInterface(&event, anchoredRootEvent, log.Data)
	if err != nil {
		return batchTreesUpdated{}, err
	}

	return event, nil
}

// verifyMerkleProof reports whether leaf, folded together with its sibling path,
// reproduces root.
//
// The tree hashes each sibling pair in sorted order with keccak256 and does not
// re-hash the leaves, so the fold is independent of the leaf's position and needs
// no leaf index. This mirrors the contract's own verifyVC folding, letting a proof
// be checked against a historical root recovered from a transaction's receipt. An
// empty proof means a single-leaf tree, where the root equals the leaf.
func verifyMerkleProof(leaf [32]byte, proof [][32]byte, root [32]byte) bool {
	computed := leaf
	for _, sibling := range proof {
		computed = hashPair(computed, sibling)
	}

	return computed == root
}

// hashPair keccak256-hashes two 32-byte nodes concatenated in ascending byte
// order, matching the contract's sorted-pair hashing.
func hashPair(a, b [32]byte) [32]byte {
	var out [32]byte

	if bytes.Compare(a[:], b[:]) < 0 {
		copy(out[:], crypto.Keccak256(a[:], b[:]))
	} else {
		copy(out[:], crypto.Keccak256(b[:], a[:]))
	}

	return out
}

// decodeLeafAndProof converts the hex leaf and proof fields into the byte forms
// the contract call and local folding expect.
func decodeLeafAndProof(leafHex string, proofHex []string) ([32]byte, [][32]byte, error) {
	leaf, err := hexToBytes32(leafHex)
	if err != nil {
		return [32]byte{}, nil, fmt.Errorf("invalid leaf: %w", err)
	}

	proof, err := parseProof(proofHex)
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
