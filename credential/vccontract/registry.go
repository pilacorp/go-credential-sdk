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

// The five shapes an anchoring has ever taken.
//
// Three are the current contract's. Two are the previous one's, kept because the
// roots anchored through them are still valid: nothing re-anchors those trees and
// no migration could, so a reader that stops understanding the old events reports
// every pre-upgrade credential as never anchored.
const (
	// batchAnchoredEvent carries parallel arrays, one entry per anchoring, for
	// trees belonging to different issuers.
	batchAnchoredEvent = "BatchRootsAnchored"
	// singleAnchoredEvent carries one anchoring with both fields indexed.
	singleAnchoredEvent = "TreeRootAnchored"
	// issuerAnchoredEvent carries several roots belonging to one indexed issuer.
	issuerAnchoredEvent = "IssuerRootsAnchored"

	// legacyBatchEvent is batchAnchoredEvent's predecessor, with a tree index per
	// entry.
	legacyBatchEvent = "BatchTreesUpdated"
	// legacySingleEvent is singleAnchoredEvent's predecessor. Its issuer and tree
	// index were indexed; the root rode in the data section.
	legacySingleEvent = "TreeUpdated"
)

// Topic counts of a well-formed log, counting the event ID plus the indexed
// fields. A log carrying fewer has to be skipped rather than indexed into.
const (
	singleAnchoredTopicCount = 3 // id, issuer, root
	issuerAnchoredTopicCount = 2 // id, issuer
	legacySingleTopicCount   = 3 // id, issuer, tree index
)

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
	// ErrUntrustedContract is returned when a caller pins verification to a
	// contract address this client was not configured to trust. Believing an
	// address supplied per-call would defeat the point of checking the emitter at
	// all, so the pin narrows the trusted set and can never widen it.
	ErrUntrustedContract = errors.New("contract address is not in this client's trusted set")
)

// receiptSource reads transaction receipts from the chain.
//
// *ethclient.Client satisfies it. It exists so the log-filtering rules — which
// carry the security weight of this package — can be tested against synthetic
// receipts without a chain.
type receiptSource interface {
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
}

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
	receipts receiptSource
	contract *bind.BoundContract
	abi      abi.ABI
	address  common.Address
	// trusted holds every contract address whose logs this client will believe:
	// address plus alsoTrust. A log from anywhere else is ignored, whatever it
	// claims to be.
	trusted map[common.Address]struct{}
}

// NewCredentialRegistry connects to the chain and returns a client for the
// Credential Registry contract at contractAddress.
//
// rpcURL and contractAddress are required. Unlike a transaction client, a working
// RPC connection is mandatory here because every operation is an on-chain read.
//
// alsoTrust names further contract addresses whose anchoring logs are to be
// believed. A tree stays verifiable at the contract that anchored it, so a
// deployment that moves to a new address keeps verifying older anchorings by
// listing the previous address here. Only contractAddress is ever called
// directly: the view functions (VerifyVCHashOnChain, GetTreeRoot, HasTree) exist
// only on the storage-keeping contract, while the alsoTrust addresses are read
// through their logs alone.
func NewCredentialRegistry(rpcURL, contractAddress string, alsoTrust ...string) (*CredentialRegistry, error) {
	if rpcURL == "" {
		return nil, errors.New("RPC URL is required")
	}

	if !common.IsHexAddress(contractAddress) {
		return nil, fmt.Errorf("invalid contract address: %q", contractAddress)
	}

	address := common.HexToAddress(contractAddress)

	trusted := map[common.Address]struct{}{address: {}}

	for i, extra := range alsoTrust {
		if !common.IsHexAddress(extra) {
			return nil, fmt.Errorf("invalid contract address in alsoTrust at index %d: %q", i, extra)
		}

		trusted[common.HexToAddress(extra)] = struct{}{}
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
		client:   client,
		receipts: client,
		address:  address,
		abi:      contractABI,
		trusted:  trusted,
		contract: bind.NewBoundContract(
			address,
			contractABI,
			client,
			client,
			client,
		),
	}, nil
}

// trusts reports whether logs emitted by address may be believed.
func (v *CredentialRegistry) trusts(address common.Address) bool {
	_, ok := v.trusted[address]

	return ok
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
//
// Deprecated: the current contract does not have verifyVC at all, so against it
// this can only fail — it works solely against an older deployment that still
// keeps roots in storage. Use VerifyVCHashByTx, which reads the anchoring out of
// the transaction's logs and works against both.
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
// Returns true when the leaf, folded with its proof, produces a root that
// req.TxHash anchored for this issuer. Returns false with a nil error when it
// does not, or when the transaction reverted. A non-nil error means the check
// could not be completed — malformed input, RPC failure, or the transaction not
// found / not yet mined (ErrTxNotFound).
//
// req.TreeIndex is accepted but not used: the contract no longer records one.
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

	// Fold first, then ask. An anchoring is recorded as (issuer, root) and nothing
	// else, so the root the caller's proof produces is the only handle there is for
	// finding it — there is no tree index left to look one up by.
	anchored, err := v.rootAnchoredForRequest(ctx, req, common.Hash(txHash), foldProof(leaf, proof))

	switch {
	// A reverted transaction anchored nothing, so it cannot attest the leaf: a
	// definitive "not verified", not a failure to check.
	case errors.Is(err, ErrTxReverted):
		return false, nil
	case err != nil:
		return false, err
	}

	return anchored, nil
}

// rootAnchoredForRequest asks whether req's transaction anchored root, pinned to
// req's contract address when it carries one.
//
// The field is optional so a caller whose proof API does not yet report the
// anchoring contract still verifies, against any trusted contract. Once it is
// reported, passing it is strictly better: it stops a root anchored by a
// different deployment from satisfying the lookup.
//
// req.TreeIndex is deliberately unused. The contract has no tree index any more,
// and the field is kept on the request only so callers still sending it keep
// working.
func (v *CredentialRegistry) rootAnchoredForRequest(ctx context.Context, req *VerifyByTxRequest, txHash common.Hash, root [32]byte) (bool, error) {
	issuer := common.HexToAddress(req.IssuerAddress)

	if req.ContractAddress == "" {
		return v.IsRootAnchored(ctx, txHash, issuer, root)
	}

	return v.IsRootAnchoredAtContract(
		ctx,
		txHash,
		issuer,
		root,
		common.HexToAddress(req.ContractAddress),
	)
}

// IsRootAnchored reports whether txHash records issuer anchoring root.
//
// The question used to run the other way — "what root did this tree get?" — and
// was answered by looking the tree index up in the log. The contract carries no
// tree index any more, so that question has no single answer: one transaction
// anchors many of an issuer's trees and nothing in the log tells them apart.
//
// Asking about a root the caller already holds needs no such tiebreaker. Fold a
// leaf and its proof into a root, then ask whether that exact root was anchored
// by that issuer. Every root in the log belongs to a tree the issuer really
// anchored, so a match proves what verification is there to prove.
//
// Logs from any contract in this client's trusted set are read. When the caller
// knows which contract anchored the tree, IsRootAnchoredAtContract is stricter.
//
// Returns ErrTxNotFound when no receipt exists (unknown or unmined) and
// ErrTxReverted when the transaction failed. A transaction that simply does not
// carry the root is (false, nil): a verdict, not a failure to check.
func (v *CredentialRegistry) IsRootAnchored(ctx context.Context, txHash common.Hash, issuer common.Address, root [32]byte) (bool, error) {
	return v.rootAnchored(ctx, txHash, issuer, root, nil)
}

// IsRootAnchoredAtContract is IsRootAnchored restricted to logs emitted by one
// deployment, which must already be trusted.
//
// Pinning can only narrow what is believed, never widen it. The address is caller
// input, so honouring an unknown one would let a caller nominate any contract at
// all and undo the emitter check entirely.
func (v *CredentialRegistry) IsRootAnchoredAtContract(ctx context.Context, txHash common.Hash, issuer common.Address, root [32]byte, contractAddress common.Address) (bool, error) {
	if !v.trusts(contractAddress) {
		return false, fmt.Errorf("%w: %s", ErrUntrustedContract, contractAddress.Hex())
	}

	return v.rootAnchored(ctx, txHash, issuer, root, &contractAddress)
}

func (v *CredentialRegistry) rootAnchored(ctx context.Context, txHash common.Hash, issuer common.Address, root [32]byte, emitter *common.Address) (bool, error) {
	if v.receipts == nil {
		return false, errors.New("registry is not initialized")
	}

	if root == ([32]byte{}) {
		return false, errors.New("cannot look up an empty root")
	}

	receipt, err := v.receipts.TransactionReceipt(ctx, txHash)
	if err != nil {
		if errors.Is(err, ethereum.NotFound) {
			return false, ErrTxNotFound
		}

		return false, fmt.Errorf("failed to get transaction receipt: %w", err)
	}

	if receipt.Status != types.ReceiptStatusSuccessful {
		return false, ErrTxReverted
	}

	for _, log := range receipt.Logs {
		// Unpacking a log does not check which contract emitted it, and anyone
		// can deploy a contract emitting these exact signatures, so a log from an
		// address that is not believed must be dropped before it is decoded.
		if emitter != nil {
			if log.Address != *emitter {
				continue
			}
		} else if !v.trusts(log.Address) {
			continue
		}

		if len(log.Topics) == 0 {
			continue
		}

		if logAnchors(v.abi, log, issuer, root) {
			return true, nil
		}
	}

	return false, nil
}

// logAnchors reports whether one log records issuer anchoring root.
//
// The two legacy events are matched on (issuer, root) like the rest; their tree
// index is skipped rather than compared. It was only ever a lookup key and never
// part of what an anchoring asserts, so ignoring it loses nothing and lets one
// question cover both contract versions.
func logAnchors(contractABI abi.ABI, log *types.Log, issuer common.Address, root [32]byte) bool {
	switch log.Topics[0] {
	case contractABI.Events[singleAnchoredEvent].ID:
		// Both fields indexed, so the whole anchoring is in the topics.
		return len(log.Topics) == singleAnchoredTopicCount &&
			common.BytesToAddress(log.Topics[1].Bytes()) == issuer &&
			log.Topics[2] == common.BytesToHash(root[:])

	case contractABI.Events[batchAnchoredEvent].ID:
		var event struct {
			Issuers []common.Address
			Roots   [][32]byte
		}

		if contractABI.UnpackIntoInterface(&event, batchAnchoredEvent, log.Data) != nil {
			return false
		}

		return pairPresent(event.Issuers, event.Roots, issuer, root)

	case contractABI.Events[issuerAnchoredEvent].ID:
		if len(log.Topics) != issuerAnchoredTopicCount ||
			common.BytesToAddress(log.Topics[1].Bytes()) != issuer {
			return false
		}

		var event struct {
			Roots [][32]byte
		}

		if contractABI.UnpackIntoInterface(&event, issuerAnchoredEvent, log.Data) != nil {
			return false
		}

		return containsRoot(event.Roots, root)

	case contractABI.Events[legacySingleEvent].ID:
		if len(log.Topics) != legacySingleTopicCount ||
			common.BytesToAddress(log.Topics[1].Bytes()) != issuer {
			return false
		}

		var event struct {
			NewRoot [32]byte
		}

		if contractABI.UnpackIntoInterface(&event, legacySingleEvent, log.Data) != nil {
			return false
		}

		return event.NewRoot == root

	case contractABI.Events[legacyBatchEvent].ID:
		var event struct {
			Issuers     []common.Address
			TreeIndices []*big.Int
			NewRoots    [][32]byte
		}

		if contractABI.UnpackIntoInterface(&event, legacyBatchEvent, log.Data) != nil {
			return false
		}

		return pairPresent(event.Issuers, event.NewRoots, issuer, root)
	}

	return false
}

// pairPresent reports whether the parallel arrays hold this (issuer, root) entry.
//
// Arrays that disagree in length come from a log this client cannot read, so the
// shorter one bounds the scan rather than panicking on it.
func pairPresent(issuers []common.Address, roots [][32]byte, issuer common.Address, root [32]byte) bool {
	for i := range issuers {
		if i >= len(roots) {
			break
		}

		if issuers[i] == issuer && roots[i] == root {
			return true
		}
	}

	return false
}

func containsRoot(roots [][32]byte, root [32]byte) bool {
	for _, anchored := range roots {
		if anchored == root {
			return true
		}
	}

	return false
}

// GetTreeRoot returns the on-chain Merkle root for the given issuer and tree
// index. A zero value means no such tree has been anchored.
//
// Deprecated: the current contract does not have getTreeRoot at all, so against
// it this can only fail. There is no replacement that returns a root: an
// anchoring is identified by (issuer, root) now, so ask IsRootAnchored whether a
// root you already hold was anchored.
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
//
// Deprecated: the current contract does not have treeExists at all, so against
// it this can only fail. An anchoring is evidenced by its transaction now, not by
// contract state — see IsRootAnchored.
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

// verifyMerkleProof reports whether leaf, folded together with its sibling path,
// reproduces root.
//
// The tree hashes each sibling pair in sorted order with keccak256 and does not
// re-hash the leaves, so the fold is independent of the leaf's position and needs
// no leaf index. This mirrors the contract's own verifyVC folding, letting a proof
// be checked against a historical root recovered from a transaction's receipt. An
// empty proof means a single-leaf tree, where the root equals the leaf.
func verifyMerkleProof(leaf [32]byte, proof [][32]byte, root [32]byte) bool {
	return foldProof(leaf, proof) == root
}

// foldProof folds leaf together with its sibling path and returns the root it
// produces.
//
// verifyMerkleProof answers "does this fold to the root I already have?", which
// is the wrong question once the root is what has to be looked up: the anchoring
// log is searched *by* root, so the root has to exist before the lookup. Folding
// first and asking about the result inverts that order.
func foldProof(leaf [32]byte, proof [][32]byte) [32]byte {
	computed := leaf
	for _, sibling := range proof {
		computed = hashPair(computed, sibling)
	}

	return computed
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
