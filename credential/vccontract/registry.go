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

// singleRootEvent is the log emitted when one tree is anchored on its own, by an
// issuer writing its own root rather than the batching writer.
//
// Both events must be understood. While the contract still kept every root in
// storage, missing this one was harmless — a view call could always fall back on
// the stored root. Once anchoring proof lives only in the logs that fallback is
// gone, and a root anchored singly would silently read as never anchored.
const singleRootEvent = "TreeUpdated"

// treeUpdatedTopicCount is the topic count of a well-formed TreeUpdated log: the
// event ID, then its two indexed fields.
const treeUpdatedTopicCount = 3

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
// Deprecated: the Credential Registry no longer keeps roots in storage, so this
// only works against a deployment that still does. Use VerifyVCHashByTx, which
// reads the root from the anchoring transaction's logs and stays correct however
// the tree grows afterwards.
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

	root, err := v.anchoredRootForRequest(ctx, req, common.Hash(txHash))

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

// anchoredRootForRequest reads the anchored root for req, pinned to req's
// contract address when it carries one.
//
// The field is optional so a caller whose proof API does not yet report the
// anchoring contract still verifies, against any trusted contract. Once it is
// reported, passing it is strictly better: it stops a root anchored by a
// different deployment from satisfying the lookup.
func (v *CredentialRegistry) anchoredRootForRequest(ctx context.Context, req *VerifyByTxRequest, txHash common.Hash) ([32]byte, error) {
	issuer := common.HexToAddress(req.IssuerAddress)

	if req.ContractAddress == "" {
		return v.GetAnchoredRoot(ctx, txHash, issuer, req.TreeIndex)
	}

	return v.GetAnchoredRootFromContract(
		ctx,
		txHash,
		issuer,
		req.TreeIndex,
		common.HexToAddress(req.ContractAddress),
	)
}

// GetAnchoredRoot returns the Merkle root that txHash anchored on-chain for the
// given issuer and tree index, read from the anchoring logs of the transaction's
// receipt.
//
// Logs from any contract in this client's trusted set are read. When the caller
// knows which contract anchored the tree — the proof API reports it per
// anchoring — GetAnchoredRootFromContract is the stricter choice.
//
// Returns ErrTxNotFound when no receipt exists (unknown or unmined),
// ErrTxReverted when the transaction failed, and ErrRootNotAnchored when it
// succeeded but recorded no root for this issuer and tree index.
func (v *CredentialRegistry) GetAnchoredRoot(ctx context.Context, txHash common.Hash, issuer common.Address, treeIndex uint64) ([32]byte, error) {
	return v.anchoredRoot(ctx, txHash, issuer, treeIndex, nil)
}

// GetAnchoredRootFromContract is GetAnchoredRoot restricted to logs emitted by
// one specific contract.
//
// Use it when the anchoring's contract address is known, so a root anchored by a
// different deployment cannot satisfy the lookup. The address must already be in
// this client's trusted set; otherwise it returns ErrUntrustedContract. Pinning
// can only narrow what is believed — a per-call address is caller input, and
// trusting it on its own word would defeat the emitter check entirely.
func (v *CredentialRegistry) GetAnchoredRootFromContract(ctx context.Context, txHash common.Hash, issuer common.Address, treeIndex uint64, contractAddress common.Address) ([32]byte, error) {
	if !v.trusts(contractAddress) {
		return [32]byte{}, fmt.Errorf("%w: %s", ErrUntrustedContract, contractAddress.Hex())
	}

	return v.anchoredRoot(ctx, txHash, issuer, treeIndex, &contractAddress)
}

// anchoredRoot scans a receipt's logs for the root anchored for issuer and
// treeIndex. When emitter is non-nil only that contract's logs are read;
// otherwise every trusted contract's logs are.
func (v *CredentialRegistry) anchoredRoot(ctx context.Context, txHash common.Hash, issuer common.Address, treeIndex uint64, emitter *common.Address) ([32]byte, error) {
	var root [32]byte

	receipt, err := v.receipts.TransactionReceipt(ctx, txHash)
	if err != nil {
		if errors.Is(err, ethereum.NotFound) {
			return root, ErrTxNotFound
		}

		return root, fmt.Errorf("failed to get transaction receipt: %w", err)
	}

	if receipt.Status != types.ReceiptStatusSuccessful {
		return root, ErrTxReverted
	}

	batchEventID := v.abi.Events[anchoredRootEvent].ID
	singleEventID := v.abi.Events[singleRootEvent].ID
	treeIndexBig := new(big.Int).SetUint64(treeIndex)

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

		switch log.Topics[0] {
		case batchEventID:
			if found, ok := rootFromBatch(v.abi, log, issuer, treeIndexBig); ok {
				return found, nil
			}
		case singleEventID:
			if found, ok := rootFromSingle(v.abi, log, issuer, treeIndexBig); ok {
				return found, nil
			}
		}
	}

	return root, ErrRootNotAnchored
}

// rootFromBatch reads the root a BatchTreesUpdated log recorded for issuer and
// treeIndex. One transaction anchors many trees at once, so the event carries
// parallel arrays and only the entry matching both fields belongs to the
// caller's tree.
func rootFromBatch(contractABI abi.ABI, log *types.Log, issuer common.Address, treeIndex *big.Int) ([32]byte, bool) {
	event, err := unpackAnchoredRoot(contractABI, log)
	if err != nil {
		return [32]byte{}, false
	}

	for i := range event.Issuers {
		if i >= len(event.TreeIndices) || i >= len(event.NewRoots) {
			break
		}

		if event.Issuers[i] == issuer && event.TreeIndices[i].Cmp(treeIndex) == 0 {
			return event.NewRoots[i], true
		}
	}

	return [32]byte{}, false
}

// rootFromSingle reads the root a TreeUpdated log recorded for issuer and
// treeIndex.
//
// Unlike the batch event, its issuer and tree index are indexed, so they live in
// the log's topics rather than its data and are compared there; only the root
// itself is in the data section.
func rootFromSingle(contractABI abi.ABI, log *types.Log, issuer common.Address, treeIndex *big.Int) ([32]byte, bool) {
	// A log claiming this event ID with the wrong topic count is malformed, and
	// indexing into it would panic rather than reject it.
	if len(log.Topics) != treeUpdatedTopicCount {
		return [32]byte{}, false
	}

	if common.BytesToAddress(log.Topics[1].Bytes()) != issuer {
		return [32]byte{}, false
	}

	if new(big.Int).SetBytes(log.Topics[2].Bytes()).Cmp(treeIndex) != 0 {
		return [32]byte{}, false
	}

	var event struct {
		NewRoot [32]byte
	}

	if err := contractABI.UnpackIntoInterface(&event, singleRootEvent, log.Data); err != nil {
		return [32]byte{}, false
	}

	return event.NewRoot, true
}

// GetTreeRoot returns the on-chain Merkle root for the given issuer and tree
// index. A zero value means no such tree has been anchored.
//
// Deprecated: only a deployment that still keeps roots in storage answers this.
// Read the root of a specific anchoring with GetAnchoredRoot instead.
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
// Deprecated: only a deployment that still keeps roots in storage answers this.
// An anchoring is now evidenced by its transaction, not by contract state.
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
