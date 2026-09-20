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
	// ErrNoContractAddress is returned by the view functions when the client was
	// built without a contractAddress. They are the only operations that call the
	// contract, so they are the only ones that need one; reading logs does not.
	ErrNoContractAddress = errors.New("no contract address configured")
	// ErrTxNotFound is returned when the chain has no receipt for the tx hash,
	// either because it is unknown or because it has not been mined yet.
	ErrTxNotFound = errors.New("transaction not found")
	// ErrTxReverted is returned when the tx exists but failed, so it anchored
	// nothing.
	ErrTxReverted = errors.New("transaction reverted")
	// ErrRootNotAnchored is returned when the tx succeeded but carries no root
	// for the requested issuer and tree index.
	//
	// Deprecated: only GetAnchoredRoot returns it, and only from the legacy
	// BatchTreesUpdated event. Kept because it shipped in v1.9.x and this module
	// is still v1; nothing else in the package produces it.
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
	// contract is the eth_call target, nil when no contractAddress was given. Only
	// the view functions use it, and they check it first.
	contract *bind.BoundContract
	abi      abi.ABI
	// address is contract's address, zero when there is none.
	address common.Address
	// trusted holds every contract address whose logs this client will believe:
	// alsoTrust, plus contractAddress when one was given. A log from anywhere else
	// is ignored, whatever it claims to be.
	//
	// Empty means believe every emitter, which is why trusts() is the only reader:
	// ranging over this map directly would silently treat "trust everyone" as
	// "trust no one".
	trusted map[common.Address]struct{}
}

// NewCredentialRegistry connects to the chain and returns a client for the
// Credential Registry contract.
//
// rpcURL is required. Unlike a transaction client, a working RPC connection is
// mandatory here because every operation is an on-chain read.
//
// The two address parameters answer two different questions, and only the second
// one matters to most callers:
//
//   - contractAddress — who to call. It is the target of every eth_call, so it is
//     needed only by the view functions (VerifyVCHashOnChain, GetTreeRoot,
//     HasTree), which exist only on the deployment that keeps roots in storage.
//     Pass "" when you do not use them; those three then return
//     ErrNoContractAddress instead of making a call that could only fail.
//   - alsoTrust — whose logs to believe. These addresses are never called. A tree
//     stays verifiable at the contract that anchored it, so a deployment that
//     moves to a new address keeps verifying older anchorings by listing the
//     previous address here.
//
// Both feed the trusted set, contractAddress included, and position within it
// carries no meaning — the set is consulted as a set.
//
// # Naming no address at all disables the emitter check
//
// Pass no address in either parameter and every log is believed, whichever
// contract emitted it. Nothing is then verified in any meaningful sense: the
// event signatures are public, so anyone can deploy a contract, emit
// TreeRootAnchored naming an issuer they do not control and a root over leaves
// they invented, and hand over a proof bundle pointing at that transaction. It
// verifies as true.
//
// The check is the whole security of this package. Name at least one address
// unless a true answer does not need to mean anything — a local experiment, or
// exploring a chain whose deployments you are still discovering. Never in
// anything that accepts a credential from outside.
//
// # One client cannot do both jobs
//
// Because contractAddress does double duty as call target, a client pointed at
// the storage-keeping deployment for the view functions is not the one that reads
// the current contract's logs. Build two.
func NewCredentialRegistry(rpcURL, contractAddress string, alsoTrust ...string) (*CredentialRegistry, error) {
	if rpcURL == "" {
		return nil, errors.New("RPC URL is required")
	}

	var address common.Address

	trusted := make(map[common.Address]struct{}, 1+len(alsoTrust))

	// An empty contractAddress is a caller saying they only read logs. The view
	// functions then have nothing to call and say so; everything else is unaffected,
	// because reading a log needs the ABI and the trusted set, never a call target.
	if contractAddress != "" {
		parsed, err := parseContractAddress(contractAddress)
		if err != nil {
			return nil, fmt.Errorf("invalid contract address: %w", err)
		}

		address = parsed
		trusted[address] = struct{}{}
	}

	for i, extra := range alsoTrust {
		parsed, err := parseContractAddress(extra)
		if err != nil {
			return nil, fmt.Errorf("invalid contract address in alsoTrust at index %d: %w", i, err)
		}

		trusted[parsed] = struct{}{}
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

	registry := &CredentialRegistry{
		client:   client,
		receipts: client,
		address:  address,
		abi:      contractABI,
		trusted:  trusted,
	}

	// Left nil when there is no address, which is what the view functions check.
	// Binding to the zero address instead would let them make a call that can only
	// fail, and report it as an RPC error rather than as the missing configuration
	// it is.
	if address != (common.Address{}) {
		registry.contract = bind.NewBoundContract(
			address,
			contractABI,
			client,
			client,
			client,
		)
	}

	return registry, nil
}

// parseContractAddress reads one configured deployment address.
//
// The zero address is rejected on top of the format check, because
// common.IsHexAddress accepts it: an unset environment variable reaching
// common.HexToAddress arrives here as a well-formed address that no contract can
// ever be at. As contractAddress it produces a client whose every call goes
// nowhere; in alsoTrust it is inert, but a value that can only be a mistake is
// worth refusing in both places rather than explaining as a special case.
func parseContractAddress(value string) (common.Address, error) {
	if !common.IsHexAddress(value) {
		return common.Address{}, fmt.Errorf("%q is not a 20-byte hex address", value)
	}

	address := common.HexToAddress(value)
	if address == (common.Address{}) {
		return common.Address{}, errors.New("the zero address names no deployment")
	}

	return address, nil
}

// trusts reports whether logs emitted by address may be believed.
//
// An empty trusted set believes every emitter. That is a deliberate choice for
// callers who do not want to enumerate deployments, and it removes the only check
// that distinguishes a real anchoring from a forged one — see the warning on
// NewCredentialRegistry before relying on it.
func (v *CredentialRegistry) trusts(address common.Address) bool {
	if len(v.trusted) == 0 {
		return true
	}

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
// Returns ErrNoContractAddress when the client was built without a
// contractAddress, since there is then nothing to call.
//
// Deprecated: the current contract does not have verifyVC at all, so against it
// this can only fail — it works solely against an older deployment that still
// keeps roots in storage. Use VerifyVCHashByTx, which reads the anchoring out of
// the transaction's logs and works against both.
func (v *CredentialRegistry) VerifyVCHashOnChain(ctx context.Context, req *VerifyRequest) (bool, error) {
	if v.contract == nil {
		return false, fmt.Errorf("%w: verifyVC is a call on the contract that keeps roots in storage, so its address must be passed to NewCredentialRegistry", ErrNoContractAddress)
	}

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
// req.TxHash anchored for this issuer.
//
// The two return values answer two different questions. A false with a nil error
// means the chain was asked and does not attest the leaf; an error means the
// chain could not be asked, and nothing was established either way — malformed
// input, an RPC failure, or the transaction not found / not yet mined
// (ErrTxNotFound).
//
// A reverted transaction falls on the first side on purpose. It did run, and it
// wrote nothing, so "this transaction does not attest the leaf" is already the
// true and complete answer; returning an error would claim the check never
// happened. It is also close to unreachable — a tx hash from the proof API is
// always a successful anchoring, because the anchoring row is only written after
// a successful receipt.
//
// A caller that does need to tell a reverted transaction apart — an auditing
// tool, an operator script — calls IsRootAnchored, the layer below, which returns
// ErrTxReverted unchanged. This function gives a verdict; that one reports what
// the chain said.
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
	anchored, err := v.rootAnchoredForRequest(ctx, req, common.Hash(txHash), FoldProof(leaf, proof))

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

// GetAnchoredRoot returns the Merkle root that txHash anchored on-chain for the
// given issuer and tree index, read from the legacy BatchTreesUpdated logs of the
// transaction's receipt.
//
// Deprecated: reads the legacy BatchTreesUpdated event only; against the current
// contract it returns ErrRootNotAnchored. Use IsRootAnchored.
//
// The current contract records an anchoring as (issuer, root) and emits no tree
// index at all, so there is nothing here to match a tree index against — which is
// why a root anchored by it can never be found through this function. Roots
// anchored by the previous contract still are, exactly as before.
//
// Kept rather than removed because it shipped in v1.9.x and this module is still
// v1: dropping an exported symbol without moving to /v2 breaks `go get -u` for
// anyone who called it, at compile time, through no fault of their own.
//
// Returns ErrTxNotFound when no receipt exists (unknown or unmined), ErrTxReverted
// when the transaction failed, and ErrRootNotAnchored when it succeeded but
// recorded no root for this issuer and tree index.
func (v *CredentialRegistry) GetAnchoredRoot(ctx context.Context, txHash common.Hash, issuer common.Address, treeIndex uint64) ([32]byte, error) {
	var root [32]byte

	if v.receipts == nil {
		return root, errors.New("registry is not initialized")
	}

	receipt, err := v.receipts.TransactionReceipt(ctx, txHash)
	if err != nil {
		if errors.Is(err, ethereum.NotFound) {
			return root, ErrTxNotFound
		}

		return root, fmt.Errorf("failed to get transaction receipt: %w", err)
	}

	if receipt == nil {
		return root, fmt.Errorf("receipt source returned no receipt and no error for tx %s", txHash.Hex())
	}

	if receipt.Status != types.ReceiptStatusSuccessful {
		return root, ErrTxReverted
	}

	eventID := v.abi.Events[legacyBatchEvent].ID
	treeIndexBig := new(big.Int).SetUint64(treeIndex)

	for _, log := range receipt.Logs {
		// receipt.Logs is []*types.Log, so a JSON null in the response unmarshals to
		// a nil element. A node that sends "logs":[null] — or anything in front of
		// one that rewrites the response — reaches this loop, and reading Address
		// off it panics before any check can run.
		if log == nil {
			continue
		}

		// Unpacking a log does not check which contract emitted it, so a lookalike
		// event from any other address must be rejected here. v1.9.x believed only
		// the configured address; the trusted set is used now, which for a caller
		// that passes no alsoTrust is the same set.
		if !v.trusts(log.Address) {
			continue
		}

		if len(log.Topics) == 0 || log.Topics[0] != eventID {
			continue
		}

		var event struct {
			Issuers     []common.Address
			TreeIndices []*big.Int
			NewRoots    [][32]byte
		}

		if v.abi.UnpackIntoInterface(&event, legacyBatchEvent, log.Data) != nil {
			continue
		}

		if len(event.Issuers) != len(event.TreeIndices) || len(event.Issuers) != len(event.NewRoots) {
			continue
		}

		for i := range event.Issuers {
			if event.Issuers[i] == issuer && event.TreeIndices[i].Cmp(treeIndexBig) == 0 {
				return event.NewRoots[i], nil
			}
		}
	}

	return root, ErrRootNotAnchored
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

	// A zero root is a verdict, not a failure. FoldProof returns the leaf itself
	// when there are no siblings, so a caller asking about the zero hash with an
	// empty proof lands here — a well-formed question whose answer is simply no.
	// No transaction can have anchored it: the contract rejects an empty root with
	// EmptyRoot, so one never reaches a log. Reporting an error instead left the
	// caller unable to tell "this proof is wrong" from "the service is broken",
	// which surfaced as a 500 in the service built on this.
	if root == ([32]byte{}) {
		return false, nil
	}

	receipt, err := v.receipts.TransactionReceipt(ctx, txHash)
	if err != nil {
		if errors.Is(err, ethereum.NotFound) {
			return false, ErrTxNotFound
		}

		return false, fmt.Errorf("failed to get transaction receipt: %w", err)
	}

	// TransactionReceipt is reached through an interface, so nothing here enforces
	// that a nil error comes with a receipt. go-ethereum's own client maps a nil
	// receipt to ethereum.NotFound, but another implementation — a test double, a
	// wrapper around a different node client — may not, and dereferencing it here
	// would panic instead of reporting anything.
	if receipt == nil {
		return false, fmt.Errorf("receipt source returned no receipt and no error for tx %s", txHash.Hex())
	}

	if receipt.Status != types.ReceiptStatusSuccessful {
		return false, ErrTxReverted
	}

	for _, log := range receipt.Logs {
		// receipt.Logs is []*types.Log, so a JSON null in the response unmarshals to
		// a nil element. A node that sends "logs":[null] — or anything in front of
		// one that rewrites the response — reaches this loop, and reading Address
		// off it panics before any check can run.
		if log == nil {
			continue
		}

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
			topicAddress(log.Topics[1]) == issuer &&
			log.Topics[2] == common.Hash(root)

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
			topicAddress(log.Topics[1]) != issuer {
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
			topicAddress(log.Topics[1]) != issuer {
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

// topicAddress reads an indexed address out of a log topic.
//
// A topic is always 32 bytes, so an address is stored left-padded into it and is
// the last 20. Slicing the topic in place avoids copying it out first, and naming
// the rule here keeps it from being re-derived at each of the three call sites.
func topicAddress(topic common.Hash) common.Address {
	return common.BytesToAddress(topic[common.HashLength-common.AddressLength:])
}

// pairPresent reports whether the parallel arrays hold this (issuer, root) entry.
//
// Arrays of different lengths are rejected outright rather than scanned up to the
// shorter one. The contract requires them to match — it reverts with
// ArrayLengthMismatch otherwise — so a log where they do not is not an anchoring
// this client can read: either the ABI it was decoded against does not describe
// the event that was emitted, or the payload is damaged.
//
// Answering from the prefix of such a log would mean trusting part of a record
// whose shape is already known to be wrong. Verification fails closed instead.
func pairPresent(issuers []common.Address, roots [][32]byte, issuer common.Address, root [32]byte) bool {
	if len(issuers) != len(roots) {
		return false
	}

	for i := range issuers {
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
// Returns ErrNoContractAddress when the client was built without a
// contractAddress, since there is then nothing to call.
//
// Deprecated: the current contract does not have getTreeRoot at all, so against
// it this can only fail. There is no replacement that returns a root: an
// anchoring is identified by (issuer, root) now, so ask IsRootAnchored whether a
// root you already hold was anchored.
func (v *CredentialRegistry) GetTreeRoot(ctx context.Context, issuerAddress string, treeIndex uint64) ([32]byte, error) {
	if v.contract == nil {
		return [32]byte{}, fmt.Errorf("%w: getTreeRoot is a call on the contract that keeps roots in storage, so its address must be passed to NewCredentialRegistry", ErrNoContractAddress)
	}

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
// Returns ErrNoContractAddress when the client was built without a
// contractAddress, since there is then nothing to call.
//
// Deprecated: the current contract does not have treeExists at all, so against
// it this can only fail. An anchoring is evidenced by its transaction now, not by
// contract state — see IsRootAnchored.
func (v *CredentialRegistry) HasTree(ctx context.Context, issuerAddress string, treeIndex uint64) (bool, error) {
	if v.contract == nil {
		return false, fmt.Errorf("%w: treeExists is a call on the contract that keeps roots in storage, so its address must be passed to NewCredentialRegistry", ErrNoContractAddress)
	}

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

// FoldProof folds a leaf together with its sibling path and returns the root it
// produces.
//
// Exported because IsRootAnchored is keyed on the root, not on the leaf: anything
// that wants to ask the chain directly — an auditing tool, an operator script,
// anyone who needs to tell a reverted transaction from a proof that simply does
// not match — has to fold first. The alternative is every caller reimplementing
// the rule, and a fold that differs in any detail produces a different root with
// nothing to signal it.
//
// The rule: sibling pairs are hashed in ascending byte order with keccak256, and
// leaves are not hashed. An empty path means a single-leaf tree, whose root is
// the leaf itself.
//
// Note what this does not establish. A leaf and an inner node are both 32 bytes
// and the fold cannot tell them apart, so an inner node folds to the root too —
// see VerifyByTxRequest.Leaf. Fold a hash you computed from the credential.
func FoldProof(leaf [32]byte, proof [][32]byte) [32]byte {
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
