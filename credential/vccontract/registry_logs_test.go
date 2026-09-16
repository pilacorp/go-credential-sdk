package vccontract

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// These tests exercise IsRootAnchored's log rules without a chain.
//
// Five event shapes are covered. Three are the current contract's; two are the
// previous one's, kept because the roots anchored through them are still valid
// and must keep verifying forever — nothing re-anchors those trees, and no
// migration could.

// legacyTreeIndex is any value at all: the legacy events carried a tree index,
// and the point of these tests is that nothing reads it any more.
const legacyTreeIndex = 7

var (
	registryAddress = common.HexToAddress("0x1111111111111111111111111111111111111111")
	legacyAddress   = common.HexToAddress("0x2222222222222222222222222222222222222222")
	// attackerAddress stands for any contract someone else deployed emitting the
	// same event signatures. Nothing about its logs is malformed — that is the
	// point of the tests that use it.
	attackerAddress = common.HexToAddress("0xdead00000000000000000000000000000000beef")

	issuerAddress = common.HexToAddress("0xabc0000000000000000000000000000000000001")
	otherIssuer   = common.HexToAddress("0xabc0000000000000000000000000000000000002")
)

// stubReceipts serves one canned receipt, standing in for the chain so the
// log-filtering rules can be exercised directly.
type stubReceipts struct {
	receipt *types.Receipt
	err     error
}

func (s stubReceipts) TransactionReceipt(context.Context, common.Hash) (*types.Receipt, error) {
	return s.receipt, s.err
}

// newTestRegistry builds a registry with no RPC connection: reading a log needs
// only the receipt source, the ABI and the trusted set.
func newTestRegistry(t *testing.T, receipts receiptSource, trusted ...common.Address) *CredentialRegistry {
	t.Helper()

	contractABI, err := loadABI()
	if err != nil {
		t.Fatalf("failed to load ABI: %v", err)
	}

	set := map[common.Address]struct{}{registryAddress: {}}
	for _, address := range trusted {
		set[address] = struct{}{}
	}

	return &CredentialRegistry{
		receipts: receipts,
		abi:      contractABI,
		address:  registryAddress,
		trusted:  set,
	}
}

func packNonIndexed(t *testing.T, emitter common.Address, eventName string, args ...any) *types.Log {
	t.Helper()

	contractABI, err := loadABI()
	if err != nil {
		t.Fatalf("failed to load ABI: %v", err)
	}

	event := contractABI.Events[eventName]

	data, err := event.Inputs.NonIndexed().Pack(args...)
	if err != nil {
		t.Fatalf("failed to pack %s: %v", eventName, err)
	}

	return &types.Log{Address: emitter, Topics: []common.Hash{event.ID}, Data: data}
}

func eventID(t *testing.T, name string) common.Hash {
	t.Helper()

	contractABI, err := loadABI()
	if err != nil {
		t.Fatalf("failed to load ABI: %v", err)
	}

	return contractABI.Events[name].ID
}

// batchLog is the current cross-issuer batch: parallel arrays, nothing indexed.
func batchLog(t *testing.T, emitter common.Address, issuers []common.Address, roots [][32]byte) *types.Log {
	t.Helper()

	return packNonIndexed(t, emitter, batchAnchoredEvent, issuers, roots)
}

// singleLog is the current single anchoring. Both fields are indexed, so both sit
// in topics and the data section is empty.
func singleLog(t *testing.T, emitter, issuer common.Address, root [32]byte) *types.Log {
	t.Helper()

	return &types.Log{
		Address: emitter,
		Topics: []common.Hash{
			eventID(t, singleAnchoredEvent),
			common.BytesToHash(issuer.Bytes()),
			common.BytesToHash(root[:]),
		},
	}
}

// issuerBatchLog is the current per-issuer batch: issuer indexed, roots in data.
func issuerBatchLog(t *testing.T, emitter, issuer common.Address, roots [][32]byte) *types.Log {
	t.Helper()

	log := packNonIndexed(t, emitter, issuerAnchoredEvent, roots)
	log.Topics = append(log.Topics, common.BytesToHash(issuer.Bytes()))

	return log
}

// legacyBatchLog is the previous contract's batch event, tree indices and all.
func legacyBatchLog(t *testing.T, emitter common.Address, issuers []common.Address, roots [][32]byte) *types.Log {
	t.Helper()

	indices := make([]*big.Int, len(roots))
	for i := range indices {
		indices[i] = big.NewInt(int64(legacyTreeIndex + i))
	}

	return packNonIndexed(t, emitter, legacyBatchEvent, issuers, indices, roots)
}

// legacySingleLog is the previous contract's single-tree event.
func legacySingleLog(t *testing.T, emitter, issuer common.Address, root [32]byte) *types.Log {
	t.Helper()

	log := packNonIndexed(t, emitter, legacySingleEvent, root)
	log.Topics = append(log.Topics,
		common.BytesToHash(issuer.Bytes()),
		common.BigToHash(big.NewInt(legacyTreeIndex)),
	)

	return log
}

func successReceipt(logs ...*types.Log) *types.Receipt {
	return &types.Receipt{Status: types.ReceiptStatusSuccessful, Logs: logs}
}

func anchoredFor(t *testing.T, registry *CredentialRegistry, root [32]byte) (bool, error) {
	t.Helper()

	return registry.IsRootAnchored(context.Background(), common.Hash{}, issuerAddress, root)
}

// everyShape builds one log per event shape, all recording issuer anchoring root.
func everyShape(t *testing.T, emitter, issuer common.Address, root [32]byte) []struct {
	name string
	log  *types.Log
} {
	t.Helper()

	return []struct {
		name string
		log  *types.Log
	}{
		{"current single", singleLog(t, emitter, issuer, root)},
		{"current cross-issuer batch", batchLog(t, emitter,
			[]common.Address{otherIssuer, issuer}, [][32]byte{mkLeaf(0x01), root})},
		{"current issuer batch", issuerBatchLog(t, emitter, issuer,
			[][32]byte{mkLeaf(0x02), root})},
		{"legacy single", legacySingleLog(t, emitter, issuer, root)},
		{"legacy batch", legacyBatchLog(t, emitter,
			[]common.Address{otherIssuer, issuer}, [][32]byte{mkLeaf(0x03), root})},
	}
}

// TestIsRootAnchoredReadsEveryEventShape is the test the upgrade rests on.
//
// A root anchored through the previous contract must keep verifying afterwards.
// The legacy events carry a tree index that no longer means anything; it is
// skipped rather than matched, because it was only ever a lookup key and never
// part of what an anchoring asserts.
func TestIsRootAnchoredReadsEveryEventShape(t *testing.T) {
	want := mkLeaf(0xbb)

	for _, tc := range everyShape(t, registryAddress, issuerAddress, want) {
		t.Run(tc.name, func(t *testing.T) {
			registry := newTestRegistry(t, stubReceipts{receipt: successReceipt(tc.log)})

			ok, err := anchoredFor(t, registry, want)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !ok {
				t.Fatal("a root this log anchors was reported as not anchored")
			}
		})
	}
}

// The other direction: a root the transaction does not carry must not match,
// whichever shape the logs take. Without this the tests above would pass on a
// function that always says yes.
func TestIsRootAnchoredRejectsARootNotInTheLogs(t *testing.T) {
	present := mkLeaf(0xbb)
	absent := mkLeaf(0xcc)

	for _, tc := range everyShape(t, registryAddress, issuerAddress, present) {
		t.Run(tc.name, func(t *testing.T) {
			registry := newTestRegistry(t, stubReceipts{receipt: successReceipt(tc.log)})

			ok, err := anchoredFor(t, registry, absent)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if ok {
				t.Fatal("a root that was never anchored verified")
			}
		})
	}
}

// The root has to belong to the issuer being asked about. Another issuer
// anchoring the same root says nothing about this one.
func TestIsRootAnchoredRejectsAnotherIssuersRoot(t *testing.T) {
	want := mkLeaf(0xbb)

	for _, tc := range everyShape(t, registryAddress, otherIssuer, want) {
		t.Run(tc.name, func(t *testing.T) {
			registry := newTestRegistry(t, stubReceipts{receipt: successReceipt(tc.log)})

			ok, err := anchoredFor(t, registry, want)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if ok {
				t.Fatal("a root anchored by a different issuer verified")
			}
		})
	}
}

// TestIsRootAnchoredRejectsForeignEmitter is the negative test the whole approach
// hinges on. Anyone can deploy a contract emitting these exact signatures, so a
// perfectly well-formed anchoring log from an address outside the trusted set
// must not be believed — otherwise any transaction at all could pose as a valid
// anchoring.
func TestIsRootAnchoredRejectsForeignEmitter(t *testing.T) {
	want := mkLeaf(0xbb)

	for _, tc := range everyShape(t, attackerAddress, issuerAddress, want) {
		t.Run(tc.name, func(t *testing.T) {
			registry := newTestRegistry(t, stubReceipts{receipt: successReceipt(tc.log)})

			ok, err := anchoredFor(t, registry, want)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if ok {
				t.Fatal("a log from an untrusted contract was believed")
			}
		})
	}
}

// A migration leaves both deployments live in the same trusted set, and the old
// one still holds the anchorings nothing will redo.
func TestIsRootAnchoredTrustsEveryConfiguredContract(t *testing.T) {
	want := mkLeaf(0xbb)

	registry := newTestRegistry(t,
		stubReceipts{receipt: successReceipt(
			legacyBatchLog(t, legacyAddress, []common.Address{issuerAddress}, [][32]byte{want}),
		)},
		legacyAddress,
	)

	ok, err := anchoredFor(t, registry, want)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !ok {
		t.Fatal("a root anchored by the previous deployment no longer verifies")
	}
}

// One transaction can mix shapes — an upgrade window, or a wrapper calling both
// deployments. Every log still has to be read, not just the first that decodes.
func TestIsRootAnchoredReadsMixedLogsInOneReceipt(t *testing.T) {
	want := mkLeaf(0xbb)

	registry := newTestRegistry(t,
		stubReceipts{receipt: successReceipt(
			legacyBatchLog(t, legacyAddress, []common.Address{otherIssuer}, [][32]byte{mkLeaf(0x01)}),
			batchLog(t, registryAddress, []common.Address{issuerAddress}, [][32]byte{want}),
		)},
		legacyAddress,
	)

	ok, err := anchoredFor(t, registry, want)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !ok {
		t.Fatal("a root in the second log was missed")
	}
}

// Pinning narrows the trusted set to one deployment; it can never widen it.
func TestIsRootAnchoredAtContractPinsEmitter(t *testing.T) {
	want := mkLeaf(0xbb)

	registry := newTestRegistry(t,
		stubReceipts{receipt: successReceipt(
			legacyBatchLog(t, legacyAddress, []common.Address{issuerAddress}, [][32]byte{want}),
		)},
		legacyAddress,
	)

	ok, err := registry.IsRootAnchoredAtContract(
		context.Background(), common.Hash{}, issuerAddress, want, legacyAddress)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !ok {
		t.Fatal("pinning the contract that emitted the log rejected it")
	}

	// Same receipt, pinned to the other trusted deployment: its log is not there.
	ok, err = registry.IsRootAnchoredAtContract(
		context.Background(), common.Hash{}, issuerAddress, want, registryAddress)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ok {
		t.Fatal("a log from a different deployment satisfied a pinned lookup")
	}
}

func TestIsRootAnchoredAtContractRejectsUntrustedPin(t *testing.T) {
	want := mkLeaf(0xbb)

	registry := newTestRegistry(t, stubReceipts{receipt: successReceipt(
		batchLog(t, registryAddress, []common.Address{issuerAddress}, [][32]byte{want}),
	)})

	_, err := registry.IsRootAnchoredAtContract(
		context.Background(), common.Hash{}, issuerAddress, want, attackerAddress)
	if !errors.Is(err, ErrUntrustedContract) {
		t.Fatalf("err = %v, want ErrUntrustedContract", err)
	}
}

// A log with no topics reaches the decoder from any contract that emits one, and
// the switch indexes Topics[0] — so the guard has to come first.
func TestIsRootAnchoredTopiclessLog(t *testing.T) {
	registry := newTestRegistry(t, stubReceipts{receipt: successReceipt(
		&types.Log{Address: registryAddress},
	)})

	ok, err := anchoredFor(t, registry, mkLeaf(0xbb))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ok {
		t.Fatal("a topicless log was read as an anchoring")
	}
}

// An indexed event whose topics were truncated must not be indexed into either.
func TestIsRootAnchoredTruncatedTopics(t *testing.T) {
	// Each carries only the event id, with every indexed field missing.
	truncated := func(eventName string) *types.Log {
		return &types.Log{
			Address: registryAddress,
			Topics:  []common.Hash{eventID(t, eventName)},
		}
	}

	tests := []struct {
		name string
		log  *types.Log
	}{
		{"current single", truncated(singleAnchoredEvent)},
		{"current issuer batch", truncated(issuerAnchoredEvent)},
		{"legacy single", truncated(legacySingleEvent)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			registry := newTestRegistry(t, stubReceipts{receipt: successReceipt(tc.log)})

			ok, err := anchoredFor(t, registry, mkLeaf(0xbb))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if ok {
				t.Fatal("a log with missing topics was read as an anchoring")
			}
		})
	}
}

// An empty root folds out of a malformed proof and would otherwise be looked up
// like any other. Nothing anchors it, but failing loudly beats searching for a
// value that can never be there.
func TestIsRootAnchoredRejectsAnEmptyRoot(t *testing.T) {
	registry := newTestRegistry(t, stubReceipts{receipt: successReceipt()})

	if _, err := anchoredFor(t, registry, [32]byte{}); err == nil {
		t.Fatal("looking up an empty root was accepted")
	}
}

func TestIsRootAnchoredReceiptOutcomes(t *testing.T) {
	tests := []struct {
		name     string
		receipts stubReceipts
		wantErr  error
	}{
		{
			name:     "unknown or unmined transaction",
			receipts: stubReceipts{err: ethereum.NotFound},
			wantErr:  ErrTxNotFound,
		},
		{
			name:     "reverted transaction anchors nothing",
			receipts: stubReceipts{receipt: &types.Receipt{Status: types.ReceiptStatusFailed}},
			wantErr:  ErrTxReverted,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			registry := newTestRegistry(t, tc.receipts)

			if _, err := anchoredFor(t, registry, mkLeaf(0xbb)); !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// A registry built without a receipt source must fail with a reason rather than
// panic. Assigning a nil *ethclient.Client into the interface would make this
// guard pass and the call panic one line later, so the constructor never does.
func TestIsRootAnchoredWithoutAReceiptSource(t *testing.T) {
	registry := &CredentialRegistry{}

	if _, err := registry.IsRootAnchored(
		context.Background(), common.Hash{}, issuerAddress, mkLeaf(0xbb)); err == nil {
		t.Fatal("a lookup without a receipt source was accepted")
	}
}
