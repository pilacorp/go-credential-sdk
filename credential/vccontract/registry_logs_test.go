package vccontract

import (
	"context"
	"encoding/json"
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

// TestIsRootAnchoredHandlesAReceiptSourceThatReturnsNothing covers the one thing
// the interface cannot enforce: a source that reports no error and no receipt.
//
// go-ethereum's own client turns that into ethereum.NotFound, but the receipt
// source is an interface precisely so other implementations can be used — a test
// double, a wrapper around a different node client — and one of those may not.
// Dereferencing the nil would panic here, inside a verification request.
func TestIsRootAnchoredHandlesAReceiptSourceThatReturnsNothing(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, stubReceipts{})

	if _, err := anchoredFor(t, registry, mkLeaf(0xbb)); err == nil {
		t.Fatal("a receipt source that returned nothing was accepted")
	}
}

// TestIsRootAnchoredRejectsABatchLogWithMismatchedArrays covers a batch log whose
// parallel arrays do not line up.
//
// The contract requires them to match — it reverts with ArrayLengthMismatch
// otherwise — so a log where they do not is not an anchoring this client can
// read: the ABI it was decoded against does not describe the event that was
// emitted, or the payload is damaged. Answering from the prefix would mean
// trusting part of a record whose shape is already known to be wrong.
func TestIsRootAnchoredRejectsABatchLogWithMismatchedArrays(t *testing.T) {
	t.Parallel()

	want := mkLeaf(0xbb)

	// The entry being asked about sits at index 0, so a scan bounded by the
	// shorter array would find it and answer true.
	logs := []struct {
		name string
		log  *types.Log
	}{
		{"current batch", packNonIndexed(t, registryAddress, batchAnchoredEvent,
			[]common.Address{issuerAddress, otherIssuer},
			[][32]byte{want})},
		{"legacy batch", packNonIndexed(t, registryAddress, legacyBatchEvent,
			[]common.Address{issuerAddress, otherIssuer},
			[]*big.Int{big.NewInt(legacyTreeIndex)},
			[][32]byte{want})},
	}

	for _, tc := range logs {
		t.Run(tc.name, func(t *testing.T) {
			registry := newTestRegistry(t, stubReceipts{receipt: successReceipt(tc.log)})

			ok, err := anchoredFor(t, registry, want)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if ok {
				t.Fatal("a log whose parallel arrays disagree was read as an anchoring")
			}
		})
	}
}

// TestGetAnchoredRootStillServesLegacyAnchorings covers the deprecated function
// kept for source compatibility.
//
// It shipped in v1.9.x and this module is still v1, so removing it would break
// `go get -u` at compile time for anyone who called it. Keeping it is only worth
// something if it still does what it did: a root anchored by the previous
// contract must still come back, by issuer and tree index, exactly as before.
func TestGetAnchoredRootStillServesLegacyAnchorings(t *testing.T) {
	t.Parallel()

	want := mkLeaf(0xbb)

	registry := newTestRegistry(t, stubReceipts{receipt: successReceipt(
		legacyBatchLog(t, registryAddress,
			[]common.Address{otherIssuer, issuerAddress},
			[][32]byte{mkLeaf(0x01), want}),
	)})

	// legacyBatchLog numbers the indices from legacyTreeIndex, so this entry is
	// the second one.
	got, err := registry.GetAnchoredRoot(
		context.Background(), common.Hash{}, issuerAddress, legacyTreeIndex+1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != want {
		t.Fatalf("got root %x, want %x", got, want)
	}
}

// The other half of the deprecation notice: against the current contract it
// cannot find anything, because those events carry no tree index to match. The
// notice says so, and this is what keeps that honest.
func TestGetAnchoredRootFindsNothingInCurrentEvents(t *testing.T) {
	t.Parallel()

	want := mkLeaf(0xbb)

	for _, tc := range []struct {
		name string
		log  *types.Log
	}{
		{"current single", singleLog(t, registryAddress, issuerAddress, want)},
		{"current cross-issuer batch", batchLog(t, registryAddress,
			[]common.Address{issuerAddress}, [][32]byte{want})},
		{"current issuer batch", issuerBatchLog(t, registryAddress, issuerAddress,
			[][32]byte{want})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry := newTestRegistry(t, stubReceipts{receipt: successReceipt(tc.log)})

			_, err := registry.GetAnchoredRoot(
				context.Background(), common.Hash{}, issuerAddress, legacyTreeIndex)
			if !errors.Is(err, ErrRootNotAnchored) {
				t.Fatalf("err = %v, want ErrRootNotAnchored", err)
			}
		})
	}
}

// receiptWithNilLog builds the receipt an RPC response of "logs":[null] produces.
//
// receipt.Logs is []*types.Log, so a JSON null unmarshals to a nil element. It is
// built by decoding real JSON rather than by writing []*types.Log{nil} directly,
// so the test keeps proving that this shape is reachable from the wire and not
// just constructible in Go.
func receiptWithNilLog(t *testing.T) *types.Receipt {
	t.Helper()

	const zeroBloom = "0x" + "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

	body := `{"status":"0x1","gasUsed":"0x0","cumulativeGasUsed":"0x0",` +
		`"logsBloom":"` + zeroBloom + `",` +
		`"transactionHash":"0x0000000000000000000000000000000000000000000000000000000000000000",` +
		`"logs":[null]}`

	var receipt types.Receipt
	if err := json.Unmarshal([]byte(body), &receipt); err != nil {
		t.Fatalf("unmarshal receipt: %v", err)
	}

	if len(receipt.Logs) != 1 || receipt.Logs[0] != nil {
		t.Fatalf("fixture did not produce a nil log entry: %#v", receipt.Logs)
	}

	return &receipt
}

// A nil entry in receipt.Logs must be skipped, not dereferenced. Reading Address
// off it panics before any emitter check can run — taking down the process on a
// verification request, because of what the other side sent.
func TestIsRootAnchoredSkipsNilLogs(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, stubReceipts{receipt: receiptWithNilLog(t)})

	ok, err := anchoredFor(t, registry, mkLeaf(0xbb))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ok {
		t.Fatal("a nil log was read as an anchoring")
	}
}

// The same loop exists in the deprecated GetAnchoredRoot, and was missed there
// too.
func TestGetAnchoredRootSkipsNilLogs(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, stubReceipts{receipt: receiptWithNilLog(t)})

	_, err := registry.GetAnchoredRoot(
		context.Background(), common.Hash{}, issuerAddress, legacyTreeIndex)
	if !errors.Is(err, ErrRootNotAnchored) {
		t.Fatalf("err = %v, want ErrRootNotAnchored", err)
	}
}

// A zero root is what FoldProof returns for the zero leaf with no siblings, so it
// arrives from ordinary callers rather than from anything malformed. The answer is
// no — the contract rejects an empty root with EmptyRoot, so none was ever
// anchored — and it has to come back as that answer.
//
// This used to be reported as an error, which surfaced as a 500 in the service
// built on this SDK and left the caller unable to tell a wrong proof from a broken
// service.
func TestIsRootAnchoredAnswersNoForAnEmptyRoot(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, stubReceipts{receipt: successReceipt()})

	found, err := anchoredFor(t, registry, [32]byte{})
	if err != nil {
		t.Fatalf("an empty root should be a verdict, not an error: %v", err)
	}

	if found {
		t.Error("an empty root was reported as anchored")
	}
}

// The receipt is never fetched for an empty root: the answer is known before any
// RPC call. A source that fails on every call proves the short circuit is real.
func TestIsRootAnchoredEmptyRootSkipsTheReceiptLookup(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, stubReceipts{err: errors.New("receipt source must not be called")})

	found, err := anchoredFor(t, registry, [32]byte{})
	if err != nil {
		t.Fatalf("empty root reached the receipt source: %v", err)
	}

	if found {
		t.Error("an empty root was reported as anchored")
	}
}
