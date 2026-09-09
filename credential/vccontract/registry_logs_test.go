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

const testTreeIndex = 7

// stubReceipts serves one canned receipt, standing in for the chain so the
// log-filtering rules can be exercised directly.
type stubReceipts struct {
	receipt *types.Receipt
	err     error
}

func (s stubReceipts) TransactionReceipt(context.Context, common.Hash) (*types.Receipt, error) {
	return s.receipt, s.err
}

// newTestRegistry builds a registry with no RPC connection: anchoredRoot needs
// only the receipt source, the ABI, and the trusted set.
func newTestRegistry(t *testing.T, receipts receiptSource, trusted ...common.Address) *CredentialRegistry {
	t.Helper()

	contractABI, err := loadABI()
	if err != nil {
		t.Fatalf("failed to load ABI: %v", err)
	}

	set := make(map[common.Address]struct{}, len(trusted))
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

// batchLog builds a well-formed BatchTreesUpdated log emitted by emitter. All
// three fields are non-indexed, so they are packed into the data section.
func batchLog(t *testing.T, emitter common.Address, issuers []common.Address, treeIndices []int64, roots [][32]byte) *types.Log {
	t.Helper()

	contractABI, err := loadABI()
	if err != nil {
		t.Fatalf("failed to load ABI: %v", err)
	}

	indices := make([]*big.Int, len(treeIndices))
	for i, index := range treeIndices {
		indices[i] = big.NewInt(index)
	}

	event := contractABI.Events[anchoredRootEvent]

	data, err := event.Inputs.NonIndexed().Pack(issuers, indices, roots)
	if err != nil {
		t.Fatalf("failed to pack %s: %v", anchoredRootEvent, err)
	}

	return &types.Log{
		Address: emitter,
		Topics:  []common.Hash{event.ID},
		Data:    data,
	}
}

// treeUpdatedLog builds a well-formed TreeUpdated log emitted by emitter. Its
// issuer and tree index are indexed, so they go in the topics and only the root
// is packed into the data section.
func treeUpdatedLog(t *testing.T, emitter, issuer common.Address, treeIndex int64, root [32]byte) *types.Log {
	t.Helper()

	contractABI, err := loadABI()
	if err != nil {
		t.Fatalf("failed to load ABI: %v", err)
	}

	event := contractABI.Events[singleRootEvent]

	data, err := event.Inputs.NonIndexed().Pack(root)
	if err != nil {
		t.Fatalf("failed to pack %s: %v", singleRootEvent, err)
	}

	return &types.Log{
		Address: emitter,
		Topics: []common.Hash{
			event.ID,
			common.BytesToHash(issuer.Bytes()),
			common.BigToHash(big.NewInt(treeIndex)),
		},
		Data: data,
	}
}

func successReceipt(logs ...*types.Log) *types.Receipt {
	return &types.Receipt{Status: types.ReceiptStatusSuccessful, Logs: logs}
}

func anchoredRootOf(t *testing.T, registry *CredentialRegistry) ([32]byte, error) {
	t.Helper()

	return registry.GetAnchoredRoot(context.Background(), common.Hash{}, issuerAddress, testTreeIndex)
}

// TestGetAnchoredRootRejectsForeignEmitter is the negative test the change
// hinges on. Anyone can deploy a contract emitting these exact signatures, so a
// perfectly well-formed anchoring log from an address outside the trusted set
// must not be believed. Without the emitter check, any transaction at all could
// pose as a valid anchoring.
func TestGetAnchoredRootRejectsForeignEmitter(t *testing.T) {
	root := mkLeaf(0xaa)

	cases := []struct {
		name string
		log  *types.Log
	}{
		{
			name: "batch event from an untrusted contract",
			log: batchLog(t, attackerAddress,
				[]common.Address{issuerAddress}, []int64{testTreeIndex}, [][32]byte{root}),
		},
		{
			name: "single event from an untrusted contract",
			log:  treeUpdatedLog(t, attackerAddress, issuerAddress, testTreeIndex, root),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registry := newTestRegistry(t,
				stubReceipts{receipt: successReceipt(tc.log)},
				registryAddress,
			)

			got, err := anchoredRootOf(t, registry)
			if !errors.Is(err, ErrRootNotAnchored) {
				t.Fatalf("foreign emitter accepted: got root %x, err %v", got, err)
			}
		})
	}
}

// TestGetAnchoredRootBatch covers the path every anchoring takes today: one
// transaction carries many trees, and only the entry matching both the issuer
// and the tree index is the caller's.
func TestGetAnchoredRootBatch(t *testing.T) {
	want := mkLeaf(0xbb)

	log := batchLog(t, registryAddress,
		[]common.Address{otherIssuer, issuerAddress, issuerAddress},
		[]int64{testTreeIndex, 3, testTreeIndex},
		[][32]byte{mkLeaf(0x01), mkLeaf(0x02), want},
	)

	registry := newTestRegistry(t, stubReceipts{receipt: successReceipt(log)}, registryAddress)

	got, err := anchoredRootOf(t, registry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("wrong entry selected: got %x want %x", got, want)
	}
}

// TestGetAnchoredRootTreeUpdated covers a root anchored on its own rather than
// in a batch. Before roots stopped being kept in storage this event could be
// ignored, because a view call would still find the root; now missing it would
// report a genuinely anchored tree as never anchored.
func TestGetAnchoredRootTreeUpdated(t *testing.T) {
	want := mkLeaf(0xcc)

	log := treeUpdatedLog(t, registryAddress, issuerAddress, testTreeIndex, want)
	registry := newTestRegistry(t, stubReceipts{receipt: successReceipt(log)}, registryAddress)

	got, err := anchoredRootOf(t, registry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("root mismatch: got %x want %x", got, want)
	}
}

// TestGetAnchoredRootTreeUpdatedIgnoresOtherTrees checks that the indexed topics
// are actually compared, not just assumed to match.
func TestGetAnchoredRootTreeUpdatedIgnoresOtherTrees(t *testing.T) {
	cases := []struct {
		name string
		log  *types.Log
	}{
		{
			name: "another issuer, same tree index",
			log:  treeUpdatedLog(t, registryAddress, otherIssuer, testTreeIndex, mkLeaf(0x11)),
		},
		{
			name: "same issuer, another tree index",
			log:  treeUpdatedLog(t, registryAddress, issuerAddress, testTreeIndex+1, mkLeaf(0x12)),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registry := newTestRegistry(t, stubReceipts{receipt: successReceipt(tc.log)}, registryAddress)

			if got, err := anchoredRootOf(t, registry); !errors.Is(err, ErrRootNotAnchored) {
				t.Fatalf("unrelated tree accepted: got root %x, err %v", got, err)
			}
		})
	}
}

// TestGetAnchoredRootMalformedTopics feeds a log that claims the TreeUpdated ID
// but carries the wrong number of topics. Indexing into it blindly would panic,
// turning a malformed log from a trusted contract into a crash.
func TestGetAnchoredRootMalformedTopics(t *testing.T) {
	contractABI, err := loadABI()
	if err != nil {
		t.Fatalf("failed to load ABI: %v", err)
	}

	log := &types.Log{
		Address: registryAddress,
		Topics: []common.Hash{
			contractABI.Events[singleRootEvent].ID,
			common.BytesToHash(issuerAddress.Bytes()),
		},
		Data: nil,
	}

	registry := newTestRegistry(t, stubReceipts{receipt: successReceipt(log)}, registryAddress)

	if got, err := anchoredRootOf(t, registry); !errors.Is(err, ErrRootNotAnchored) {
		t.Fatalf("malformed log accepted: got root %x, err %v", got, err)
	}
}

// TestGetAnchoredRootTrustsEveryConfiguredContract covers a tree that stays open
// across a migration: earlier anchorings sit at the previous deployment, and
// both must remain verifiable.
func TestGetAnchoredRootTrustsEveryConfiguredContract(t *testing.T) {
	want := mkLeaf(0xdd)

	log := batchLog(t, legacyAddress,
		[]common.Address{issuerAddress}, []int64{testTreeIndex}, [][32]byte{want})

	registry := newTestRegistry(t,
		stubReceipts{receipt: successReceipt(log)},
		registryAddress, legacyAddress,
	)

	got, err := anchoredRootOf(t, registry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("root mismatch: got %x want %x", got, want)
	}
}

// TestGetAnchoredRootFromContractPinsEmitter checks that pinning narrows the
// trusted set: a root anchored by one trusted deployment must not satisfy a
// lookup pinned to another.
func TestGetAnchoredRootFromContractPinsEmitter(t *testing.T) {
	want := mkLeaf(0xee)

	log := batchLog(t, legacyAddress,
		[]common.Address{issuerAddress}, []int64{testTreeIndex}, [][32]byte{want})

	registry := newTestRegistry(t,
		stubReceipts{receipt: successReceipt(log)},
		registryAddress, legacyAddress,
	)

	got, err := registry.GetAnchoredRootFromContract(
		context.Background(), common.Hash{}, issuerAddress, testTreeIndex, legacyAddress)
	if err != nil {
		t.Fatalf("unexpected error for the anchoring contract: %v", err)
	}
	if got != want {
		t.Fatalf("root mismatch: got %x want %x", got, want)
	}

	got, err = registry.GetAnchoredRootFromContract(
		context.Background(), common.Hash{}, issuerAddress, testTreeIndex, registryAddress)
	if !errors.Is(err, ErrRootNotAnchored) {
		t.Fatalf("pin ignored: got root %x, err %v", got, err)
	}
}

// TestGetAnchoredRootFromContractRejectsUntrustedPin checks that pinning can
// only ever narrow the trusted set. The address is caller input, so honouring an
// unknown one would let a caller nominate the attacker's contract and undo the
// emitter check entirely.
func TestGetAnchoredRootFromContractRejectsUntrustedPin(t *testing.T) {
	log := batchLog(t, attackerAddress,
		[]common.Address{issuerAddress}, []int64{testTreeIndex}, [][32]byte{mkLeaf(0x21)})

	registry := newTestRegistry(t, stubReceipts{receipt: successReceipt(log)}, registryAddress)

	_, err := registry.GetAnchoredRootFromContract(
		context.Background(), common.Hash{}, issuerAddress, testTreeIndex, attackerAddress)
	if !errors.Is(err, ErrUntrustedContract) {
		t.Fatalf("expected ErrUntrustedContract, got %v", err)
	}
}

func TestGetAnchoredRootReceiptOutcomes(t *testing.T) {
	cases := []struct {
		name     string
		receipts stubReceipts
		want     error
	}{
		{
			name:     "unknown or unmined transaction",
			receipts: stubReceipts{err: ethereum.NotFound},
			want:     ErrTxNotFound,
		},
		{
			name:     "reverted transaction anchors nothing",
			receipts: stubReceipts{receipt: &types.Receipt{Status: types.ReceiptStatusFailed}},
			want:     ErrTxReverted,
		},
		{
			name:     "successful transaction with no anchoring log",
			receipts: stubReceipts{receipt: successReceipt()},
			want:     ErrRootNotAnchored,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registry := newTestRegistry(t, tc.receipts, registryAddress)

			if _, err := anchoredRootOf(t, registry); !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

// TestAnchoringEventIDs pins the embedded ABI's two anchoring events to the
// topic hashes of the deployed NDACredential contract.
//
// The ABI here is a hand-trimmed subset rather than compiler output, so a typo
// in a field name or type would change the event ID and make every log stop
// matching — with no error anywhere, just verification quietly reporting that
// nothing was ever anchored.
func TestAnchoringEventIDs(t *testing.T) {
	contractABI, err := loadABI()
	if err != nil {
		t.Fatalf("failed to load ABI: %v", err)
	}

	cases := map[string]string{
		anchoredRootEvent: "0xdfca0e820844f18511e987f70077b11bc4543e954283a833a15d51abdbbc7cd0",
		singleRootEvent:   "0x6359763dd97d67c7b79a119f0e38c8d995c8b2fd50f10d53b24d9949ca132fdb",
	}

	for name, want := range cases {
		event, ok := contractABI.Events[name]
		if !ok {
			t.Fatalf("event %s is missing from the embedded ABI", name)
		}

		if got := event.ID.Hex(); got != want {
			t.Fatalf("event %s topic mismatch: got %s want %s", name, got, want)
		}
	}
}

// TestNewCredentialRegistryRejectsBadAlsoTrust confirms a malformed trusted
// address fails at construction. common.HexToAddress would otherwise quietly
// truncate or zero-pad it into a plausible-looking address that never matches.
func TestNewCredentialRegistryRejectsBadAlsoTrust(t *testing.T) {
	_, err := NewCredentialRegistry(
		"http://localhost:8545",
		registryAddress.Hex(),
		"not-an-address",
	)
	if err == nil {
		t.Fatal("expected an error for a malformed alsoTrust address")
	}
}
