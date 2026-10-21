package didcontract

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

const writerAnchorTopic0 = "0x39edf358809bd8ab55bfce6add00fc1843a5c6e38ca5257fe7fb98b8bb145469"

var (
	testRegistry = common.HexToAddress("0x75e7b09a24bce5a921babe27b62ec7bfe2230d6a")
	testWriter   = common.HexToAddress("0x5b6a5525e2c2d2428554b04d24b3bb5c1f3f5ae3")
)

func writerLog(t *testing.T, emitter common.Address, index uint, dids []common.Address, treeIndexes []*big.Int, roots [][32]byte) *types.Log {
	t.Helper()

	contractABI, err := loadABI()
	if err != nil {
		t.Fatal(err)
	}
	event := contractABI.Events[writerAnchorEvent]
	data, err := event.Inputs.NonIndexed().Pack(dids, treeIndexes, roots)
	if err != nil {
		t.Fatal(err)
	}

	return &types.Log{
		Address: emitter,
		Topics:  []common.Hash{event.ID, common.BytesToHash(testWriter.Bytes())},
		Data:    data,
		Index:   index,
	}
}

func TestSubtreeABI_MatchesTheContract(t *testing.T) {
	contractABI, err := loadABI()
	if err != nil {
		t.Fatal(err)
	}

	signature := crypto.Keccak256Hash([]byte("BatchSubtreesAnchoredByWriter(address,address[],uint256[],bytes32[])"))
	if signature.Hex() != writerAnchorTopic0 || contractABI.Events[writerAnchorEvent].ID != signature {
		t.Errorf("topic0 = %s, ABI event id = %s, want %s", signature.Hex(), contractABI.Events[writerAnchorEvent].ID.Hex(), writerAnchorTopic0)
	}
	if role := crypto.Keccak256Hash([]byte("SUBTREE_WRITER_ROLE")); SubtreeWriterRole != role {
		t.Errorf("SubtreeWriterRole = %s, want %s", SubtreeWriterRole.Hex(), role.Hex())
	}
	if selector := common.Bytes2Hex(contractABI.Methods[hasRoleMethod].ID); selector != "91d14854" {
		t.Errorf("hasRole selector = 0x%s, want 0x91d14854", selector)
	}
}

func TestDecodeWriterAnchors_BatchInOrderFromTheRegistryOnly(t *testing.T) {
	const n = 64
	dids := make([]common.Address, n)
	treeIndexes := make([]*big.Int, n)
	roots := make([][32]byte, n)
	for i := range n {
		dids[i] = common.BigToAddress(big.NewInt(int64(1000 + i)))
		treeIndexes[i] = big.NewInt(int64(i))
		roots[i] = crypto.Keccak256Hash(big.NewInt(int64(i)).Bytes())
	}

	other := common.HexToAddress("0x0000000000000000000000000000000000000bad")
	receipt := &types.Receipt{Logs: []*types.Log{
		writerLog(t, other, 3, dids[:1], treeIndexes[:1], roots[:1]),
		nil,
		writerLog(t, testRegistry, 7, dids, treeIndexes, roots),
	}}

	anchors, err := DecodeWriterAnchors(receipt, testRegistry)
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != n {
		t.Fatalf("decoded %d anchors, want %d", len(anchors), n)
	}
	for i, a := range anchors {
		if a.Writer != testWriter || a.DID != dids[i] || a.TreeIndex.Cmp(treeIndexes[i]) != 0 ||
			a.Root != roots[i] {
			t.Fatalf("anchor %d = %+v", i, a)
		}
	}
}

func TestDecodeWriterAnchors_UnequalArraysAreRefused(t *testing.T) {
	receipt := &types.Receipt{Logs: []*types.Log{
		writerLog(t, testRegistry, 0,
			[]common.Address{testWriter, testWriter}, []*big.Int{big.NewInt(1)}, [][32]byte{{1}, {2}}),
	}}

	if _, err := DecodeWriterAnchors(receipt, testRegistry); err == nil {
		t.Error("an event with unequal arrays was decoded")
	}
}
