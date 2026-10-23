package subdid

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/pilacorp/go-credential-sdk/didv2/didcontract"
)

const (
	treeLeaf0     = "0xd40e8cdf47ef809607d4be35edfc75aa9cbc3bda443ab93c706956ecdba3d8a8"
	treeLeaf1     = "0x6438c3e7fdf61c59a979cf95b40ab859cfdccb3c9f0ac33249699461ebfd8363"
	treeLeaf2     = "0x6de90012fb12be46705b90a88415f7b49863cccefde9a86fd6943637efa2c1de"
	treeRoot      = "0x740265369adf60c8f89f0a3b1f92feb3643c702d228a8894c900006384e59a9f"
	treePath2     = "0xdf7c4019734ba03dd33f5d2f0365ef1dd49fc152631947e894b4c67ec69a01b2"
	treeIndexHex  = "0xddbf3a86f0876cd98e1f4fbfa04c8bad4be62d65ca7da74c6d1c40738f936453"
	anchorTxHex   = "0x3c71000000000000000000000000000000000000000000000000000000000001"
	legacyChainID = 704
)

var (
	treePaths = [][]string{
		{treeLeaf1, treeLeaf2},
		{treeLeaf0, treeLeaf2},
		{treePath2},
	}
	testRegistry = common.HexToAddress("0x75e7b09a24bce5a921babe27b62ec7bfe2230d6a")
	testWriter   = common.HexToAddress("0x5b6a5525e2c2d2428554b04d24b3bb5c1f3f5ae3")
)

type anchorEntry struct {
	did       common.Address
	treeIndex *big.Int
	root      common.Hash
}

func writerLog(t *testing.T, emitter common.Address, entries ...anchorEntry) *types.Log {
	t.Helper()

	addresses, _ := abi.NewType("address[]", "", nil)
	uints, _ := abi.NewType("uint256[]", "", nil)
	hashes, _ := abi.NewType("bytes32[]", "", nil)
	args := abi.Arguments{{Type: addresses}, {Type: uints}, {Type: hashes}}

	var dids []common.Address
	var treeIndexes []*big.Int
	var roots [][32]byte
	for _, e := range entries {
		dids = append(dids, e.did)
		treeIndexes = append(treeIndexes, e.treeIndex)
		roots = append(roots, e.root)
	}
	data, err := args.Pack(dids, treeIndexes, roots)
	if err != nil {
		t.Fatal(err)
	}

	topic0 := crypto.Keccak256Hash([]byte("BatchSubtreesAnchoredByWriter(address,address[],uint256[],bytes32[])"))
	return &types.Log{Address: emitter, Topics: []common.Hash{topic0, common.BytesToHash(testWriter.Bytes())}, Data: data}
}

func treeAnchor(root string) anchorEntry {
	treeIndex, _ := new(big.Int).SetString(treeIndexHex[2:], 16)
	return anchorEntry{did: common.HexToAddress(didAddress(rootR1)), treeIndex: treeIndex, root: common.HexToHash(root)}
}

// fakeChain answers as a node holding receipts at a DIDRegistry: a call to
// another address reads an empty account, an unknown selector reverts.
type fakeChain struct {
	down     bool
	chainID  int64
	receipts map[common.Hash]*types.Receipt
	writers  map[common.Address]bool
}

var errNodeDown = errors.New("dial tcp: connection refused")

func (f *fakeChain) ChainID(context.Context) (*big.Int, error) {
	if f.down {
		return nil, errNodeDown
	}
	return big.NewInt(f.chainID), nil
}

func (f *fakeChain) TransactionReceipt(_ context.Context, h common.Hash) (*types.Receipt, error) {
	if f.down {
		return nil, errNodeDown
	}
	r, ok := f.receipts[h]
	if !ok {
		return nil, ethereum.NotFound
	}
	return r, nil
}

func (f *fakeChain) CallContract(_ context.Context, msg ethereum.CallMsg, block *big.Int) ([]byte, error) {
	if f.down {
		return nil, errNodeDown
	}
	if block != nil {
		return nil, errors.New("fakeChain answers only the latest block")
	}
	if msg.To == nil || *msg.To != testRegistry {
		return []byte{}, nil
	}
	if len(msg.Data) != 68 || !bytes.Equal(msg.Data[:4], common.FromHex("0x91d14854")) {
		return nil, errors.New("execution reverted")
	}

	out := make([]byte, 32)
	if common.BytesToHash(msg.Data[4:36]) == didcontract.SubtreeWriterRole && f.writers[common.BytesToAddress(msg.Data[36:68])] {
		out[31] = 1
	}
	return out, nil
}

func provingChain(t *testing.T, logs ...*types.Log) *fakeChain {
	t.Helper()

	if len(logs) == 0 {
		logs = []*types.Log{writerLog(t, testRegistry, treeAnchor(treeRoot))}
	}
	return &fakeChain{
		chainID:  legacyChainID,
		receipts: map[common.Hash]*types.Receipt{common.HexToHash(anchorTxHex): {Status: types.ReceiptStatusSuccessful, Logs: logs}},
		writers:  map[common.Address]bool{testWriter: true},
	}
}

func newVerifier(t *testing.T, chains map[string]*fakeChain) *Verifier {
	t.Helper()

	var configured []Chain
	for code, client := range chains {
		configured = append(configured, Chain{Code: code, EVMChainID: legacyChainID, DIDRegistry: testRegistry, Client: client})
	}
	v, err := NewVerifier(configured...)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func proofFor(subDID string, index int, status string, chains ...string) *ProofResponse {
	p := &ProofResponse{DID: subDID, RootDID: rootR1, TreeIndex: treeIndexHex}
	for _, c := range chains {
		p.Chains = append(p.Chains, ChainProof{Chain: c, TxHash: anchorTxHex, Root: treeRoot, Path: treePaths[index], Status: status})
	}
	return p
}

func activeRequest(t *testing.T, chain string, chains ...string) VerifyRequest {
	return VerifyRequest{
		SubDID:   row1SubDID,
		Document: decodeFixture(t, createSubDIDJSON),
		Proof:    proofFor(row1SubDID, 0, statusActivated, chains...),
		Chain:    chain,
	}
}

func TestVerifySubDID_ActiveAndRevokedLeaves(t *testing.T) {
	v := newVerifier(t, map[string]*fakeChain{"did": provingChain(t)})

	res, err := v.VerifySubDID(context.Background(), activeRequest(t, "did", "did"))
	if err != nil || res.Status != StatusActive || res.Reason != "" || res.Chain != "did" || res.TxHash != common.HexToHash(anchorTxHex) {
		t.Errorf("leaf 0 with its document: %+v, %v", res, err)
	}

	res, err = v.VerifySubDID(context.Background(), VerifyRequest{
		SubDID: row2SubDID, Proof: proofFor(row2SubDID, 1, statusDeactivated, "did"), Chain: "did",
	})
	if err != nil || res.Status != StatusRevoked || res.Reason != "" {
		t.Errorf("leaf 1 without a document: %+v, %v", res, err)
	}

	req := activeRequest(t, "did", "did")
	req.Document = nil
	if _, err := v.VerifySubDID(context.Background(), req); !errors.Is(err, ErrDocumentRequired) {
		t.Errorf("activated without a document: %v, want ErrDocumentRequired", err)
	}
}

func TestVerifySubDID_Reasons(t *testing.T) {
	wrongRoot := treeAnchor(treeLeaf0)

	tests := []struct {
		reason Reason
		chain  *fakeChain
		edit   func(*VerifyRequest)
	}{
		{ReasonResponseMismatch, nil, func(r *VerifyRequest) { r.Proof.DID = row2SubDID }},
		{ReasonIDMismatch, nil, func(r *VerifyRequest) { r.Document.Controller = rootR2 }},
		{ReasonConsentInvalid, nil, func(r *VerifyRequest) { r.Document.DocumentMetadata[rootConsentKey] = rootConsentHighS }},
		{ReasonNoAnchor, &fakeChain{chainID: legacyChainID, receipts: map[common.Hash]*types.Receipt{
			common.HexToHash(anchorTxHex): {Status: types.ReceiptStatusFailed, Logs: []*types.Log{writerLog(t, testRegistry, treeAnchor(treeRoot))}},
		}, writers: map[common.Address]bool{testWriter: true}}, nil},
		{ReasonRootMismatch, provingChain(t, writerLog(t, testRegistry, wrongRoot)), nil},
		{ReasonWriterRevoked, &fakeChain{chainID: legacyChainID, receipts: provingChain(t).receipts}, nil},
		{ReasonProofMismatch, nil, func(r *VerifyRequest) { r.Proof.Chains[0].Path = treePaths[1] }},
	}
	for _, tt := range tests {
		chain := tt.chain
		if chain == nil {
			chain = provingChain(t)
		}
		req := activeRequest(t, "did", "did")
		if tt.edit != nil {
			tt.edit(&req)
		}

		res, err := newVerifier(t, map[string]*fakeChain{"did": chain}).VerifySubDID(context.Background(), req)
		if err != nil || res.Status != StatusInvalid || res.Reason != tt.reason {
			t.Errorf("%s: got %+v, %v", tt.reason, res, err)
		}
	}
}

func TestVerifySubDID_OnlyTheNamedChainIsRead(t *testing.T) {
	v := newVerifier(t, map[string]*fakeChain{"did": {down: true}, "trace": provingChain(t)})

	if _, err := v.VerifySubDID(context.Background(), activeRequest(t, "did", "did", "trace")); !errors.Is(err, ErrChainUnavailable) {
		t.Errorf("did down: %v, want ErrChainUnavailable", err)
	}

	res, err := v.VerifySubDID(context.Background(), activeRequest(t, "trace", "did", "trace"))
	if err != nil || res.Status != StatusActive || res.Chain != "trace" {
		t.Errorf("trace proving: %+v, %v", res, err)
	}
}

func TestVerifySubDID_NodeOnAnotherChainID(t *testing.T) {
	node := provingChain(t)
	node.chainID = 705

	_, err := newVerifier(t, map[string]*fakeChain{"did": node}).VerifySubDID(context.Background(), activeRequest(t, "did", "did"))
	if !errors.Is(err, ErrChainMismatch) || !errors.Is(err, ErrChainUnavailable) {
		t.Errorf("node answering 705: %v, want ErrChainMismatch", err)
	}
}

func TestVerifySubDID_NamedChainMissingFromTheProof(t *testing.T) {
	v := newVerifier(t, map[string]*fakeChain{"did": provingChain(t), "trace": provingChain(t)})

	if _, err := v.VerifySubDID(context.Background(), activeRequest(t, "did", "trace")); !errors.Is(err, ErrNotAnchored) {
		t.Errorf("did not in chains: %v, want ErrNotAnchored", err)
	}
}

func TestVerifySubDID_LastEntryForTheTreeWins(t *testing.T) {
	node := provingChain(t,
		writerLog(t, testRegistry, treeAnchor(treeLeaf0)),
		writerLog(t, testRegistry, treeAnchor(treeLeaf2), treeAnchor(treeRoot)),
	)

	res, err := newVerifier(t, map[string]*fakeChain{"did": node}).VerifySubDID(context.Background(), activeRequest(t, "did", "did"))
	if err != nil || res.Status != StatusActive {
		t.Errorf("two entries for the tree: %+v, %v", res, err)
	}
}
