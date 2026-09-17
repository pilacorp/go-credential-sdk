package vccontract

import (
	"context"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// These cover VerifyVCHashByTx itself — the entry point every integration calls.
// The pieces underneath have their own tests, but the switch that turns their
// answers into a verdict has none of its own, and it is where a mistake is
// invisible: swallowing an error there reads as "not verified" and nothing fails.

// A two-leaf tree: the leaf under test, its one sibling, and the root they fold to.
func twoLeafTree() (leaf, sibling, root [32]byte) {
	leaf, sibling = mkLeaf(0xa1), mkLeaf(0xb2)

	return leaf, sibling, hashPair(leaf, sibling)
}

func TestVerifyVCHashByTx(t *testing.T) {
	t.Parallel()

	leaf, sibling, root := twoLeafTree()
	txHash := mkLeaf(0xcd)

	// The anchoring that backs the happy path, emitted by the main deployment.
	anchoring := func(t *testing.T, emitter common.Address) *types.Receipt {
		t.Helper()

		return successReceipt(batchLog(t, emitter, []common.Address{issuerAddress}, [][32]byte{root}))
	}

	tests := []struct {
		name string
		// receipt the chain answers with; nil means use the standard anchoring.
		receipt func(*testing.T) *types.Receipt
		err     error
		// trusted deployments beyond registryAddress
		alsoTrust []common.Address
		// mutate the request built from the fixtures above
		mutate func(*VerifyByTxRequest)

		want    bool
		wantErr error
	}{
		{
			name: "the leaf this transaction anchored",
			want: true,
		},
		{
			name:   "a proof that folds to something else",
			mutate: func(r *VerifyByTxRequest) { r.Proof = []string{hexOf(mkLeaf(0xee))} },
			want:   false,
		},
		{
			name:   "a leaf that is not in the tree",
			mutate: func(r *VerifyByTxRequest) { r.Leaf = hexOf(mkLeaf(0xef)) },
			want:   false,
		},
		{
			name:   "an anchoring by a different issuer",
			mutate: func(r *VerifyByTxRequest) { r.IssuerAddress = otherIssuer.Hex() },
			want:   false,
		},
		{
			// The behaviour argued for in review: a reverted transaction ran and
			// wrote nothing, so "does not attest the leaf" is a verdict already
			// known, not a failure to check.
			name:    "a reverted transaction is a verdict, not a failure",
			receipt: func(*testing.T) *types.Receipt { return &types.Receipt{Status: types.ReceiptStatusFailed} },
			want:    false,
		},
		{
			// The opposite: nothing was established, so the caller must be able to
			// tell and retry rather than record a failed verification.
			name:    "an unmined transaction is a failure, not a verdict",
			err:     ethereum.NotFound,
			wantErr: ErrTxNotFound,
		},
		{
			name:      "pinned to the deployment that emitted the log",
			receipt:   func(t *testing.T) *types.Receipt { return anchoring(t, legacyAddress) },
			alsoTrust: []common.Address{legacyAddress},
			mutate:    func(r *VerifyByTxRequest) { r.ContractAddress = legacyAddress.Hex() },
			want:      true,
		},
		{
			// Trusted, but not the one that emitted this log. Pinning must actually
			// narrow: a log from elsewhere in the trusted set cannot satisfy it.
			name:      "pinned to another trusted deployment",
			alsoTrust: []common.Address{legacyAddress},
			mutate:    func(r *VerifyByTxRequest) { r.ContractAddress = legacyAddress.Hex() },
			want:      false,
		},
		{
			// Pinning can only narrow what is believed. Honouring an unknown
			// address would let a caller nominate any contract at all.
			name:    "pinned to a deployment outside the trusted set",
			mutate:  func(r *VerifyByTxRequest) { r.ContractAddress = attackerAddress.Hex() },
			wantErr: ErrUntrustedContract,
		},
		{
			name:    "malformed request",
			mutate:  func(r *VerifyByTxRequest) { r.IssuerAddress = "not-an-address" },
			wantErr: nil, // any error will do; checked below
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			receipts := stubReceipts{err: tc.err}
			if tc.err == nil {
				build := tc.receipt
				if build == nil {
					build = func(t *testing.T) *types.Receipt { return anchoring(t, registryAddress) }
				}

				receipts.receipt = build(t)
			}

			registry := newTestRegistry(t, receipts, tc.alsoTrust...)

			req := &VerifyByTxRequest{
				IssuerAddress: issuerAddress.Hex(),
				Leaf:          hexOf(leaf),
				Proof:         []string{hexOf(sibling)},
				TxHash:        hexOf(txHash),
			}
			if tc.mutate != nil {
				tc.mutate(req)
			}

			ok, err := registry.VerifyVCHashByTx(context.Background(), req)

			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}

				return
			case tc.name == "malformed request":
				if err == nil {
					t.Fatal("a malformed request was accepted")
				}

				return
			case err != nil:
				t.Fatalf("unexpected error: %v", err)
			}

			if ok != tc.want {
				t.Fatalf("verified = %v, want %v", ok, tc.want)
			}
		})
	}
}
