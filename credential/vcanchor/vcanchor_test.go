package vcanchor

import (
	"fmt"
	"strings"
	"testing"
)

func TestBuildBatchGeneratesVerifiableReceipt(t *testing.T) {
	hashes := []string{
		"0x0000000000000000000000000000000000000000000000000000000000000001",
		"0x0000000000000000000000000000000000000000000000000000000000000002",
		"0x0000000000000000000000000000000000000000000000000000000000000003",
		"0x0000000000000000000000000000000000000000000000000000000000000004",
	}

	batch, err := BuildBatch(BatchInput{
		IssuerDID:      "did:pila:testnet:0xissuer",
		ExternalTreeID: "app-tree-001",
		VCHashes:       hashes,
	})
	if err != nil {
		t.Fatalf("BuildBatch returned error: %v", err)
	}

	if batch.HashScheme != HashSchemeKeccak256SortedPairsNoLeafHashV1 {
		t.Fatalf("unexpected hash scheme: %s", batch.HashScheme)
	}
	if batch.LeafCount != len(hashes) {
		t.Fatalf("unexpected leaf count: got %d want %d", batch.LeafCount, len(hashes))
	}
	if !strings.HasPrefix(batch.Root, "0x") || len(batch.Root) != 66 {
		t.Fatalf("root should be 0x-prefixed 32-byte hex, got %q", batch.Root)
	}

	receipt, err := batch.Receipt(hashes[2], "0xtx")
	if err != nil {
		t.Fatalf("Receipt returned error: %v", err)
	}
	if receipt.LeafIndex != 2 {
		t.Fatalf("unexpected leaf index: got %d want 2", receipt.LeafIndex)
	}
	if len(receipt.Proof) != 2 {
		t.Fatalf("unexpected proof length: got %d want 2", len(receipt.Proof))
	}

	verified, err := VerifyReceiptLocal(*receipt, len(hashes))
	if err != nil {
		t.Fatalf("VerifyReceiptLocal returned error: %v", err)
	}
	if !verified {
		t.Fatal("receipt should verify")
	}
}

func TestVerifyReceiptLocalRejectsTamperedLeaf(t *testing.T) {
	batch, err := BuildBatch(BatchInput{
		IssuerDID:      "did:pila:testnet:0xissuer",
		ExternalTreeID: "app-tree-001",
		VCHashes: []string{
			"0x0000000000000000000000000000000000000000000000000000000000000001",
			"0x0000000000000000000000000000000000000000000000000000000000000002",
			"0x0000000000000000000000000000000000000000000000000000000000000003",
		},
	})
	if err != nil {
		t.Fatalf("BuildBatch returned error: %v", err)
	}

	receipt, err := batch.Receipt("0x0000000000000000000000000000000000000000000000000000000000000002", "0xtx")
	if err != nil {
		t.Fatalf("Receipt returned error: %v", err)
	}

	receipt.VCHash = "0x0000000000000000000000000000000000000000000000000000000000000009"

	verified, err := VerifyReceiptLocal(*receipt, 3)
	if err != nil {
		t.Fatalf("VerifyReceiptLocal returned error: %v", err)
	}
	if verified {
		t.Fatal("tampered receipt should not verify")
	}
}

func TestBuildBatchRejectsDuplicateHashes(t *testing.T) {
	_, err := BuildBatch(BatchInput{
		IssuerDID:      "did:pila:testnet:0xissuer",
		ExternalTreeID: "app-tree-001",
		VCHashes: []string{
			"0x0000000000000000000000000000000000000000000000000000000000000001",
			"0000000000000000000000000000000000000000000000000000000000000001",
		},
	})
	if err == nil {
		t.Fatal("expected duplicate hash error")
	}
}

// proofLen is what stops an internal node from passing as a leaf, so it must match
// the tree builder exactly. Cross-check the formula against real proofs rather than
// trusting it, including the odd-leaf shapes where the last node pairs with itself.
func TestProofLenMatchesGeneratedProofs(t *testing.T) {
	for leafCount := 1; leafCount <= 40; leafCount++ {
		leaves := make([][]byte, leafCount)
		for i := range leaves {
			leaf := make([]byte, 32)
			leaf[30] = byte(i / 256)
			leaf[31] = byte(i % 256)
			leaves[i] = leaf
		}

		for _, idx := range []int{0, leafCount / 2, leafCount - 1} {
			proof, err := merkleProof(leaves, idx)
			if err != nil {
				t.Fatalf("merkleProof(leafCount=%d, idx=%d) returned error: %v", leafCount, idx, err)
			}
			if got := proofLen(leafCount); got != len(proof) {
				t.Errorf("leafCount=%d idx=%d: proofLen=%d but real proof has %d siblings",
					leafCount, idx, got, len(proof))
			}
		}
	}
}

// A batch-issued receipt must carry leaf_count and still verify end to end.
func TestReceiptCarriesLeafCountAndVerifies(t *testing.T) {
	hashes := []string{
		"0x0000000000000000000000000000000000000000000000000000000000000001",
		"0x0000000000000000000000000000000000000000000000000000000000000002",
		"0x0000000000000000000000000000000000000000000000000000000000000003",
	}

	batch, err := BuildBatch(BatchInput{
		IssuerDID:      "did:pila:testnet:0xissuer",
		ExternalTreeID: "app-tree-leafcount",
		VCHashes:       hashes,
	})
	if err != nil {
		t.Fatalf("BuildBatch returned error: %v", err)
	}

	receipt, err := batch.Receipt(hashes[1], "0xtx")
	if err != nil {
		t.Fatalf("Receipt returned error: %v", err)
	}
	if receipt.LeafCount != len(hashes) {
		t.Fatalf("receipt leaf_count = %d, want %d", receipt.LeafCount, len(hashes))
	}

	ok, err := VerifyReceiptLocal(*receipt, len(hashes))
	if err != nil {
		t.Fatalf("VerifyReceiptLocal returned error: %v", err)
	}
	if !ok {
		t.Fatal("a genuine receipt must verify")
	}
}

// Merkle second-preimage: leaves go into the tree unhashed, so an internal node
// recomputed from a published receipt folds to the same root. The offline verifier
// must reject it just as the server does.
func TestVerifyReceiptLocalRejectsInternalNodeAsLeaf(t *testing.T) {
	hashes := []string{
		"0x0000000000000000000000000000000000000000000000000000000000000001",
		"0x0000000000000000000000000000000000000000000000000000000000000002",
		"0x0000000000000000000000000000000000000000000000000000000000000003",
		"0x0000000000000000000000000000000000000000000000000000000000000004",
	}

	batch, err := BuildBatch(BatchInput{
		IssuerDID:      "did:pila:testnet:0xissuer",
		ExternalTreeID: "app-tree-preimage",
		VCHashes:       hashes,
	})
	if err != nil {
		t.Fatalf("BuildBatch returned error: %v", err)
	}

	// Everything below is derived from the published receipt alone.
	receipt, err := batch.Receipt(hashes[0], "0xtx")
	if err != nil {
		t.Fatalf("Receipt returned error: %v", err)
	}

	_, leaf0, err := normalizeHash32(receipt.VCHash)
	if err != nil {
		t.Fatalf("normalizeHash32 returned error: %v", err)
	}
	_, sibling0, err := normalizeHash32(receipt.Proof[0])
	if err != nil {
		t.Fatalf("normalizeHash32 returned error: %v", err)
	}

	internal := mergeSorted(leaf0, sibling0)

	forged := *receipt
	forged.VCHash = hexHash(internal)
	forged.Proof = receipt.Proof[1:]

	// Guard the test itself: without the length check this really would fold to the
	// root, so the assertion below is meaningful rather than accidentally true.
	_, root, err := normalizeHash32(receipt.Root)
	if err != nil {
		t.Fatalf("normalizeHash32 returned error: %v", err)
	}
	rawProof := make([][]byte, 0, len(forged.Proof))
	for _, s := range forged.Proof {
		_, raw, err := normalizeHash32(s)
		if err != nil {
			t.Fatalf("normalizeHash32 returned error: %v", err)
		}
		rawProof = append(rawProof, raw)
	}
	if !verifyProof(internal, rawProof, root) {
		t.Fatal("test setup: the internal node does not fold to the root")
	}

	// The attacker controls every field of the receipt, so run both moves they have.
	for _, tc := range []struct {
		name      string
		leafCount int
	}{
		// Leaving the real count in place: the proof is now one sibling short.
		{name: "declared count untouched", leafCount: len(hashes)},
		// Shrinking the count so ceil(log2(n)) matches the short proof. Only checking
		// the length against the anchored count catches this one.
		{name: "declared count lowered to fit", leafCount: len(hashes) / 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempt := forged
			attempt.LeafCount = tc.leafCount

			ok, err := VerifyReceiptLocal(attempt, len(hashes))
			if err != nil {
				t.Fatalf("VerifyReceiptLocal returned error: %v", err)
			}
			if ok {
				t.Fatal("an internal node must not verify as a VC hash")
			}
		})
	}
}

func TestVerifyReceiptLocalRejectsReceiptWithoutLeafCount(t *testing.T) {
	receipt := Receipt{
		VCHash:     "0x0000000000000000000000000000000000000000000000000000000000000001",
		Root:       "0x0000000000000000000000000000000000000000000000000000000000000001",
		HashScheme: HashSchemeKeccak256SortedPairsNoLeafHashV1,
	}

	// No anchored count to check against: the caller has nothing to verify with, which
	// is a caller bug rather than a bad receipt, so it is an error and not a false.
	if _, err := VerifyReceiptLocal(receipt, 0); err == nil {
		t.Fatal("verification without an anchored leaf_count must error")
	}

	ok, err := VerifyReceiptLocal(receipt, 1)
	if err != nil {
		t.Fatalf("VerifyReceiptLocal returned error: %v", err)
	}
	if ok {
		t.Fatal("a receipt whose leaf_count is missing must not verify")
	}
}

// MaxLeavesPerBatch bounds the memory a single tree can take. Nothing else enforces
// it, so a batch one leaf over the cap must be refused at build time.
func TestBuildBatchRejectsMoreThanMaxLeaves(t *testing.T) {
	hashes := make([]string, MaxLeavesPerBatch+1)
	for i := range hashes {
		hashes[i] = fmt.Sprintf("0x%064x", i+1)
	}

	if _, err := BuildBatch(BatchInput{
		IssuerDID:      "did:pila:testnet:0xissuer",
		ExternalTreeID: "app-tree-oversized",
		VCHashes:       hashes,
	}); err == nil {
		t.Fatalf("a batch of %d leaves must be rejected", len(hashes))
	}

	if _, err := BuildBatch(BatchInput{
		IssuerDID:      "did:pila:testnet:0xissuer",
		ExternalTreeID: "app-tree-at-cap",
		VCHashes:       hashes[:MaxLeavesPerBatch],
	}); err != nil {
		t.Fatalf("a batch of exactly %d leaves must build: %v", MaxLeavesPerBatch, err)
	}
}
