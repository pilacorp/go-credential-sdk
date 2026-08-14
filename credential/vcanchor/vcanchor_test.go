package vcanchor

import (
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

	verified, err := VerifyReceiptLocal(*receipt)
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

	verified, err := VerifyReceiptLocal(*receipt)
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
