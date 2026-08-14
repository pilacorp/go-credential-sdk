package vcanchor

import (
	"context"
	"testing"
)

type fakeSubmitter struct {
	txHash string
	req    SubmitRootRequest
}

func (f *fakeSubmitter) SubmitRoot(ctx context.Context, req SubmitRootRequest) (*SubmitRootResponse, error) {
	f.req = req
	return &SubmitRootResponse{
		IssuerDID:      req.IssuerDID,
		ExternalTreeID: req.ExternalTreeID,
		Root:           req.Root,
		TxHash:         f.txHash,
		Status:         "anchored",
	}, nil
}

func TestManagerPersistsBatchAndGeneratesReceiptFromStore(t *testing.T) {
	ctx := context.Background()
	store := newTestFileStore(t)
	submitter := &fakeSubmitter{txHash: "0xtx"}
	manager := NewManager(store, submitter)

	hashes := []string{
		"0x0000000000000000000000000000000000000000000000000000000000000001",
		"0x0000000000000000000000000000000000000000000000000000000000000002",
		"0x0000000000000000000000000000000000000000000000000000000000000003",
	}

	batch, err := manager.CreateBatch(ctx, BatchInput{
		IssuerDID:      "did:pila:testnet:0xissuer",
		ExternalTreeID: "app-tree-001",
		VCHashes:       hashes,
	})
	if err != nil {
		t.Fatalf("CreateBatch returned error: %v", err)
	}

	if err := manager.ValidateStoredBatch(ctx, batch.IssuerDID, batch.ExternalTreeID); err != nil {
		t.Fatalf("ValidateStoredBatch returned error: %v", err)
	}

	resp, err := manager.SubmitRoot(ctx, batch.IssuerDID, batch.ExternalTreeID)
	if err != nil {
		t.Fatalf("SubmitRoot returned error: %v", err)
	}
	if resp.TxHash != "0xtx" {
		t.Fatalf("unexpected tx hash: %s", resp.TxHash)
	}
	if submitter.req.Root != batch.Root {
		t.Fatalf("submitted root mismatch: got %s want %s", submitter.req.Root, batch.Root)
	}

	receipt, err := manager.GenerateReceipt(ctx, batch.IssuerDID, batch.ExternalTreeID, hashes[1])
	if err != nil {
		t.Fatalf("GenerateReceipt returned error: %v", err)
	}
	if receipt.TxHash != "0xtx" {
		t.Fatalf("receipt should use anchored tx hash, got %s", receipt.TxHash)
	}

	verified, err := VerifyReceiptLocal(*receipt)
	if err != nil {
		t.Fatalf("VerifyReceiptLocal returned error: %v", err)
	}
	if !verified {
		t.Fatal("receipt generated from store should verify")
	}
}

func TestFileStoreRejectsSameTreeWithDifferentDigest(t *testing.T) {
	ctx := context.Background()
	store := newTestFileStore(t)

	first, err := batchToStoredBatch(mustBuildBatch(t, "app-tree-001", []string{
		"0x0000000000000000000000000000000000000000000000000000000000000001",
	}))
	if err != nil {
		t.Fatalf("batchToStoredBatch returned error: %v", err)
	}
	second, err := batchToStoredBatch(mustBuildBatch(t, "app-tree-001", []string{
		"0x0000000000000000000000000000000000000000000000000000000000000002",
	}))
	if err != nil {
		t.Fatalf("batchToStoredBatch returned error: %v", err)
	}

	if err := store.SaveBatch(ctx, *first); err != nil {
		t.Fatalf("SaveBatch returned error: %v", err)
	}
	if err := store.SaveBatch(ctx, *second); err == nil {
		t.Fatal("expected conflicting batch error")
	}
}

func TestFileStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	store := newTestFileStore(t)

	batch := mustBuildBatch(t, "app-tree-001", []string{
		"0x0000000000000000000000000000000000000000000000000000000000000001",
		"0x0000000000000000000000000000000000000000000000000000000000000002",
	})
	stored, err := batchToStoredBatch(batch)
	if err != nil {
		t.Fatalf("batchToStoredBatch returned error: %v", err)
	}

	if err := store.SaveBatch(ctx, *stored); err != nil {
		t.Fatalf("SaveBatch returned error: %v", err)
	}
	if err := store.MarkAnchored(ctx, batch.IssuerDID, batch.ExternalTreeID, "0xtx"); err != nil {
		t.Fatalf("MarkAnchored returned error: %v", err)
	}

	loaded, err := store.GetBatch(ctx, batch.IssuerDID, batch.ExternalTreeID)
	if err != nil {
		t.Fatalf("GetBatch returned error: %v", err)
	}
	if loaded.Root != batch.Root {
		t.Fatalf("loaded root mismatch: got %s want %s", loaded.Root, batch.Root)
	}
	if loaded.TxHash != "0xtx" {
		t.Fatalf("loaded tx hash mismatch: got %s", loaded.TxHash)
	}
}

func mustBuildBatch(t *testing.T, externalTreeID string, hashes []string) *Batch {
	t.Helper()

	batch, err := BuildBatch(BatchInput{
		IssuerDID:      "did:pila:testnet:0xissuer",
		ExternalTreeID: externalTreeID,
		VCHashes:       hashes,
	})
	if err != nil {
		t.Fatalf("BuildBatch returned error: %v", err)
	}

	return batch
}

func newTestFileStore(t *testing.T) *FileStore {
	t.Helper()

	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore returned error: %v", err)
	}

	return store
}
