package vcanchor

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestManagerPersistsBatchAndGeneratesReceiptFromStore(t *testing.T) {
	ctx := context.Background()
	store := newTestStore()
	manager := NewManager(store)

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

	// The application anchors the root through its own call to Authen Service and
	// reports the transaction back here; the SDK never makes that call itself.
	if err := manager.MarkAnchored(ctx, batch.IssuerDID, batch.ExternalTreeID, "0xtx"); err != nil {
		t.Fatalf("MarkAnchored returned error: %v", err)
	}

	receipt, err := manager.GenerateReceipt(ctx, batch.IssuerDID, batch.ExternalTreeID, hashes[1])
	if err != nil {
		t.Fatalf("GenerateReceipt returned error: %v", err)
	}
	if receipt.TxHash != "0xtx" {
		t.Fatalf("receipt should use anchored tx hash, got %s", receipt.TxHash)
	}

	verified, err := VerifyReceiptLocal(*receipt, batch.Root, len(hashes))
	if err != nil {
		t.Fatalf("VerifyReceiptLocal returned error: %v", err)
	}
	if !verified {
		t.Fatal("receipt generated from store should verify")
	}
}

func TestStoreRejectsSameTreeWithDifferentDigest(t *testing.T) {
	ctx := context.Background()
	store := newTestStore()

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

func TestStoreContractRoundTrip(t *testing.T) {
	ctx := context.Background()
	store := newTestStore()

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

type testStore struct {
	batches  map[string]StoredBatch
	getCalls int
}

func newTestStore() *testStore {
	return &testStore{batches: make(map[string]StoredBatch)}
}

func (s *testStore) SaveBatch(ctx context.Context, batch StoredBatch) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	now := time.Now().Unix()
	if batch.CreatedAtUnix == 0 {
		batch.CreatedAtUnix = now
	}
	batch.LastModifiedUnix = now
	if batch.Status == "" {
		batch.Status = "created"
	}

	key := batch.IssuerDID + "\x00" + batch.ExternalTreeID
	if existing, ok := s.batches[key]; ok {
		if !SameBatchContent(existing, batch) {
			return ErrBatchConflict
		}
		return nil
	}

	s.batches[key] = cloneTestStoredBatch(batch)
	return nil
}

func cloneTestStoredBatch(batch StoredBatch) StoredBatch {
	batch.OrderedVCHashes = append([]string(nil), batch.OrderedVCHashes...)
	return batch
}

func (s *testStore) MarkAnchored(ctx context.Context, issuerDID, externalTreeID, txHash string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if txHash == "" {
		return fmt.Errorf("tx_hash is required")
	}

	key := issuerDID + "\x00" + externalTreeID
	batch, ok := s.batches[key]
	if !ok {
		return ErrBatchNotFound
	}

	now := time.Now().Unix()
	batch.TxHash = txHash
	batch.Status = "anchored"
	batch.AnchoredAtUnix = now
	batch.LastModifiedUnix = now
	s.batches[key] = batch

	return nil
}

func (s *testStore) GetBatch(ctx context.Context, issuerDID, externalTreeID string) (*StoredBatch, error) {
	s.getCalls++
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	batch, ok := s.batches[issuerDID+"\x00"+externalTreeID]
	if !ok {
		return nil, ErrBatchNotFound
	}

	cloned := cloneTestStoredBatch(batch)
	return &cloned, nil
}

// Receipts must not exist before the root is on chain, and MarkAnchored is the only
// thing that opens that door.
func TestGenerateReceiptRequiresMarkAnchored(t *testing.T) {
	ctx := context.Background()
	store := newTestStore()
	manager := NewManager(store)

	hashes := []string{
		"0x0000000000000000000000000000000000000000000000000000000000000001",
		"0x0000000000000000000000000000000000000000000000000000000000000002",
	}

	batch, err := manager.CreateBatch(ctx, BatchInput{
		IssuerDID:      "did:pila:testnet:0xissuer",
		ExternalTreeID: "app-tree-unanchored",
		VCHashes:       hashes,
	})
	if err != nil {
		t.Fatalf("CreateBatch returned error: %v", err)
	}

	if _, err := manager.GenerateReceipt(ctx, batch.IssuerDID, batch.ExternalTreeID, hashes[0]); err == nil {
		t.Fatal("an unanchored batch must not produce a receipt")
	}

	// An empty hash is not an anchoring: taking it would unlock receipts pointing at
	// no transaction at all.
	if err := manager.MarkAnchored(ctx, batch.IssuerDID, batch.ExternalTreeID, ""); err == nil {
		t.Fatal("MarkAnchored must reject an empty tx hash")
	}

	if err := manager.MarkAnchored(ctx, batch.IssuerDID, batch.ExternalTreeID, "0xtx"); err != nil {
		t.Fatalf("MarkAnchored returned error: %v", err)
	}

	receipt, err := manager.GenerateReceipt(ctx, batch.IssuerDID, batch.ExternalTreeID, hashes[0])
	if err != nil {
		t.Fatalf("GenerateReceipt returned error: %v", err)
	}
	if receipt.TxHash != "0xtx" {
		t.Fatalf("receipt tx hash = %q", receipt.TxHash)
	}
}
