package vcanchor

import (
	"context"
	"fmt"
	"testing"
	"time"
)

type fakeSubmitter struct {
	txHash    string
	status    string
	issuerDID string
	req       SubmitRootRequest
}

func (f *fakeSubmitter) SubmitRoot(ctx context.Context, req SubmitRootRequest) (*SubmitRootResponse, error) {
	f.req = req

	status := f.status
	if status == "" {
		status = StatusAnchored
	}

	issuerDID := f.issuerDID
	if issuerDID == "" {
		issuerDID = req.IssuerDID
	}

	return &SubmitRootResponse{
		IssuerDID:      issuerDID,
		ExternalTreeID: req.ExternalTreeID,
		Root:           req.Root,
		TxHash:         f.txHash,
		Status:         status,
	}, nil
}

func TestManagerPersistsBatchAndGeneratesReceiptFromStore(t *testing.T) {
	ctx := context.Background()
	store := newTestStore()
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

	verified, err := VerifyReceiptLocal(*receipt, len(hashes))
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

func cloneTestStoredBatch(batch StoredBatch) StoredBatch {
	batch.OrderedVCHashes = append([]string(nil), batch.OrderedVCHashes...)
	return batch
}

// The service records the hash it broadcast even for an attempt that never confirmed,
// so an "anchoring" response can carry a stale tx hash. Marking the batch anchored on
// the hash alone would let GenerateReceipt issue a receipt for a tx that anchored
// nothing, which the verifier would then reject.
func TestSubmitRootDoesNotMarkAnchoredWhenStatusIsNotAnchored(t *testing.T) {
	hashes := []string{
		"0x0000000000000000000000000000000000000000000000000000000000000001",
		"0x0000000000000000000000000000000000000000000000000000000000000002",
	}

	for _, status := range []string{StatusPending, StatusAnchoring, StatusFailed} {
		t.Run(status, func(t *testing.T) {
			ctx := context.Background()
			store := newTestStore()
			manager := NewManager(store, &fakeSubmitter{txHash: "0xstaletx", status: status})

			batch, err := manager.CreateBatch(ctx, BatchInput{
				IssuerDID:      "did:pila:testnet:0xissuer",
				ExternalTreeID: "app-tree-" + status,
				VCHashes:       hashes,
			})
			if err != nil {
				t.Fatalf("CreateBatch returned error: %v", err)
			}

			if _, err := manager.SubmitRoot(ctx, batch.IssuerDID, batch.ExternalTreeID); err != nil {
				t.Fatalf("SubmitRoot returned error: %v", err)
			}

			stored, err := store.GetBatch(ctx, batch.IssuerDID, batch.ExternalTreeID)
			if err != nil {
				t.Fatalf("GetBatch returned error: %v", err)
			}
			if stored.TxHash != "" {
				t.Fatalf("status %q must not anchor the batch, got tx hash %q", status, stored.TxHash)
			}

			// And no receipt may be issued off the back of it.
			if _, err := manager.GenerateReceipt(ctx, batch.IssuerDID, batch.ExternalTreeID, hashes[0]); err == nil {
				t.Fatalf("status %q: GenerateReceipt must fail while the batch is not anchored", status)
			}
		})
	}
}

// The happy path must still anchor.
func TestSubmitRootMarksAnchoredWhenStatusIsAnchored(t *testing.T) {
	ctx := context.Background()
	store := newTestStore()
	manager := NewManager(store, &fakeSubmitter{txHash: "0xtx", status: StatusAnchored})

	batch, err := manager.CreateBatch(ctx, BatchInput{
		IssuerDID:      "did:pila:testnet:0xissuer",
		ExternalTreeID: "app-tree-anchored",
		VCHashes: []string{
			"0x0000000000000000000000000000000000000000000000000000000000000001",
			"0x0000000000000000000000000000000000000000000000000000000000000002",
		},
	})
	if err != nil {
		t.Fatalf("CreateBatch returned error: %v", err)
	}

	if _, err := manager.SubmitRoot(ctx, batch.IssuerDID, batch.ExternalTreeID); err != nil {
		t.Fatalf("SubmitRoot returned error: %v", err)
	}

	stored, err := store.GetBatch(ctx, batch.IssuerDID, batch.ExternalTreeID)
	if err != nil {
		t.Fatalf("GetBatch returned error: %v", err)
	}
	if stored.TxHash != "0xtx" {
		t.Fatalf("anchored batch should carry the tx hash, got %q", stored.TxHash)
	}
}

// SubmitRoot must validate and submit the same snapshot. Two reads would leave a
// window for a concurrent writer to swap the content after the check passed.
func TestSubmitRootReadsTheBatchOnce(t *testing.T) {
	ctx := context.Background()
	store := newTestStore()
	manager := NewManager(store, &fakeSubmitter{txHash: "0xtx"})

	batch, err := manager.CreateBatch(ctx, BatchInput{
		IssuerDID:      "did:pila:testnet:0xissuer",
		ExternalTreeID: "app-tree-once",
		VCHashes: []string{
			"0x0000000000000000000000000000000000000000000000000000000000000001",
			"0x0000000000000000000000000000000000000000000000000000000000000002",
		},
	})
	if err != nil {
		t.Fatalf("CreateBatch returned error: %v", err)
	}

	store.getCalls = 0
	if _, err := manager.SubmitRoot(ctx, batch.IssuerDID, batch.ExternalTreeID); err != nil {
		t.Fatalf("SubmitRoot returned error: %v", err)
	}
	if store.getCalls != 1 {
		t.Fatalf("SubmitRoot read the batch %d times, want 1", store.getCalls)
	}
}

// The service anchors under the DID it authenticated, ignoring our header. A row
// written under a different DID makes every later verify miss it, so the mismatch has
// to surface at submit time rather than as an unexplained verified: false.
func TestSubmitRootRejectsDifferentIssuerDIDInResponse(t *testing.T) {
	ctx := context.Background()
	store := newTestStore()
	submitter := &fakeSubmitter{txHash: "0xtx", issuerDID: "did:pila:testnet:0xsomeoneelse"}
	manager := NewManager(store, submitter)

	batch, err := manager.CreateBatch(ctx, BatchInput{
		IssuerDID:      "did:pila:testnet:0xissuer",
		ExternalTreeID: "app-tree-did",
		VCHashes: []string{
			"0x0000000000000000000000000000000000000000000000000000000000000001",
			"0x0000000000000000000000000000000000000000000000000000000000000002",
		},
	})
	if err != nil {
		t.Fatalf("CreateBatch returned error: %v", err)
	}

	if _, err := manager.SubmitRoot(ctx, batch.IssuerDID, batch.ExternalTreeID); err == nil {
		t.Fatal("a root anchored under a different issuer DID must be rejected")
	}

	stored, err := store.GetBatch(ctx, batch.IssuerDID, batch.ExternalTreeID)
	if err != nil {
		t.Fatalf("GetBatch returned error: %v", err)
	}
	if stored.TxHash != "" {
		t.Fatalf("the batch must not be marked anchored, got tx hash %q", stored.TxHash)
	}
}
