package vcanchor

import (
	"context"
	"fmt"
)

type RootSubmitter interface {
	SubmitRoot(ctx context.Context, req SubmitRootRequest) (*SubmitRootResponse, error)
}

type Manager struct {
	store     Store
	submitter RootSubmitter
}

func NewManager(store Store, submitter RootSubmitter) *Manager {
	return &Manager{store: store, submitter: submitter}
}

func (m *Manager) CreateBatch(ctx context.Context, input BatchInput) (*Batch, error) {
	if m.store == nil {
		return nil, fmt.Errorf("store is required")
	}

	batch, err := BuildBatch(input)
	if err != nil {
		return nil, err
	}

	stored, err := batchToStoredBatch(batch)
	if err != nil {
		return nil, err
	}
	if err := m.store.SaveBatch(ctx, *stored); err != nil {
		return nil, err
	}

	return batch, nil
}

func (m *Manager) SubmitRoot(ctx context.Context, issuerDID, externalTreeID string) (*SubmitRootResponse, error) {
	if m.store == nil {
		return nil, fmt.Errorf("store is required")
	}
	if m.submitter == nil {
		return nil, fmt.Errorf("root submitter is required")
	}

	stored, err := m.store.GetBatch(ctx, issuerDID, externalTreeID)
	if err != nil {
		return nil, err
	}
	// Validate the snapshot we are about to submit. Reading once for the check and
	// again for the payload would let a concurrent writer land different content in
	// between, so the root we send would be one nobody validated.
	if err := validateStoredBatch(*stored); err != nil {
		return nil, err
	}

	resp, err := m.submitter.SubmitRoot(ctx, SubmitRootRequest{
		IssuerDID:      stored.IssuerDID,
		ExternalTreeID: stored.ExternalTreeID,
		Root:           stored.Root,
		LeafCount:      stored.LeafCount,
		HashScheme:     stored.HashScheme,
		LeavesDigest:   stored.LeavesDigest,
	})
	if err != nil {
		return nil, err
	}
	// The service ignores our x-issuer-did header and anchors under the DID it
	// authenticated. When the two differ it writes the row under its own DID while we
	// would build receipts under ours, and every later verify would miss the row and
	// return verified: false with nothing to explain why.
	if resp != nil && resp.IssuerDID != "" && resp.IssuerDID != stored.IssuerDID {
		return nil, fmt.Errorf("vcanchor: service anchored under %s, not %s", resp.IssuerDID, stored.IssuerDID)
	}
	// A tx hash alone does not mean the root is anchored: the service records the hash
	// it broadcast even when confirmation failed, and a later claim can carry that
	// stale hash into an "anchoring" response. Marking on the hash would let
	// GenerateReceipt hand out a receipt pointing at a tx that anchored nothing.
	if resp != nil && resp.Status == StatusAnchored && resp.TxHash != "" {
		if err := m.store.MarkAnchored(ctx, issuerDID, externalTreeID, resp.TxHash); err != nil {
			return nil, err
		}
	}

	return resp, nil
}

func (m *Manager) GenerateReceipt(ctx context.Context, issuerDID, externalTreeID, vcHash string) (*Receipt, error) {
	if m.store == nil {
		return nil, fmt.Errorf("store is required")
	}

	stored, err := m.store.GetBatch(ctx, issuerDID, externalTreeID)
	if err != nil {
		return nil, err
	}
	if stored.TxHash == "" {
		return nil, fmt.Errorf("batch %s is not anchored", externalTreeID)
	}

	// TODO: proof generation rebuilds the batch from ordered hashes; for
	// multi-million-leaf trees, replace this with persisted tree levels.
	batch, err := BuildBatch(BatchInput{
		IssuerDID:      stored.IssuerDID,
		ExternalTreeID: stored.ExternalTreeID,
		VCHashes:       stored.OrderedVCHashes,
	})
	if err != nil {
		return nil, err
	}
	if err := ensureBatchMatchesStored(batch, *stored); err != nil {
		return nil, err
	}

	return batch.Receipt(vcHash, stored.TxHash)
}

func (m *Manager) ValidateStoredBatch(ctx context.Context, issuerDID, externalTreeID string) error {
	if m.store == nil {
		return fmt.Errorf("store is required")
	}

	stored, err := m.store.GetBatch(ctx, issuerDID, externalTreeID)
	if err != nil {
		return err
	}

	return validateStoredBatch(*stored)
}

// validateStoredBatch rebuilds the tree from the stored hash list and checks it still
// produces the four fields the store claims, catching a store that dropped, reordered
// or rewrote leaves.
func validateStoredBatch(stored StoredBatch) error {
	batch, err := BuildBatch(BatchInput{
		IssuerDID:      stored.IssuerDID,
		ExternalTreeID: stored.ExternalTreeID,
		VCHashes:       stored.OrderedVCHashes,
	})
	if err != nil {
		return err
	}

	return ensureBatchMatchesStored(batch, stored)
}

func ensureBatchMatchesStored(batch *Batch, stored StoredBatch) error {
	if batch.Root != stored.Root {
		return fmt.Errorf("stored batch root mismatch: got %s want %s", batch.Root, stored.Root)
	}
	if batch.LeafCount != stored.LeafCount {
		return fmt.Errorf("stored batch leaf_count mismatch: got %d want %d", batch.LeafCount, stored.LeafCount)
	}
	if batch.HashScheme != stored.HashScheme {
		return fmt.Errorf("stored batch hash_scheme mismatch: got %s want %s", batch.HashScheme, stored.HashScheme)
	}
	if batch.LeavesDigest != stored.LeavesDigest {
		return fmt.Errorf("stored batch leaves_digest mismatch: got %s want %s", batch.LeavesDigest, stored.LeavesDigest)
	}

	return nil
}
