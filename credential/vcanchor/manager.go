package vcanchor

import (
	"context"
	"fmt"
)

type Manager struct {
	store Store
}

// NewManager wires a Manager to the application's Store. Anchoring itself is not the
// SDK's job: this package builds trees, keeps them, and proves membership, while the
// call that hands a root to Authen Service belongs to the application.
func NewManager(store Store) *Manager {
	return &Manager{store: store}
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

// getBatch reads a batch through the application's Store. Store is an extension point
// the SDK does not control, so a (nil, nil) return — a miss reported as success — has
// to become an error here rather than a nil dereference deeper in.
func (m *Manager) getBatch(ctx context.Context, issuerDID, externalTreeID string) (*StoredBatch, error) {
	stored, err := m.store.GetBatch(ctx, issuerDID, externalTreeID)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, fmt.Errorf("vcanchor: store returned no batch for %s/%s: %w", issuerDID, externalTreeID, ErrBatchNotFound)
	}

	return stored, nil
}

// MarkAnchored records the transaction that anchored this batch's root, which is what
// unlocks GenerateReceipt. Call it with the tx hash Authen Service reports once the
// root is on chain — not with a hash from a broadcast whose confirmation failed, or
// the receipts will point at a transaction that anchored nothing.
func (m *Manager) MarkAnchored(ctx context.Context, issuerDID, externalTreeID, txHash string) error {
	if m.store == nil {
		return fmt.Errorf("store is required")
	}
	if txHash == "" {
		return fmt.Errorf("tx hash is required")
	}

	// Read first: marking a batch the Store does not have would create a placement for
	// leaves nobody can produce.
	stored, err := m.getBatch(ctx, issuerDID, externalTreeID)
	if err != nil {
		return err
	}

	return m.store.MarkAnchored(ctx, stored.IssuerDID, stored.ExternalTreeID, txHash)
}

func (m *Manager) GenerateReceipt(ctx context.Context, issuerDID, externalTreeID, vcHash string) (*Receipt, error) {
	if m.store == nil {
		return nil, fmt.Errorf("store is required")
	}

	stored, err := m.getBatch(ctx, issuerDID, externalTreeID)
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

	stored, err := m.getBatch(ctx, issuerDID, externalTreeID)
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
