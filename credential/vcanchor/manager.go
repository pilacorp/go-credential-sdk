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
	if err := m.ValidateStoredBatch(ctx, issuerDID, externalTreeID); err != nil {
		return nil, err
	}

	stored, err := m.store.GetBatch(ctx, issuerDID, externalTreeID)
	if err != nil {
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
	if resp != nil && resp.TxHash != "" {
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

	// ponytail: proof generation rebuilds the batch from ordered hashes; for
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

	batch, err := BuildBatch(BatchInput{
		IssuerDID:      stored.IssuerDID,
		ExternalTreeID: stored.ExternalTreeID,
		VCHashes:       stored.OrderedVCHashes,
	})
	if err != nil {
		return err
	}

	return ensureBatchMatchesStored(batch, *stored)
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
