package vcanchor

import (
	"context"
	"fmt"
)

// RootService is the service side of anchoring. SubmitRoot creates, GetRoot only
// reads — kept apart so an application can run a submitting worker and a polling
// worker with different credentials, and so polling can never anchor by accident.
type RootService interface {
	SubmitRoot(ctx context.Context, req SubmitRootRequest) (*SubmitRootResponse, error)
	GetRoot(ctx context.Context, issuerDID, root string, leafCount int) (*SubmitRootResponse, error)
}

type Manager struct {
	store     Store
	submitter RootService
}

func NewManager(store Store, submitter RootService) *Manager {
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

// SubmitRoot submits the stored batch's root and, once the service reports it
// anchored, marks the batch anchored in the Store. Anchoring is asynchronous: the
// first call returns StatusPending with no tx hash and marks nothing. Poll with
// RootStatus until it reports StatusAnchored, which is also when GenerateReceipt
// starts working — resubmitting works too, but it needs write permission and would
// create the row if it were somehow missing.
func (m *Manager) SubmitRoot(ctx context.Context, issuerDID, externalTreeID string) (*SubmitRootResponse, error) {
	if m.store == nil {
		return nil, fmt.Errorf("store is required")
	}
	if m.submitter == nil {
		return nil, fmt.Errorf("root service is required")
	}

	stored, err := m.getBatch(ctx, issuerDID, externalTreeID)
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
		IssuerDID: stored.IssuerDID,
		Root:      stored.Root,
		LeafCount: stored.LeafCount,
	})
	if err != nil {
		return nil, err
	}

	if err := m.markAnchoredIfOnChain(ctx, stored, resp); err != nil {
		return nil, err
	}

	return resp, nil
}

// RootStatus reads the batch's anchoring state without submitting it, and marks the
// batch anchored once the service reports it on chain. This is what a polling worker
// should call: SubmitRoot would create the row if it were missing, so a worker meant
// only to watch would end up anchoring.
func (m *Manager) RootStatus(ctx context.Context, issuerDID, externalTreeID string) (*SubmitRootResponse, error) {
	if m.store == nil {
		return nil, fmt.Errorf("store is required")
	}
	if m.submitter == nil {
		return nil, fmt.Errorf("root service is required")
	}

	stored, err := m.getBatch(ctx, issuerDID, externalTreeID)
	if err != nil {
		return nil, err
	}

	resp, err := m.submitter.GetRoot(ctx, stored.IssuerDID, stored.Root, stored.LeafCount)
	if err != nil {
		return nil, err
	}

	return resp, m.markAnchoredIfOnChain(ctx, stored, resp)
}

// markAnchoredIfOnChain records the tx hash in the Store once, and only once the
// service says the root is on chain. Anchoring is asynchronous, so a pending response
// carries no tx hash; and a hash alone is not proof, since an older service records
// the hash it broadcast even when confirmation failed. Marking on that would let
// GenerateReceipt hand out a receipt pointing at a tx that anchored nothing.
func (m *Manager) markAnchoredIfOnChain(ctx context.Context, stored *StoredBatch, resp *SubmitRootResponse) error {
	if resp == nil {
		return fmt.Errorf("vcanchor: root service returned no response")
	}
	// The service ignores our x-issuer-did header and answers under the DID it
	// authenticated. When the two differ it holds the row under its own DID while we
	// would build receipts under ours, and every later verify would miss the row and
	// return verified: false with nothing to explain why.
	if resp.IssuerDID != "" && resp.IssuerDID != stored.IssuerDID {
		return fmt.Errorf("vcanchor: service anchored under %s, not %s", resp.IssuerDID, stored.IssuerDID)
	}
	if resp.Status != StatusAnchored || resp.TxHash == "" {
		return nil
	}

	return m.store.MarkAnchored(ctx, stored.IssuerDID, stored.ExternalTreeID, resp.TxHash)
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
