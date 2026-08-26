package vcanchor

import (
	"context"
	"errors"
)

var (
	ErrBatchNotFound = errors.New("vcanchor: batch not found")
	ErrBatchConflict = errors.New("vcanchor: batch already exists with different content")
)

type Store interface {
	SaveBatch(ctx context.Context, batch StoredBatch) error
	GetBatch(ctx context.Context, issuerDID, externalTreeID string) (*StoredBatch, error)
	MarkAnchored(ctx context.Context, issuerDID, externalTreeID, txHash string) error
}

func (b StoredBatch) Manifest() Manifest {
	return Manifest{
		IssuerDID:      b.IssuerDID,
		ExternalTreeID: b.ExternalTreeID,
		Root:           b.Root,
		LeafCount:      b.LeafCount,
		HashScheme:     b.HashScheme,
		LeavesDigest:   b.LeavesDigest,
	}
}

// SameBatchContent reports whether two stored batches describe the same tree. A
// Store uses it in SaveBatch to tell a retry of the same batch (return nil) from a
// genuine collision on the same key (return ErrBatchConflict).
func SameBatchContent(a, b StoredBatch) bool {
	return a.IssuerDID == b.IssuerDID &&
		a.ExternalTreeID == b.ExternalTreeID &&
		a.Root == b.Root &&
		a.LeafCount == b.LeafCount &&
		a.HashScheme == b.HashScheme &&
		a.LeavesDigest == b.LeavesDigest
}
