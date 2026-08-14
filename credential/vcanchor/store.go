package vcanchor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
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

type FileStore struct {
	dir string
}

func NewFileStore(dir string) (*FileStore, error) {
	if dir == "" {
		return nil, fmt.Errorf("dir is required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	return &FileStore{dir: dir}, nil
}

func (s *FileStore) SaveBatch(ctx context.Context, batch StoredBatch) error {
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

	existing, err := s.GetBatch(ctx, batch.IssuerDID, batch.ExternalTreeID)
	if err == nil {
		if !sameBatchContent(*existing, batch) {
			return ErrBatchConflict
		}
		return nil
	}
	if !errors.Is(err, ErrBatchNotFound) {
		return err
	}

	return s.writeBatch(batch)
}

func (s *FileStore) GetBatch(ctx context.Context, issuerDID, externalTreeID string) (*StoredBatch, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	raw, err := os.ReadFile(s.path(issuerDID, externalTreeID))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrBatchNotFound
	}
	if err != nil {
		return nil, err
	}

	var batch StoredBatch
	if err := json.Unmarshal(raw, &batch); err != nil {
		return nil, err
	}

	return &batch, nil
}

func (s *FileStore) MarkAnchored(ctx context.Context, issuerDID, externalTreeID, txHash string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if txHash == "" {
		return fmt.Errorf("tx_hash is required")
	}

	batch, err := s.GetBatch(ctx, issuerDID, externalTreeID)
	if err != nil {
		return err
	}

	now := time.Now().Unix()
	batch.TxHash = txHash
	batch.Status = "anchored"
	batch.AnchoredAtUnix = now
	batch.LastModifiedUnix = now

	return s.writeBatch(*batch)
}

func (s *FileStore) writeBatch(batch StoredBatch) error {
	raw, err := json.MarshalIndent(batch, "", "  ")
	if err != nil {
		return err
	}

	path := s.path(batch.IssuerDID, batch.ExternalTreeID)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}

	return os.Rename(tmp, path)
}

func (s *FileStore) path(issuerDID, externalTreeID string) string {
	return filepath.Join(s.dir, storeKey(issuerDID, externalTreeID)+".json")
}

func storeKey(issuerDID, externalTreeID string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(issuerDID + "\x00" + externalTreeID))
}

func sameBatchContent(a, b StoredBatch) bool {
	return a.IssuerDID == b.IssuerDID &&
		a.ExternalTreeID == b.ExternalTreeID &&
		a.Root == b.Root &&
		a.LeafCount == b.LeafCount &&
		a.HashScheme == b.HashScheme &&
		a.LeavesDigest == b.LeavesDigest
}

func cloneStoredBatch(batch StoredBatch) StoredBatch {
	batch.OrderedVCHashes = append([]string(nil), batch.OrderedVCHashes...)
	return batch
}
