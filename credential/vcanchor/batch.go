package vcanchor

import (
	"fmt"
)

func BuildBatch(input BatchInput) (*Batch, error) {
	if input.IssuerDID == "" {
		return nil, fmt.Errorf("issuer_did is required")
	}
	if input.ExternalTreeID == "" {
		return nil, fmt.Errorf("external_tree_id is required")
	}
	if len(input.VCHashes) == 0 {
		return nil, fmt.Errorf("vc_hashes is required")
	}

	leaves := make([][]byte, 0, len(input.VCHashes))
	leavesByHash := make(map[string]int, len(input.VCHashes))

	for _, hash := range input.VCHashes {
		normalized, raw, err := normalizeHash32(hash)
		if err != nil {
			return nil, err
		}
		if _, exists := leavesByHash[normalized]; exists {
			return nil, fmt.Errorf("duplicate vc_hash %s", normalized)
		}

		leavesByHash[normalized] = len(leaves)
		leaves = append(leaves, raw)
	}

	root, err := merkleRoot(leaves)
	if err != nil {
		return nil, err
	}
	leavesDigest := digestLeaves(leaves)

	return &Batch{
		IssuerDID:      input.IssuerDID,
		ExternalTreeID: input.ExternalTreeID,
		Root:           hexHash(root),
		LeafCount:      len(leaves),
		HashScheme:     HashSchemeKeccak256SortedPairsNoLeafHashV1,
		LeavesDigest:   hexHash(leavesDigest),
		leavesByHash:   leavesByHash,
		leaves:         leaves,
	}, nil
}

func (b *Batch) RootRequest() SubmitRootRequest {
	return SubmitRootRequest{
		IssuerDID:      b.IssuerDID,
		ExternalTreeID: b.ExternalTreeID,
		Root:           b.Root,
		LeafCount:      b.LeafCount,
		HashScheme:     b.HashScheme,
		LeavesDigest:   b.LeavesDigest,
	}
}

func (b *Batch) Manifest() Manifest {
	return Manifest{
		IssuerDID:      b.IssuerDID,
		ExternalTreeID: b.ExternalTreeID,
		Root:           b.Root,
		LeafCount:      b.LeafCount,
		HashScheme:     b.HashScheme,
		LeavesDigest:   b.LeavesDigest,
	}
}

func (b *Batch) Receipt(vcHash, txHash string) (*Receipt, error) {
	normalized, _, err := normalizeHash32(vcHash)
	if err != nil {
		return nil, err
	}

	leafIndex, ok := b.leavesByHash[normalized]
	if !ok {
		return nil, fmt.Errorf("vc_hash %s is not in batch", normalized)
	}

	proof, err := merkleProof(b.leaves, leafIndex)
	if err != nil {
		return nil, err
	}

	proofHex := make([]string, len(proof))
	for i, sibling := range proof {
		proofHex[i] = hexHash(sibling)
	}

	return &Receipt{
		IssuerDID:      b.IssuerDID,
		ExternalTreeID: b.ExternalTreeID,
		VCHash:         normalized,
		LeafIndex:      leafIndex,
		Root:           b.Root,
		Proof:          proofHex,
		TxHash:         txHash,
		HashScheme:     b.HashScheme,
	}, nil
}

func batchToStoredBatch(batch *Batch) (*StoredBatch, error) {
	if batch == nil {
		return nil, fmt.Errorf("batch is nil")
	}

	hashes := make([]string, len(batch.leaves))
	for i, leaf := range batch.leaves {
		hashes[i] = hexHash(leaf)
	}

	return &StoredBatch{
		IssuerDID:       batch.IssuerDID,
		ExternalTreeID:  batch.ExternalTreeID,
		Root:            batch.Root,
		LeafCount:       batch.LeafCount,
		HashScheme:      batch.HashScheme,
		LeavesDigest:    batch.LeavesDigest,
		OrderedVCHashes: hashes,
		Status:          "created",
	}, nil
}
