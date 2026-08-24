package vcanchor

import "fmt"

func VerifyReceiptLocal(receipt Receipt) (bool, error) {
	if receipt.HashScheme != HashSchemeKeccak256SortedPairsNoLeafHashV1 {
		return false, fmt.Errorf("unsupported hash_scheme %q", receipt.HashScheme)
	}

	_, leaf, err := normalizeHash32(receipt.VCHash)
	if err != nil {
		return false, err
	}
	_, root, err := normalizeHash32(receipt.Root)
	if err != nil {
		return false, err
	}

	// Without this the offline path is weaker than the server's: an internal node
	// recomputed from any published receipt folds to the same root and would verify
	// as a VC hash. A real leaf always carries exactly ceil(log2(leaf_count))
	// siblings, so the length is what pins the value to the bottom of the tree.
	if receipt.LeafCount <= 0 {
		return false, fmt.Errorf("receipt is missing leaf_count")
	}
	if want := proofLen(receipt.LeafCount); len(receipt.Proof) != want {
		return false, nil
	}

	proof := make([][]byte, len(receipt.Proof))
	for i, sibling := range receipt.Proof {
		_, raw, err := normalizeHash32(sibling)
		if err != nil {
			return false, fmt.Errorf("invalid proof[%d]: %w", i, err)
		}
		proof[i] = raw
	}

	return verifyProof(leaf, proof, root), nil
}
