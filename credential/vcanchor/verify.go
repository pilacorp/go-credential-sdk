package vcanchor

import "fmt"

// VerifyReceiptLocal checks that receipt's vc_hash and proof fold to its root, and
// that the proof is the right length for a leaf.
//
// anchoredLeafCount must come from the anchored root record — on chain, or from Authen
// Service — never from the receipt. The receipt is the thing under test: were the
// length check measured against receipt.LeafCount, a sender could simply declare a
// smaller count to match a short proof lifted from higher up the tree.
func VerifyReceiptLocal(receipt Receipt, anchoredLeafCount int) (bool, error) {
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
	// siblings, so the length pins the value to the bottom of the tree — but only
	// when the count is the anchored one, which is why the receipt's own claim is
	// checked against it rather than trusted.
	if anchoredLeafCount <= 0 {
		return false, fmt.Errorf("anchored leaf_count is required")
	}
	if receipt.LeafCount != anchoredLeafCount {
		return false, nil
	}
	if want := proofLen(anchoredLeafCount); len(receipt.Proof) != want {
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
