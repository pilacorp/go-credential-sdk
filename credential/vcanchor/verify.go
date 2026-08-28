package vcanchor

import "fmt"

// VerifyReceiptLocal checks that receipt's vc_hash and proof fold to the anchored
// root, and that the proof is the right length for a leaf.
//
// anchoredRoot and anchoredLeafCount must both come from the anchored root record —
// on chain, or from Authen Service — never from the receipt. The receipt is the thing
// under test. Folding to receipt.Root alone proves nothing: a forger builds their own
// tree over their own leaves and every receipt cut from it is internally consistent.
// The root is what ties the proof to something the issuer committed on chain. The leaf
// count matters for the same reason — measured against receipt.LeafCount, a sender
// could declare a smaller count to match a short proof lifted from higher up the tree.
func VerifyReceiptLocal(receipt Receipt, anchoredRoot string, anchoredLeafCount int) (bool, error) {
	if receipt.HashScheme != HashSchemeKeccak256SortedPairsNoLeafHashV1 {
		return false, fmt.Errorf("unsupported hash_scheme %q", receipt.HashScheme)
	}

	_, leaf, err := normalizeHash32(receipt.VCHash)
	if err != nil {
		return false, err
	}
	normalizedReceiptRoot, _, err := normalizeHash32(receipt.Root)
	if err != nil {
		return false, err
	}
	normalizedAnchoredRoot, root, err := normalizeHash32(anchoredRoot)
	if err != nil {
		return false, fmt.Errorf("invalid anchored root: %w", err)
	}
	// Fold against the anchored root, and reject a receipt that claims a different one
	// rather than quietly verifying it against the value the caller supplied.
	if normalizedReceiptRoot != normalizedAnchoredRoot {
		return false, nil
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
