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
