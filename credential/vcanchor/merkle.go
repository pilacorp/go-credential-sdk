package vcanchor

import (
	"bytes"
	"crypto/subtle"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

func merkleRoot(leaves [][]byte) ([]byte, error) {
	if len(leaves) == 0 {
		return nil, fmt.Errorf("leaves is empty")
	}
	if len(leaves) == 1 {
		return cloneBytes(leaves[0]), nil
	}

	level := cloneLeaves(leaves)
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			right := level[i]
			if i+1 < len(level) {
				right = level[i+1]
			}
			next = append(next, mergeSorted(level[i], right))
		}
		level = next
	}

	return level[0], nil
}

func merkleProof(leaves [][]byte, leafIndex int) ([][]byte, error) {
	if len(leaves) == 0 {
		return nil, fmt.Errorf("leaves is empty")
	}
	if leafIndex < 0 || leafIndex >= len(leaves) {
		return nil, fmt.Errorf("leaf index %d out of range", leafIndex)
	}
	if len(leaves) == 1 {
		return [][]byte{}, nil
	}

	proof := make([][]byte, 0)
	index := leafIndex
	level := cloneLeaves(leaves)

	for len(level) > 1 {
		siblingIndex := index ^ 1
		if siblingIndex >= len(level) {
			siblingIndex = index
		}
		proof = append(proof, cloneBytes(level[siblingIndex]))

		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			right := level[i]
			if i+1 < len(level) {
				right = level[i+1]
			}
			next = append(next, mergeSorted(level[i], right))
		}

		index /= 2
		level = next
	}

	return proof, nil
}

func verifyProof(leaf []byte, proof [][]byte, root []byte) bool {
	current := cloneBytes(leaf)
	for _, sibling := range proof {
		current = mergeSorted(current, sibling)
	}

	return subtle.ConstantTimeCompare(current, root) == 1
}

func mergeSorted(left, right []byte) []byte {
	if bytes.Compare(left, right) < 0 {
		return crypto.Keccak256(left, right)
	}

	return crypto.Keccak256(right, left)
}

func digestLeaves(leaves [][]byte) []byte {
	combined := make([]byte, 0, len(leaves)*32)
	for _, leaf := range leaves {
		combined = append(combined, leaf...)
	}

	return crypto.Keccak256(combined)
}

func cloneLeaves(leaves [][]byte) [][]byte {
	out := make([][]byte, len(leaves))
	for i := range leaves {
		out[i] = cloneBytes(leaves[i])
	}

	return out
}

func cloneBytes(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)

	return out
}
