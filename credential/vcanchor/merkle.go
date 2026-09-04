package vcanchor

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"math/bits"

	"github.com/ethereum/go-ethereum/crypto"
)

func merkleRoot(leaves [][]byte) ([]byte, error) {
	if len(leaves) == 0 {
		return nil, fmt.Errorf("leaves is empty")
	}
	if len(leaves) == 1 {
		return cloneBytes(leaves[0]), nil
	}

	// The loop only reads level and writes into fresh "next" slices, so it never
	// mutates the caller's leaves. Alias directly instead of cloning.
	level := leaves
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
	// Aliased, not cloned: level is never mutated (see merkleRoot). Siblings that
	// go into proof are copied via cloneBytes below, so proof stays independent.
	level := leaves

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
	// Stream each leaf into the hasher instead of concatenating into one
	// len(leaves)*32 buffer. This is byte-identical to Keccak256 over the
	// concatenation but uses O(1) extra memory.
	h := crypto.NewKeccakState()
	for _, leaf := range leaves {
		h.Write(leaf)
	}

	digest := make([]byte, 32)
	h.Read(digest)

	return digest
}

func cloneBytes(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)

	return out
}

// proofLen returns how many siblings a leaf's proof carries in a tree of leafCount
// leaves. Each level halves the node count (an odd trailing node pairs with itself),
// so the tree height — and therefore every leaf's proof — is ceil(log2(leafCount)).
//
// This is what separates a leaf from an internal node: the scheme feeds leaves in
// unhashed, so the two are indistinguishable to the fold, but an internal node sits
// higher up and its proof is strictly shorter.
func proofLen(leafCount int) int {
	if leafCount <= 1 {
		return 0
	}

	return bits.Len(uint(leafCount - 1))
}
