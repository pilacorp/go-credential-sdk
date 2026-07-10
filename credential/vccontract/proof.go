package vccontract

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// hexToBytes32 decodes a hex string (with or without a "0x" prefix) into a
// 32-byte array. It returns an error if the input is not valid hex or is not
// exactly 32 bytes long.
func hexToBytes32(s string) ([32]byte, error) {
	s = strings.TrimPrefix(s, "0x")

	b, err := hex.DecodeString(s)
	if err != nil {
		return [32]byte{}, fmt.Errorf("invalid hex: %w", err)
	}

	if len(b) != 32 {
		return [32]byte{}, fmt.Errorf("length must be 32 bytes, got %d", len(b))
	}

	var out [32]byte
	copy(out[:], b)

	return out, nil
}

// parseProof decodes each hex-encoded sibling into a 32-byte array.
func parseProof(proof []string) ([][32]byte, error) {
	out := make([][32]byte, len(proof))

	for i, p := range proof {
		b, err := hexToBytes32(p)
		if err != nil {
			return nil, fmt.Errorf("proof element %d: %w", i, err)
		}

		out[i] = b
	}

	return out, nil
}

// hashPair hashes two sibling nodes into their parent.
//
// The pair is sorted before hashing so that verification does not depend on the
// left/right position of the sibling — this matches the tree construction used
// by the issuer service (keccak256 over the concatenation of the smaller node
// followed by the larger node). Inputs are not mutated.
func hashPair(a, b [32]byte) [32]byte {
	combined := make([]byte, 0, 64)

	if bytes.Compare(a[:], b[:]) < 0 {
		combined = append(combined, a[:]...)
		combined = append(combined, b[:]...)
	} else {
		combined = append(combined, b[:]...)
		combined = append(combined, a[:]...)
	}

	var out [32]byte
	copy(out[:], crypto.Keccak256(combined))

	return out
}

// computeRoot folds the leaf with each proof sibling in order to reconstruct the
// Merkle root. For a single-leaf tree the proof is empty and the root equals the
// leaf.
func computeRoot(leaf [32]byte, proof [][32]byte) [32]byte {
	computed := leaf
	for _, sibling := range proof {
		computed = hashPair(computed, sibling)
	}

	return computed
}
