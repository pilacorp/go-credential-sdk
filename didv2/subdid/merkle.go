package subdid

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// MaxLeaves is the largest number of leaves a Sub-DID tree holds.
const MaxLeaves = 8192

const maxProofLen = 13

const revokedLeafTag = "revoked"

// MerkleRoot returns the root of leaves, kept in input order. An odd last node
// is promoted unchanged; a pair hashes as keccak256(min ‖ max).
func MerkleRoot(leaves [][32]byte) ([32]byte, error) {
	if err := checkLeafCount(len(leaves)); err != nil {
		return [32]byte{}, err
	}

	level := append([][32]byte(nil), leaves...)
	for len(level) > 1 {
		level = nextLevel(level)
	}

	return level[0], nil
}

// MerkleProof returns the siblings of leaves[index], bottom-up. A level where
// the node is promoted adds no sibling.
func MerkleProof(leaves [][32]byte, index int) ([][32]byte, error) {
	if err := checkLeafCount(len(leaves)); err != nil {
		return nil, err
	}
	if index < 0 || index >= len(leaves) {
		return nil, fmt.Errorf("subdid: leaf index %d out of range [0, %d)", index, len(leaves))
	}

	proof := make([][32]byte, 0, maxProofLen)
	level := append([][32]byte(nil), leaves...)
	for len(level) > 1 {
		if sibling := index ^ 1; sibling < len(level) {
			proof = append(proof, level[sibling])
		}
		level = nextLevel(level)
		index /= 2
	}

	return proof, nil
}

// VerifyProof folds path onto leaf and reports whether it reaches root. A path
// longer than 13 siblings is refused.
func VerifyProof(leaf [32]byte, path [][32]byte, root [32]byte) bool {
	if len(path) > maxProofLen {
		return false
	}

	h := leaf
	for _, sibling := range path {
		h = hashPair(h, sibling)
	}

	return h == root
}

// RevokedLeaf returns keccak256("revoked" ‖ addr), the leaf of a revoked Sub-DID.
func RevokedLeaf(addr common.Address) [32]byte {
	return crypto.Keccak256Hash([]byte(revokedLeafTag), addr.Bytes())
}

func checkLeafCount(n int) error {
	if n == 0 {
		return fmt.Errorf("subdid: a tree needs at least one leaf")
	}
	if n > MaxLeaves {
		return fmt.Errorf("subdid: %d leaves exceed the maximum of %d", n, MaxLeaves)
	}

	return nil
}

func nextLevel(level [][32]byte) [][32]byte {
	next := make([][32]byte, 0, (len(level)+1)/2)
	for i := 0; i+1 < len(level); i += 2 {
		next = append(next, hashPair(level[i], level[i+1]))
	}
	if len(level)%2 == 1 {
		next = append(next, level[len(level)-1])
	}

	return next
}

func hashPair(a, b [32]byte) [32]byte {
	if bytes.Compare(a[:], b[:]) > 0 {
		a, b = b, a
	}

	return crypto.Keccak256Hash(a[:], b[:])
}
