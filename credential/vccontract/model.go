// Package vccontract provides a lightweight, read-only client for verifying that a
// Verifiable Credential (VC) hash is anchored on-chain in the Credential Registry
// smart contract.
//
// The Credential Registry stores, per issuer and per tree index, the Merkle root
// of a tree whose leaves are VC hashes. A holder (or any third party) can prove
// that a specific VC hash is included in a given tree by supplying a Merkle proof.
//
// This package does NOT issue credentials, build trees, or submit transactions.
// It only performs read-only (eth_call) verification against the chain, so it
// never needs a private key and never spends gas. The caller is expected to
// already have the proof components (issuer address, tree index, leaf, and
// sibling proof) — typically obtained from the authen-service proof API.
//
// Verification is done via VerifyVCHashOnChain, which calls the contract's
// verifyVC(...) view function: the contract folds the Merkle proof up to the
// stored root and returns the verdict.
package vccontract

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// hash32HexLen is the hex length of a 32-byte value without the "0x" prefix.
const hash32HexLen = 64

// VerifyRequest holds the Merkle proof components needed to verify that a VC hash
// (the leaf) is included in an issuer's on-chain tree.
type VerifyRequest struct {
	// IssuerAddress is the issuer's Ethereum address (0x...). It identifies which
	// issuer's tree the leaf is expected to belong to.
	IssuerAddress string
	// TreeIndex is the index of the issuer's tree that anchors this leaf.
	TreeIndex uint64
	// Leaf is the VC hash to verify, as a 32-byte hex string (with or without "0x").
	Leaf string
	// Proof is the ordered list of sibling hashes (each a 32-byte hex string) that,
	// folded with the leaf, reconstruct the tree root. It is empty for a
	// single-leaf tree (in which case the root equals the leaf).
	Proof []string
}

// Validate checks that the request is well-formed before hitting the chain.
func (r *VerifyRequest) Validate() error {
	if r == nil {
		return errors.New("verify request is required")
	}

	if !common.IsHexAddress(r.IssuerAddress) {
		return fmt.Errorf("invalid issuer address: %q", r.IssuerAddress)
	}

	if err := validateHash32(r.Leaf); err != nil {
		return fmt.Errorf("invalid leaf: %w", err)
	}

	for i, p := range r.Proof {
		if err := validateHash32(p); err != nil {
			return fmt.Errorf("invalid proof element at index %d: %w", i, err)
		}
	}

	return nil
}

// validateHash32 verifies that s is a 32-byte value encoded as hex, with an
// optional "0x" prefix.
func validateHash32(s string) error {
	trimmed := strings.TrimPrefix(s, "0x")
	if len(trimmed) != hash32HexLen {
		return fmt.Errorf("expected %d hex chars (32 bytes), got %d", hash32HexLen, len(trimmed))
	}

	return nil
}
