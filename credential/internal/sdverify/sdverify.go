// Package sdverify bridges jsonmap and ecdsasd for cached ecdsa-sd-2023
// verification. It lets jsonmap cache the URDNA2015 canonical form of a
// document body and reuse it across multiple sd proof verifications in
// a single VerifyProof call, without adding to ecdsasd's exported API.
package sdverify

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
)

// VerifyFunc verifies an ecdsa-sd-2023 proof against pre-computed canonical
// N-Quads of the document body. Set by ecdsasd's init; the function handles
// both header checks (base proof rejection) and per-proof verification.
type VerifyFunc func(canonicalNQuads []string, proofConfig map[string]interface{}, proofValue string, pub *ecdsa.PublicKey) error

var verifyFn VerifyFunc

// Register sets the derived-proof verification function. Called once by
// ecdsasd's package init.
func Register(fn VerifyFunc) { verifyFn = fn }

// DocVerifier caches the URDNA2015 canonical N-Quads of a document body for
// reuse across multiple ecdsa-sd-2023 proof verifications. The first call to
// VerifyProof canonicalizes the document; subsequent calls reuse the result.
type DocVerifier struct {
	document map[string]interface{}
	nquads   []string
	err      error
	done     bool
	misses   *int // when non-nil, incremented on the first canonicalization
}

// NewDocVerifier returns a DocVerifier that will lazily canonicalize document.
// When misses is non-nil, it is incremented once when the canonical form is
// first computed.
func NewDocVerifier(document map[string]interface{}, misses *int) *DocVerifier {
	return &DocVerifier{document: document, misses: misses}
}

// VerifyProof verifies an ecdsa-sd-2023 proof. The first call canonicalizes
// the document; subsequent calls reuse the cached canonical N-Quads.
func (v *DocVerifier) VerifyProof(proofConfig map[string]interface{}, proofValue string, pub *ecdsa.PublicKey) error {
	if verifyFn == nil {
		return fmt.Errorf("sdverify: ecdsasd verifier not registered")
	}
	if !v.done {
		v.nquads, _, v.err = processor.CanonicalizeWithIdMap(v.document)
		v.done = true
		if v.misses != nil && v.err == nil {
			*v.misses++
		}
	}
	if v.err != nil {
		return fmt.Errorf("ecdsasd: canonicalize reveal doc: %w", v.err)
	}
	return verifyFn(v.nquads, proofConfig, proofValue, pub)
}
