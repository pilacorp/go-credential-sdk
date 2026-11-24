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

// VerifyFunc verifies an ecdsa-sd-2023 proof. canon returns the canonical
// N-Quads of the document body; the function calls it only once the proof
// value has passed its header and parse checks. Set by ecdsasd's init.
type VerifyFunc func(canon func() ([]string, error), proofConfig map[string]interface{}, proofValue string, pub *ecdsa.PublicKey) error

var verifyFn VerifyFunc

// Register sets the ecdsa-sd-2023 proof check: header refusals, derived proof
// parse and verification. Called once by ecdsasd's package init.
func Register(fn VerifyFunc) { verifyFn = fn }

// DocVerifier caches the URDNA2015 canonical N-Quads of a document body for
// reuse across multiple ecdsa-sd-2023 proof verifications. The document is
// canonicalized the first time a proof gets past its header and parse checks;
// later proofs reuse the result.
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

// VerifyProof verifies an ecdsa-sd-2023 proof. The document is canonicalized
// the first time a proof gets past its header and parse checks; later calls
// reuse that result.
func (v *DocVerifier) VerifyProof(proofConfig map[string]interface{}, proofValue string, pub *ecdsa.PublicKey) error {
	if verifyFn == nil {
		return fmt.Errorf("sdverify: ecdsasd verifier not registered")
	}
	return verifyFn(v.canonical, proofConfig, proofValue, pub)
}

// canonical runs URDNA2015 on the first call and returns the cached result,
// or the cached error, on every later call.
func (v *DocVerifier) canonical() ([]string, error) {
	if !v.done {
		v.nquads, _, v.err = processor.CanonicalizeWithIdMap(v.document)
		v.done = true
		if v.misses != nil && v.err == nil {
			*v.misses++
		}
	}
	return v.nquads, v.err
}
