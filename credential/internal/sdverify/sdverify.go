// Package sdverify bridges jsonmap and ecdsasd for cached ecdsa-sd-2023
// verification. jsonmap canonicalizes a document body once per VerifyProof
// call and hands the result to every sd proof through here, without adding to
// ecdsasd's exported API.
package sdverify

import (
	"crypto/ecdsa"
	"fmt"
)

// VerifyFunc verifies an ecdsa-sd-2023 proof. canon returns the canonical
// N-Quads of the document body; the function calls it only once the proof
// value has passed its header and parse checks. Set by ecdsasd's init.
type VerifyFunc func(canon func() ([]string, error), proofConfig map[string]interface{}, proofValue string, pub *ecdsa.PublicKey) error

var verifyFn VerifyFunc

// Register sets the ecdsa-sd-2023 proof check: header refusals, derived proof
// parse and verification. Called once by ecdsasd's package init.
func Register(fn VerifyFunc) { verifyFn = fn }

// VerifyProof verifies an ecdsa-sd-2023 proof through the check ecdsasd
// registered. canon is called at most once per proof; the caller decides
// whether it caches.
func VerifyProof(canon func() ([]string, error), proofConfig map[string]interface{}, proofValue string, pub *ecdsa.PublicKey) error {
	if verifyFn == nil {
		return fmt.Errorf("sdverify: ecdsasd verifier not registered")
	}
	return verifyFn(canon, proofConfig, proofValue, pub)
}
