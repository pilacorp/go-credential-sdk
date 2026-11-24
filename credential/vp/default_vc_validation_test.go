package vp

import (
	"strings"
	"testing"
)

// TC-B08: A VP with a tampered inner VC is rejected by default (no options).
// Before this change, inner VCs were only checked when WithVCValidation was
// passed explicitly.
func TestDefaultVCValidation_TamperedVCRejected(t *testing.T) {
	pres, resolver := vpWithSignedVC(t, func(vcMap map[string]interface{}) {
		vcMap["credentialSubject"].(map[string]interface{})["id"] = "did:example:tampered"
	})
	err := pres.Verify(WithResolver(resolver), WithVerifyProof())
	if err == nil {
		t.Fatal("expected a tampered credential to fail by default")
	}
	if !strings.Contains(err.Error(), "verify credential") {
		t.Errorf("unexpected error: %v (want it to mention verify credential)", err)
	}
}

// TC-B09: WithSkipVCValidation opts out of the default VC verification.
func TestWithSkipVCValidation_TamperedVCPasses(t *testing.T) {
	pres, resolver := vpWithSignedVC(t, func(vcMap map[string]interface{}) {
		vcMap["credentialSubject"].(map[string]interface{})["id"] = "did:example:tampered"
	})
	err := pres.Verify(WithResolver(resolver), WithVerifyProof(), WithSkipVCValidation())
	if err != nil {
		t.Fatalf("Verify with WithSkipVCValidation = %v, want nil", err)
	}
}

// Valid credentials still pass with the new default.
func TestDefaultVCValidation_ValidVCPasses(t *testing.T) {
	pres, resolver := vpWithSignedVC(t, nil)
	if err := pres.Verify(WithResolver(resolver), WithVerifyProof()); err != nil {
		t.Fatalf("expected valid VP to pass with default VC validation: %v", err)
	}
}
