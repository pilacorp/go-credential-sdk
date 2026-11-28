package vc

import (
	"errors"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
)

// credentialSubject is a checked key: callers read it after Verify, so a
// subject the compacted form does not reproduce is refused by the check
// itself, whatever the proof would say. The v1 context has no @vocab, so a
// field it does not define is dropped by expansion and never signed (#207
// review).
func TestVerifyCompactedForm_CredentialSubjectIsChecked(t *testing.T) {
	doc := func(subject map[string]interface{}) CredentialData {
		return CredentialData{
			"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":              []interface{}{"VerifiableCredential"},
			"issuer":            "did:example:issuer",
			"issuanceDate":      "2026-01-01T00:00:00Z",
			"credentialSubject": subject,
		}
	}
	if err := (&JSONCredential{credentialData: doc(map[string]interface{}{"id": "did:example:subject"})}).verifyCompactedForm(processor.JSONLDLimits{}); err != nil {
		t.Fatalf("a subject the context defines was refused: %v", err)
	}
	err := (&JSONCredential{credentialData: doc(map[string]interface{}{
		"id": "did:example:subject", "permissions": []interface{}{"admin"},
	})}).verifyCompactedForm(processor.JSONLDLimits{})
	if !errors.Is(err, processor.ErrNotCompactedForm) {
		t.Fatalf("err = %v, want ErrNotCompactedForm for an unsigned subject field", err)
	}
}
