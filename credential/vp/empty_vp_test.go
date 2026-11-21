package vp_test

import (
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// TC-B05: a VP with an empty verifiableCredential array must pass with
// WithVCValidation. The old code rejected with "credential input is nil".
func TestEmptyVP_WithVCValidation(t *testing.T) {
	const did = "did:example:empty-vp"
	resolver, prov := joseVPFixture(t, did)

	contents := joseVPContents(did)
	// Explicitly no credentials.
	contents.VerifiableCredentials = nil

	p, err := vp.NewJOSEPresentation(contents,
		vp.WithVerificationMethodKey("key-1"),
		vp.WithResolver(resolver),
	)
	if err != nil {
		t.Fatalf("NewJOSEPresentation: %v", err)
	}
	if err := p.AddProofByProvider(prov, vp.WithResolver(resolver)); err != nil {
		t.Fatalf("sign: %v", err)
	}

	serialized, err := p.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	token := serialized.(string)

	_, err = vp.ParsePresentation([]byte(token),
		vp.WithVCValidation(),
		vp.WithVerifyProof(),
		vp.WithResolver(resolver),
	)
	if err != nil {
		t.Fatalf("ParsePresentation(empty VP + WithVCValidation) = %v, want nil", err)
	}
}

// TC-B06: a VP with no verifiableCredential key at all must also pass.
func TestEmptyVP_NoVerifiableCredentialKey(t *testing.T) {
	const did = "did:example:empty-vp2"
	resolver, prov := joseVPFixture(t, did)
	kid := did + "#key-1"

	// Build a VP payload by hand with no verifiableCredential field.
	payload := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiablePresentation"},
		"holder":   did,
	}
	token := signJOSEVP(t, prov, kid, payload)

	_, err := vp.ParsePresentation([]byte(token),
		vp.WithVCValidation(),
		vp.WithVerifyProof(),
		vp.WithResolver(resolver),
	)
	if err != nil {
		t.Fatalf("ParsePresentation(no VC key + WithVCValidation) = %v, want nil", err)
	}
}
