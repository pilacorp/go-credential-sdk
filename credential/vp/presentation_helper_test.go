package vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// parseHolder mirrors vc.parseIssuer: both VC Data Model forms yield the id,
// anything else leaves Holder empty.
func TestParseHolder(t *testing.T) {
	tests := []struct {
		name     string
		holder   interface{}
		expected string
	}{
		{"string", "did:example:holder", "did:example:holder"},
		{"object with id", map[string]interface{}{"id": "did:example:holder", "name": "Alice"}, "did:example:holder"},
		{"object without id", map[string]interface{}{"name": "Alice"}, ""},
		{"empty string", "", ""},
		{"missing", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := PresentationData{}
			if tt.holder != nil {
				data["holder"] = tt.holder
			}
			var contents PresentationContents
			if err := parseHolder(data, &contents); err != nil {
				t.Fatalf("parseHolder: %v", err)
			}
			if contents.Holder != tt.expected {
				t.Errorf("Holder = %q, want %q", contents.Holder, tt.expected)
			}
		})
	}
}

// vpWithSignedVC returns a presentation embedding one P-256-signed credential
// that has no credentialSchema, plus a resolver for both issuer and holder.
// mutateVC lets a test tamper with the credential after signing.
func vpWithSignedVC(t *testing.T, mutateVC func(map[string]interface{})) (Presentation, *vmpkg.StaticResolver) {
	t.Helper()
	const issuer = "did:example:vcval-issuer"
	const holder = "did:example:vcval-holder"

	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holderKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerProv, _ := signer.NewP256Provider(issuerKey)
	holderProv, _ := signer.NewP256Provider(holderKey)
	resolver := vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(issuer, mustP256VM(t, issuer, "key-1", &issuerKey.PublicKey)),
		vmpkg.NewDIDDocument(holder, mustP256VM(t, holder, "key-1", &holderKey.PublicKey)),
	)

	cred, err := vc.ParseJSONCredential([]byte(`{
		"@context": ["https://www.w3.org/ns/credentials/v2"],
		"id": "urn:uuid:vcval-001",
		"type": ["VerifiableCredential"],
		"issuer": "` + issuer + `",
		"credentialSubject": {"id": "did:example:subject"}
	}`))
	if err != nil {
		t.Fatalf("parse vc: %v", err)
	}
	if err := cred.AddProofByProvider(issuerProv, vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign vc: %v", err)
	}
	serialized, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize vc: %v", err)
	}
	vcMap, ok := serialized.(map[string]interface{})
	if !ok {
		t.Fatalf("serialized vc is %T, want map", serialized)
	}
	if mutateVC != nil {
		mutateVC(vcMap)
	}

	vpDoc, _ := json.Marshal(map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               holder,
		"verifiableCredential": []interface{}{vcMap},
	})
	pres, err := ParseJSONPresentation(vpDoc)
	if err != nil {
		t.Fatalf("parse vp: %v", err)
	}
	if err := pres.AddProofByProvider(holderProv, WithResolver(resolver)); err != nil {
		t.Fatalf("sign vp: %v", err)
	}
	return pres, resolver
}

// credentialSchema is optional in the VC Data Model, so WithVCValidation on
// its own must accept a schema-less credential with a valid proof.
func TestWithVCValidation_ProofOnlyByDefault(t *testing.T) {
	pres, resolver := vpWithSignedVC(t, nil)
	if err := pres.Verify(WithResolver(resolver), WithVCValidation()); err != nil {
		t.Fatalf("expected proof-only VC validation to pass, got: %v", err)
	}
}

// Forwarded vc options reach the embedded credential: asking for schema
// validation reinstates the credentialSchema requirement.
func TestWithVCValidation_ForwardsVCOptions(t *testing.T) {
	pres, resolver := vpWithSignedVC(t, nil)
	err := pres.Verify(WithResolver(resolver), WithVCValidation(vc.WithSchemaValidation()))
	if err == nil {
		t.Fatal("expected schema validation to reject a credential without credentialSchema")
	}
	if !strings.Contains(err.Error(), "credentialSchema is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Dropping the schema requirement must not drop proof verification.
func TestWithVCValidation_TamperedVCRejected(t *testing.T) {
	pres, resolver := vpWithSignedVC(t, func(vcMap map[string]interface{}) {
		vcMap["credentialSubject"].(map[string]interface{})["id"] = "did:example:someone-else"
	})
	if err := pres.Verify(WithResolver(resolver), WithVCValidation()); err == nil {
		t.Fatal("expected a tampered credential to fail VC validation")
	}
}

// Without WithVCValidation embedded credentials are not inspected at all:
// only the presentation proof is checked.
func TestWithoutVCValidation_VCsNotChecked(t *testing.T) {
	pres, resolver := vpWithSignedVC(t, func(vcMap map[string]interface{}) {
		vcMap["credentialSubject"].(map[string]interface{})["id"] = "did:example:someone-else"
	})
	if err := pres.Verify(WithResolver(resolver)); err != nil {
		t.Fatalf("VC should not have been checked without WithVCValidation: %v", err)
	}
}

// aud may be a single string or an array of strings (RFC 7519 §4.1.3).
func TestAudContains(t *testing.T) {
	cases := []struct {
		name string
		aud  interface{}
		want bool
	}{
		{"string match", "verifier.example", true},
		{"string mismatch", "other.example", false},
		{"array contains", []interface{}{"other.example", "verifier.example"}, true},
		{"array missing", []interface{}{"other.example"}, false},
		{"array non-string entries", []interface{}{1, nil, "verifier.example"}, true},
		{"string slice", []string{"verifier.example"}, true},
		{"nil", nil, false},
		{"wrong type", 42, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := audContains(tc.aud, "verifier.example"); got != tc.want {
				t.Fatalf("audContains(%v) = %v, want %v", tc.aud, got, tc.want)
			}
		})
	}
}

// mustP256VM builds a P-256 JsonWebKey2020 VM or fails the test.
func mustP256VM(t *testing.T, did, fragment string, pub *ecdsa.PublicKey) vmpkg.VerificationMethodEntry {
	t.Helper()
	entry, err := vmpkg.NewP256VM(did, fragment, pub)
	if err != nil {
		t.Fatalf("NewP256VM(%s, %s): %v", did, fragment, err)
	}
	return entry
}
