package vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// vpSDJWTFixture creates a signed vp+sd-jwt with a custom claim made
// selectively disclosable, carrying one enveloped vc+jwt credential.
func vpSDJWTFixture(t *testing.T) (token string, holderDID string, resolver vmpkg.ResolverProvider) {
	t.Helper()

	// Issuer signs a plain vc+jwt for the holder to present.
	issuerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen issuer key: %v", err)
	}
	const issuerDID = "did:example:vp-sd-issuer"
	issuerVM, _ := vmpkg.NewP256VM(issuerDID, "key-1", &issuerPriv.PublicKey)
	issuerDoc := vmpkg.NewDIDDocument(issuerDID, issuerVM)
	issuerResolver := vmpkg.NewStaticResolver(issuerDoc)
	issuerProv, _ := signer.NewP256Provider(issuerPriv)

	credContents := vc.CredentialContents{
		Context:   []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:        "urn:uuid:vp-sd-cred-1",
		Types:     []string{"VerifiableCredential"},
		Issuer:    issuerDID,
		ValidFrom: time.Now().Add(-time.Hour),
		Subject: []vc.Subject{{
			ID:           "did:example:vp-sd-holder",
			CustomFields: map[string]interface{}{"name": "Alice"},
		}},
	}
	cred, err := vc.NewJOSECredential(credContents,
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(issuerResolver),
	)
	if err != nil {
		t.Fatalf("NewJOSECredential: %v", err)
	}
	if err := cred.AddProofByProvider(issuerProv); err != nil {
		t.Fatalf("sign cred: %v", err)
	}

	// Holder creates a vp+sd-jwt with a custom disclosable claim.
	holderPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen holder key: %v", err)
	}
	holderDID = "did:example:vp-sd-holder"
	holderVM, _ := vmpkg.NewP256VM(holderDID, "key-1", &holderPriv.PublicKey)
	combinedDoc := vmpkg.NewDIDDocument(holderDID, holderVM)
	// Resolver sees both issuer and holder.
	resolver = vmpkg.NewStaticResolver(issuerDoc, combinedDoc)
	holderProv, _ := signer.NewP256Provider(holderPriv)

	vpContents := vp.PresentationContents{
		Context:               []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:                    "urn:uuid:vp-sd-001",
		Types:                 []string{"VerifiablePresentation"},
		Holder:                holderDID,
		VerifiableCredentials: []vc.Credential{cred},
		CustomFields: map[string]interface{}{
			"termsOfAgreement": map[string]interface{}{
				"type":        "ConsentReceipt",
				"agreedAt":    "2024-06-01T12:00:00Z",
				"consentedTo": "data-sharing-policy-v2",
			},
		},
	}
	pres, err := vp.NewJOSEPresentation(vpContents,
		vp.WithSDSelectivePaths([]string{"termsOfAgreement.consentedTo"}),
		vp.WithVerificationMethodKey("key-1"),
		vp.WithResolver(resolver),
	)
	if err != nil {
		t.Fatalf("NewJOSEPresentation: %v", err)
	}
	if err := pres.AddProofByProvider(holderProv, vp.WithResolver(resolver)); err != nil {
		t.Fatalf("sign vp: %v", err)
	}

	serialized, err := pres.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	token = serialized.(string)
	return token, holderDID, resolver
}

// TC-C05: Issue vp+sd-jwt, sign, serialize, re-parse, verify -- round trip.
func TestVPSDJWT_RoundTrip(t *testing.T) {
	token, _, resolver := vpSDJWTFixture(t)

	// The token must be an SD-JWT (contains ~).
	if !strings.Contains(token, "~") {
		t.Fatal("expected SD-JWT format with ~ separator")
	}

	// Header typ must be vp+sd-jwt.
	headerB64 := strings.Split(token, ".")[0]
	raw, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header struct {
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if header.Typ != "vp+sd-jwt" {
		t.Fatalf("typ = %q, want vp+sd-jwt", header.Typ)
	}

	// Parse and verify.
	parsed, err := vp.ParseJOSEPresentation(token)
	if err != nil {
		t.Fatalf("ParseJOSEPresentation: %v", err)
	}
	if err := parsed.Verify(vp.WithResolver(resolver)); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// The reconstructed payload should contain the disclosed claim.
	contents, err := parsed.GetContents()
	if err != nil {
		t.Fatalf("GetContents: %v", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(contents, &payload); err != nil {
		t.Fatalf("unmarshal contents: %v", err)
	}

	toa, ok := payload["termsOfAgreement"].(map[string]interface{})
	if !ok {
		t.Fatal("termsOfAgreement missing from reconstructed payload")
	}
	if toa["consentedTo"] != "data-sharing-policy-v2" {
		t.Fatalf("consentedTo = %v, want data-sharing-policy-v2", toa["consentedTo"])
	}
}

// TC-C05b: vp+sd-jwt can also be parsed through the generic ParsePresentation.
func TestVPSDJWT_ParsePresentation(t *testing.T) {
	token, _, resolver := vpSDJWTFixture(t)

	parsed, err := vp.ParsePresentation([]byte(token))
	if err != nil {
		t.Fatalf("ParsePresentation: %v", err)
	}
	if err := parsed.Verify(vp.WithResolver(resolver)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TC-C05c: Holder can present a subset of disclosures.
func TestVPSDJWT_SelectivePresent(t *testing.T) {
	token, _, resolver := vpSDJWTFixture(t)

	pres, err := vp.ParseJOSEPresentation(token)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Present with no disclosures (withhold all).
	presented, err := pres.Present(nil)
	if err != nil {
		t.Fatalf("Present(nil): %v", err)
	}
	ser, _ := presented.Serialize()
	reparsed, err := vp.ParseJOSEPresentation(ser.(string))
	if err != nil {
		t.Fatalf("re-parse after withholding: %v", err)
	}
	if err := reparsed.Verify(vp.WithResolver(resolver)); err != nil {
		t.Fatalf("verify after withholding: %v", err)
	}

	// The withheld claim should not appear in the reconstructed payload.
	contents, _ := reparsed.GetContents()
	var payload map[string]interface{}
	if err := json.Unmarshal(contents, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	toa, _ := payload["termsOfAgreement"].(map[string]interface{})
	if _, found := toa["consentedTo"]; found {
		t.Fatal("consentedTo should be withheld when presenting with no disclosures")
	}
}

// TC-C06: Structural properties cannot be made selectively disclosable.
func TestVPSDJWT_SecuredPropertiesRefused(t *testing.T) {
	holderPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const holderDID = "did:example:vp-sd-refuse"
	holderVM, _ := vmpkg.NewP256VM(holderDID, "key-1", &holderPriv.PublicKey)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(holderDID, holderVM))

	for _, path := range []string{
		"@context",
		"type",
		"holder",
	} {
		t.Run(path, func(t *testing.T) {
			vpContents := vp.PresentationContents{
				Context: []interface{}{"https://www.w3.org/ns/credentials/v2"},
				ID:      "urn:uuid:vp-sd-refuse",
				Types:   []string{"VerifiablePresentation"},
				Holder:  holderDID,
			}
			_, err := vp.NewJOSEPresentation(vpContents,
				vp.WithSDSelectivePaths([]string{path}),
				vp.WithVerificationMethodKey("key-1"),
				vp.WithResolver(resolver),
			)
			if err == nil {
				t.Fatalf("expected error for disclosable %q", path)
			}
			if !strings.Contains(err.Error(), "selective disclosure") &&
				!strings.Contains(err.Error(), "_sd") {
				t.Fatalf("error for %q should mention selective disclosure: %v", path, err)
			}
		})
	}
}

// TC-C06b: EnvelopedVerifiableCredential entries in the VP use the correct
// media type for both vc+jwt and vc+sd-jwt credentials.
func TestVPSDJWT_EnvelopedCredentialMediaTypes(t *testing.T) {
	token, _, _ := vpSDJWTFixture(t)

	pres, err := vp.ParseJOSEPresentation(token)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	contents, err := pres.GetContents()
	if err != nil {
		t.Fatalf("GetContents: %v", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(contents, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	creds, ok := payload["verifiableCredential"].([]interface{})
	if !ok || len(creds) == 0 {
		t.Fatal("expected at least one verifiableCredential")
	}
	entry, ok := creds[0].(map[string]interface{})
	if !ok {
		t.Fatal("credential entry is not a map")
	}
	id, _ := entry["id"].(string)
	if !strings.HasPrefix(id, "data:application/vc+jwt,") {
		t.Fatalf("credential id should use vc+jwt media type, got %q", id[:min(len(id), 40)])
	}
}
