package vp_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
	josesdjwt "github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

// vpKBJWTFixture creates a signed vp+sd-jwt with a KB-JWT attached. The
// presentation's payload carries cnf.jwk so the KB-JWT verifier can find the
// holder's key. Returns the full token (SD-JWT+KB) and a resolver.
func vpKBJWTFixture(t *testing.T, audience, nonce string) (token string, resolver vmpkg.ResolverProvider) {
	t.Helper()

	// Issuer key and document
	issuerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen issuer key: %v", err)
	}
	const issuerDID = "did:example:vp-kb-issuer"
	issuerVM, _ := vmpkg.NewP256VM(issuerDID, "key-1", &issuerPriv.PublicKey)
	issuerDoc := vmpkg.NewDIDDocument(issuerDID, issuerVM)
	issuerProv, _ := signer.NewP256Provider(issuerPriv)

	// Holder key and document
	holderPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen holder key: %v", err)
	}
	const holderDID = "did:example:vp-kb-holder"
	holderVM, _ := vmpkg.NewP256VM(holderDID, "key-1", &holderPriv.PublicKey)
	holderDoc := vmpkg.NewDIDDocument(holderDID, holderVM)
	resolver = vmpkg.NewStaticResolver(issuerDoc, holderDoc)
	holderProv, _ := signer.NewP256Provider(holderPriv)

	// Issue a plain vc+jwt for the holder.
	credContents := vc.CredentialContents{
		Context:   []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:        "urn:uuid:vp-kb-cred-1",
		Types:     []string{"VerifiableCredential"},
		Issuer:    issuerDID,
		ValidFrom: time.Now().Add(-time.Hour),
		Subject: []vc.Subject{{
			ID:           holderDID,
			CustomFields: map[string]interface{}{"name": "Alice"},
		}},
	}
	cred, err := vc.NewJOSECredential(credContents,
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(resolver),
	)
	if err != nil {
		t.Fatalf("NewJOSECredential: %v", err)
	}
	if err := cred.AddProofByProvider(issuerProv); err != nil {
		t.Fatalf("sign cred: %v", err)
	}

	// Build a vp+sd-jwt with a custom disclosable claim and cnf.jwk for KB-JWT.
	// The disclosable field must be nested inside a custom object — the VP
	// rejects _sd at the root to protect structural properties.
	cnfJWK := testECPublicKeyToJWK(t, &holderPriv.PublicKey)
	vpContents := vp.PresentationContents{
		Context:               []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:                    "urn:uuid:vp-kb-001",
		Types:                 []string{"VerifiablePresentation"},
		Holder:                holderDID,
		VerifiableCredentials: []vc.Credential{cred},
		CustomFields: map[string]interface{}{
			"termsOfAgreement": map[string]interface{}{
				"type":        "ConsentReceipt",
				"consentedTo": "data-sharing-policy-v2",
			},
			"cnf": map[string]interface{}{"jwk": cnfJWK},
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

	// Present with all disclosures to get the SD-JWT presentation string.
	disclosures, err := pres.DecodedDisclosures()
	if err != nil {
		t.Fatalf("DecodedDisclosures: %v", err)
	}
	selected := make([]string, len(disclosures))
	for i, d := range disclosures {
		selected[i] = d.Disclosure
	}
	presented, err := pres.Present(selected)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	ser, err := presented.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	sdJWTPresentation := ser.(string)

	// Build KB-JWT signed by the holder's key.
	holderSigner, err := jws.PrivateKeySigner(holderPriv)
	if err != nil {
		t.Fatalf("PrivateKeySigner: %v", err)
	}
	sdHash := josesdjwt.SDHash(sdJWTPresentation)
	kbToken, err := josesdjwt.NewKBJWT(context.Background(), holderSigner, &holderPriv.PublicKey, josesdjwt.KBClaims{
		Audience: audience,
		Nonce:    nonce,
		IssuedAt: time.Now(),
		SDHash:   sdHash,
	})
	if err != nil {
		t.Fatalf("NewKBJWT: %v", err)
	}

	token = sdJWTPresentation + kbToken
	return token, resolver
}

func testECPublicKeyToJWK(t *testing.T, pub *ecdsa.PublicKey) map[string]interface{} {
	t.Helper()
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	pub.X.FillBytes(xb)
	pub.Y.FillBytes(yb)
	return map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xb),
		"y":   base64.RawURLEncoding.EncodeToString(yb),
	}
}

// F2a: VP with KB-JWT and no policy → accepted (KB-JWT ignored).
func TestVPKBJWT_AcceptedWithoutPolicy(t *testing.T) {
	token, resolver := vpKBJWTFixture(t, "verifier-1", "nonce-1")

	parsed, err := vp.ParseJOSEPresentation(token)
	if err != nil {
		t.Fatalf("ParseJOSEPresentation should accept KB-JWT without policy: %v", err)
	}
	// Verify WITHOUT WithKBJWT — KB-JWT should be ignored.
	err = parsed.Verify(vp.WithResolver(resolver))
	if err != nil {
		t.Fatalf("Verify should pass without KB-JWT policy: %v", err)
	}
}

// F2b: VP with KB-JWT and policy with valid audience/nonce → accepted.
func TestVPKBJWT_ValidWithPolicy(t *testing.T) {
	token, resolver := vpKBJWTFixture(t, "verifier-1", "nonce-1")

	parsed, err := vp.ParseJOSEPresentation(token)
	if err != nil {
		t.Fatalf("ParseJOSEPresentation: %v", err)
	}
	err = parsed.Verify(
		vp.WithResolver(resolver),
		vp.WithKBJWT("verifier-1", "nonce-1"),
	)
	if err != nil {
		t.Fatalf("Verify with valid KB-JWT: %v", err)
	}
}

// F2c: VP with KB-JWT and wrong nonce → rejected.
func TestVPKBJWT_WrongNonce(t *testing.T) {
	token, resolver := vpKBJWTFixture(t, "verifier-1", "correct-nonce")

	parsed, err := vp.ParseJOSEPresentation(token)
	if err != nil {
		t.Fatalf("ParseJOSEPresentation: %v", err)
	}
	err = parsed.Verify(
		vp.WithResolver(resolver),
		vp.WithKBJWT("verifier-1", "wrong-nonce"),
	)
	if err == nil {
		t.Fatal("expected nonce mismatch error")
	}
	if !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("error should mention nonce: %v", err)
	}
}

// F2d: VP with KB-JWT and wrong audience → rejected.
func TestVPKBJWT_WrongAudience(t *testing.T) {
	token, resolver := vpKBJWTFixture(t, "verifier-1", "nonce-1")

	parsed, err := vp.ParseJOSEPresentation(token)
	if err != nil {
		t.Fatalf("ParseJOSEPresentation: %v", err)
	}
	err = parsed.Verify(
		vp.WithResolver(resolver),
		vp.WithKBJWT("verifier-2", "nonce-1"),
	)
	if err == nil {
		t.Fatal("expected aud mismatch error")
	}
	if !strings.Contains(err.Error(), "aud") {
		t.Fatalf("error should mention aud: %v", err)
	}
}

// F2e: VP with policy requiring KB-JWT but no KB-JWT present → rejected.
func TestVPKBJWT_MissingKBJWT(t *testing.T) {
	// vpSDJWTFixture creates a VP without KB-JWT.
	token, _, resolver := vpSDJWTFixture(t)

	parsed, err := vp.ParseJOSEPresentation(token)
	if err != nil {
		t.Fatalf("ParseJOSEPresentation: %v", err)
	}
	err = parsed.Verify(
		vp.WithResolver(resolver),
		vp.WithKBJWT("verifier-1", "nonce-1"),
	)
	if err == nil {
		t.Fatal("expected error for missing KB-JWT")
	}
	if !strings.Contains(err.Error(), "KB-JWT required") {
		t.Fatalf("error should say KB-JWT required: %v", err)
	}
}

// F2f: VP with KB-JWT whose sd_hash is wrong → rejected.
func TestVPKBJWT_WrongSDHash(t *testing.T) {
	token, resolver := vpKBJWTFixture(t, "verifier-1", "nonce-1")

	// Tamper with the token to change the SD-JWT part while keeping the same
	// KB-JWT. Remove a disclosure so sd_hash no longer matches.
	lastTilde := strings.LastIndex(token, "~")
	if lastTilde < 0 {
		t.Fatal("expected ~ in token")
	}
	kbPart := token[lastTilde+1:]
	sdPart := token[:lastTilde+1] // includes the trailing ~

	// Find the first disclosure ~ and remove it.
	firstDiscIdx := strings.Index(sdPart, "~")
	if firstDiscIdx < 0 {
		t.Fatal("no disclosures found")
	}
	secondDiscIdx := strings.Index(sdPart[firstDiscIdx+1:], "~")
	if secondDiscIdx < 0 {
		t.Fatal("only one ~ segment")
	}
	// Remove the first disclosure segment.
	tamperedSD := sdPart[:firstDiscIdx+1] + sdPart[firstDiscIdx+1+secondDiscIdx+1:]
	tamperedToken := tamperedSD + kbPart

	parsed, err := vp.ParseJOSEPresentation(tamperedToken)
	if err != nil {
		// Parse failure is also acceptable.
		return
	}
	err = parsed.Verify(
		vp.WithResolver(resolver),
		vp.WithKBJWT("verifier-1", "nonce-1"),
	)
	if err == nil {
		t.Fatal("expected sd_hash mismatch error")
	}
	if !strings.Contains(err.Error(), "sd_hash") {
		t.Fatalf("error should mention sd_hash: %v", err)
	}
}

// F2g: WithKBJWT("", "nonce") must be refused — empty audience silently
// disables the requirement.
func TestVPKBJWT_EmptyAudienceRefused(t *testing.T) {
	token, resolver := vpKBJWTFixture(t, "verifier-1", "nonce-1")

	parsed, err := vp.ParseJOSEPresentation(token)
	if err != nil {
		t.Fatalf("ParseJOSEPresentation: %v", err)
	}
	err = parsed.Verify(
		vp.WithResolver(resolver),
		vp.WithKBJWT("", "nonce-1"),
	)
	if err == nil {
		t.Fatal("expected error for empty audience")
	}
	if !strings.Contains(err.Error(), "audience") && !strings.Contains(err.Error(), "non-empty") {
		t.Fatalf("error should mention audience: %v", err)
	}
}

// F2h: WithKBJWT("aud", "") must be refused — empty nonce.
func TestVPKBJWT_EmptyNonceRefused(t *testing.T) {
	token, resolver := vpKBJWTFixture(t, "verifier-1", "nonce-1")

	parsed, err := vp.ParseJOSEPresentation(token)
	if err != nil {
		t.Fatalf("ParseJOSEPresentation: %v", err)
	}
	err = parsed.Verify(
		vp.WithResolver(resolver),
		vp.WithKBJWT("verifier-1", ""),
	)
	if err == nil {
		t.Fatal("expected error for empty nonce")
	}
	if !strings.Contains(err.Error(), "nonce") && !strings.Contains(err.Error(), "non-empty") {
		t.Fatalf("error should mention nonce: %v", err)
	}
}

// F2i: WithKBJWT("", "nonce") on a VP without KB-JWT must NOT verify — the
// empty audience must not silently disable the requirement.
func TestVPKBJWT_EmptyAudienceDoesNotSkipRequirement(t *testing.T) {
	token, _, resolver := vpSDJWTFixture(t)

	parsed, err := vp.ParseJOSEPresentation(token)
	if err != nil {
		t.Fatalf("ParseJOSEPresentation: %v", err)
	}
	err = parsed.Verify(
		vp.WithResolver(resolver),
		vp.WithKBJWT("", "nonce-1"),
	)
	if err == nil {
		t.Fatal("expected error: WithKBJWT(\"\", \"nonce\") must not silently verify without KB-JWT")
	}
}
