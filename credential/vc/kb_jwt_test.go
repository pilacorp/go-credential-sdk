package vc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
)

// issueSDJWTWithCNF creates a signed vc+sd-jwt with the holder's key in cnf.jwk.
func issueSDJWTWithCNF(t *testing.T, issuerDID string, issuerPriv *ecdsa.PrivateKey, holderPub *ecdsa.PublicKey) *vc.JOSECredential {
	t.Helper()

	contents := vc.CredentialContents{
		Context:   []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:        "urn:uuid:kb-jwt-test",
		Types:     []string{"VerifiableCredential"},
		Issuer:    issuerDID,
		ValidFrom: time.Now().Add(-time.Hour),
		Subject: []vc.Subject{{
			ID: "did:example:holder",
			CustomFields: map[string]interface{}{
				"name":      "Alice",
				"bloodType": "O-",
			},
		}},
	}

	resolver := kbIssuerResolver(t, issuerDID, issuerPriv)
	cred, err := vc.NewJOSECredential(contents,
		vc.WithSDSelectivePaths([]string{"credentialSubject.bloodType"}),
		vc.WithConfirmationKey(holderPub),
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(resolver),
	)
	if err != nil {
		t.Fatalf("NewJOSECredential: %v", err)
	}

	prov := kbIssuerProvider(t, issuerPriv)
	if err := cred.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return cred
}

func kbIssuerResolver(t *testing.T, did string, priv *ecdsa.PrivateKey) vmpkg.ResolverProvider {
	t.Helper()
	vm, err := vmpkg.NewP256VM(did, "key-1", &priv.PublicKey)
	if err != nil {
		t.Fatalf("NewP256VM: %v", err)
	}
	return vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))
}

func kbIssuerProvider(t *testing.T, priv *ecdsa.PrivateKey) signer.SignerProvider {
	t.Helper()
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("NewP256Provider: %v", err)
	}
	return prov
}

func kbDisclosures(t *testing.T, cred *vc.JOSECredential) []string {
	t.Helper()
	disclosures, err := cred.DecodedDisclosures()
	if err != nil {
		t.Fatalf("DecodedDisclosures: %v", err)
	}
	selected := make([]string, len(disclosures))
	for i, d := range disclosures {
		selected[i] = d.Disclosure
	}
	return selected
}

// TC-C01: Issue vc+sd-jwt with cnf, present with KB-JWT, verify with
// WithKBJWT("verifier-1", "abc") -- passes.
func TestKBJWT_RoundTrip(t *testing.T) {
	issuerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen issuer key: %v", err)
	}
	holderPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen holder key: %v", err)
	}

	const issuerDID = "did:example:kb-issuer"
	cred := issueSDJWTWithCNF(t, issuerDID, issuerPriv, &holderPriv.PublicKey)
	selected := kbDisclosures(t, cred)

	holderSigner, err := jws.PrivateKeySigner(holderPriv)
	if err != nil {
		t.Fatalf("PrivateKeySigner: %v", err)
	}
	presented, err := cred.PresentWithKBJWT(context.Background(), selected, holderSigner, &holderPriv.PublicKey, "verifier-1", "abc")
	if err != nil {
		t.Fatalf("PresentWithKBJWT: %v", err)
	}

	serialized, err := presented.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	token := serialized.(string)
	if !strings.Contains(token, "~") {
		t.Fatal("expected SD-JWT format")
	}

	resolver := kbIssuerResolver(t, issuerDID, issuerPriv)
	parsed, err := vc.ParseJOSECredential(token)
	if err != nil {
		t.Fatalf("ParseJOSECredential: %v", err)
	}
	err = parsed.Verify(
		vc.WithResolver(resolver),
		vc.WithKBJWT("verifier-1", "abc"),
	)
	if err != nil {
		t.Fatalf("Verify with KB-JWT: %v", err)
	}
}

// TC-C02: Same as TC-C01 but verify with WithKBJWT("verifier-2", "abc") --
// rejected: aud mismatch.
func TestKBJWT_WrongAudience(t *testing.T) {
	issuerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen issuer key: %v", err)
	}
	holderPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen holder key: %v", err)
	}

	const issuerDID = "did:example:kb-aud"
	cred := issueSDJWTWithCNF(t, issuerDID, issuerPriv, &holderPriv.PublicKey)
	selected := kbDisclosures(t, cred)

	holderSigner, _ := jws.PrivateKeySigner(holderPriv)
	presented, err := cred.PresentWithKBJWT(context.Background(), selected, holderSigner, &holderPriv.PublicKey, "verifier-1", "abc")
	if err != nil {
		t.Fatalf("PresentWithKBJWT: %v", err)
	}

	serialized, _ := presented.Serialize()
	token := serialized.(string)

	resolver := kbIssuerResolver(t, issuerDID, issuerPriv)
	parsed, _ := vc.ParseJOSECredential(token)
	err = parsed.Verify(
		vc.WithResolver(resolver),
		vc.WithKBJWT("verifier-2", "abc"),
	)
	if err == nil {
		t.Fatal("expected aud mismatch error")
	}
	if !strings.Contains(err.Error(), "aud") {
		t.Fatalf("error should mention aud: %v", err)
	}
}

// TC-C03: vc+sd-jwt without KB-JWT, verify with WithKBJWT -- rejected.
func TestKBJWT_MissingKBJWT(t *testing.T) {
	issuerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen issuer key: %v", err)
	}
	holderPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen holder key: %v", err)
	}

	const issuerDID = "did:example:kb-missing"
	cred := issueSDJWTWithCNF(t, issuerDID, issuerPriv, &holderPriv.PublicKey)
	selected := kbDisclosures(t, cred)

	// Present WITHOUT KB-JWT (plain Present).
	presented, err := cred.Present(selected)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	serialized, _ := presented.Serialize()
	token := serialized.(string)

	resolver := kbIssuerResolver(t, issuerDID, issuerPriv)
	parsed, _ := vc.ParseJOSECredential(token)
	err = parsed.Verify(
		vc.WithResolver(resolver),
		vc.WithKBJWT("verifier-1", "nonce-1"),
	)
	if err == nil {
		t.Fatal("expected error for missing KB-JWT")
	}
	if !strings.Contains(err.Error(), "KB-JWT required") {
		t.Fatalf("error should say KB-JWT required: %v", err)
	}
}

// TC-C04: vc+sd-jwt with KB-JWT, verify WITHOUT WithKBJWT -- passes (KB-JWT
// ignored).
func TestKBJWT_IgnoredWithoutOption(t *testing.T) {
	issuerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen issuer key: %v", err)
	}
	holderPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen holder key: %v", err)
	}

	const issuerDID = "did:example:kb-ignore"
	cred := issueSDJWTWithCNF(t, issuerDID, issuerPriv, &holderPriv.PublicKey)
	selected := kbDisclosures(t, cred)

	holderSigner, _ := jws.PrivateKeySigner(holderPriv)
	presented, err := cred.PresentWithKBJWT(context.Background(), selected, holderSigner, &holderPriv.PublicKey, "verifier-1", "abc")
	if err != nil {
		t.Fatalf("PresentWithKBJWT: %v", err)
	}

	serialized, _ := presented.Serialize()
	token := serialized.(string)

	// Verify WITHOUT WithKBJWT -- KB-JWT should be ignored.
	resolver := kbIssuerResolver(t, issuerDID, issuerPriv)
	parsed, _ := vc.ParseJOSECredential(token)
	err = parsed.Verify(vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("expected no error when KB-JWT is not required: %v", err)
	}
}

// TestKBJWT_WrongNonce verifies that a KB-JWT with the wrong nonce is rejected.
func TestKBJWT_WrongNonce(t *testing.T) {
	issuerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen issuer key: %v", err)
	}
	holderPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen holder key: %v", err)
	}

	const issuerDID = "did:example:kb-nonce"
	cred := issueSDJWTWithCNF(t, issuerDID, issuerPriv, &holderPriv.PublicKey)
	selected := kbDisclosures(t, cred)

	holderSigner, _ := jws.PrivateKeySigner(holderPriv)
	presented, err := cred.PresentWithKBJWT(context.Background(), selected, holderSigner, &holderPriv.PublicKey, "verifier-1", "correct-nonce")
	if err != nil {
		t.Fatalf("PresentWithKBJWT: %v", err)
	}

	serialized, _ := presented.Serialize()
	token := serialized.(string)

	resolver := kbIssuerResolver(t, issuerDID, issuerPriv)
	parsed, _ := vc.ParseJOSECredential(token)
	err = parsed.Verify(
		vc.WithResolver(resolver),
		vc.WithKBJWT("verifier-1", "wrong-nonce"),
	)
	if err == nil {
		t.Fatal("expected nonce mismatch error")
	}
	if !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("error should mention nonce: %v", err)
	}
}
