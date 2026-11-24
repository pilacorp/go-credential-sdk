package vc_test

import (
	"context"
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

// S2: KB-JWT signed by a different key than cnf.jwk must be rejected.
func TestKBJWT_WrongSigningKey(t *testing.T) {
	issuerPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holderPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attackerPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	const issuerDID = "did:example:kb-wrong-key"
	cred := issueSDJWTWithCNF(t, issuerDID, issuerPriv, &holderPriv.PublicKey)
	selected := kbDisclosures(t, cred)

	// Sign the KB-JWT with the attacker's key instead of the holder's.
	attackerSigner, _ := jws.PrivateKeySigner(attackerPriv)
	presented, err := cred.PresentWithKBJWT(
		context.Background(), selected, attackerSigner, &attackerPriv.PublicKey,
		"verifier-1", "nonce-1",
	)
	if err != nil {
		t.Fatalf("PresentWithKBJWT: %v", err)
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
		t.Fatal("expected error: KB-JWT signed by wrong key")
	}
}

// S2: KB-JWT with wrong typ header (not kb+jwt) must be rejected.
func TestKBJWT_WrongTyp(t *testing.T) {
	issuerPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holderPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	const issuerDID = "did:example:kb-wrong-typ"
	cred := issueSDJWTWithCNF(t, issuerDID, issuerPriv, &holderPriv.PublicKey)
	selected := kbDisclosures(t, cred)

	// Present normally to get a valid token, then tamper with the KB-JWT typ.
	holderSigner, _ := jws.PrivateKeySigner(holderPriv)
	presented, err := cred.PresentWithKBJWT(
		context.Background(), selected, holderSigner, &holderPriv.PublicKey,
		"verifier-1", "nonce-1",
	)
	if err != nil {
		t.Fatalf("PresentWithKBJWT: %v", err)
	}

	serialized, _ := presented.Serialize()
	token := serialized.(string)

	// The KB-JWT is the last segment after the final ~.
	lastTilde := strings.LastIndex(token, "~")
	if lastTilde < 0 {
		t.Fatal("expected ~ in token")
	}
	kbPart := token[lastTilde+1:]
	sdPart := token[:lastTilde+1]

	// Decode the KB-JWT header, change typ, re-encode (signature will be invalid).
	kbParts := strings.SplitN(kbPart, ".", 3)
	if len(kbParts) != 3 {
		t.Fatalf("KB-JWT is not a 3-part JWS: %q", kbPart)
	}
	headerBytes, _ := base64.RawURLEncoding.DecodeString(kbParts[0])
	var hdr map[string]interface{}
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		t.Fatalf("unmarshal KB header: %v", err)
	}
	hdr["typ"] = "JWT" // wrong typ
	newHeader, _ := json.Marshal(hdr)
	kbParts[0] = base64.RawURLEncoding.EncodeToString(newHeader)
	tamperedToken := sdPart + strings.Join(kbParts, ".")

	resolver := kbIssuerResolver(t, issuerDID, issuerPriv)
	parsed, _ := vc.ParseJOSECredential(tamperedToken)
	err = parsed.Verify(
		vc.WithResolver(resolver),
		vc.WithKBJWT("verifier-1", "nonce-1"),
	)
	if err == nil {
		t.Fatal("expected error for KB-JWT with wrong typ")
	}
}

// S2: sd_hash computed from one presentation must not verify another.
func TestKBJWT_SDHashReuse(t *testing.T) {
	issuerPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holderPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	const issuerDID = "did:example:kb-sdhash-reuse"
	cred := issueSDJWTWithCNF(t, issuerDID, issuerPriv, &holderPriv.PublicKey)
	allDisclosures := kbDisclosures(t, cred)

	holderSigner, _ := jws.PrivateKeySigner(holderPriv)

	// Two presentations: one with all disclosures, one with none.
	presentedAll, err := cred.PresentWithKBJWT(
		context.Background(), allDisclosures, holderSigner, &holderPriv.PublicKey,
		"verifier-1", "nonce-all",
	)
	if err != nil {
		t.Fatalf("PresentWithKBJWT (all): %v", err)
	}
	presentedNone, err := cred.PresentWithKBJWT(
		context.Background(), nil, holderSigner, &holderPriv.PublicKey,
		"verifier-1", "nonce-none",
	)
	if err != nil {
		t.Fatalf("PresentWithKBJWT (none): %v", err)
	}

	serAll, _ := presentedAll.Serialize()
	serNone, _ := presentedNone.Serialize()
	tokenAll := serAll.(string)
	tokenNone := serNone.(string)

	// Swap the KB-JWTs: take the KB from "all" and glue it onto "none".
	lastAll := strings.LastIndex(tokenAll, "~")
	lastNone := strings.LastIndex(tokenNone, "~")
	kbFromAll := tokenAll[lastAll+1:]
	sdPartNone := tokenNone[:lastNone+1]
	frankenToken := sdPartNone + kbFromAll

	resolver := kbIssuerResolver(t, issuerDID, issuerPriv)
	parsed, _ := vc.ParseJOSECredential(frankenToken)
	err = parsed.Verify(
		vc.WithResolver(resolver),
		vc.WithKBJWT("verifier-1", "nonce-all"),
	)
	if err == nil {
		t.Fatal("expected error: sd_hash from a different presentation should not verify")
	}
	if !strings.Contains(err.Error(), "sd_hash") {
		t.Fatalf("error should mention sd_hash: %v", err)
	}
}

// N1: WithConfirmationKey + non-sha-256 _sd_alg must be rejected at issuance.
func TestKBJWT_RefuseNonSHA256AtIssuance(t *testing.T) {
	issuerPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holderPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	const issuerDID = "did:example:kb-refuse-alg"
	resolver := kbIssuerResolver(t, issuerDID, issuerPriv)

	contents := vc.CredentialContents{
		Context:   []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:        "urn:uuid:kb-refuse-alg",
		Types:     []string{"VerifiableCredential"},
		Issuer:    issuerDID,
		ValidFrom: time.Now().Add(-time.Hour),
		Subject: []vc.Subject{{
			ID:           "did:example:holder",
			CustomFields: map[string]interface{}{"name": "Alice"},
		}},
	}

	_, err := vc.NewJOSECredential(contents,
		vc.WithSDSelectivePaths([]string{"credentialSubject.name"}),
		vc.WithSDHashAlgorithm("sha-384"),
		vc.WithConfirmationKey(&holderPriv.PublicKey),
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(resolver),
	)
	if err == nil {
		t.Fatal("expected error for WithConfirmationKey + sha-384")
	}
	if !strings.Contains(err.Error(), "sha-256") {
		t.Fatalf("error should mention sha-256: %v", err)
	}
}

// TC-C07: WithKBJWT("", "nonce") must be refused — empty audience silently
// disables the requirement.
func TestKBJWT_EmptyAudienceRefused(t *testing.T) {
	issuerPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holderPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	const issuerDID = "did:example:kb-empty-aud"
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
		vc.WithKBJWT("", "abc"),
	)
	if err == nil {
		t.Fatal("expected error for empty audience")
	}
	if !strings.Contains(err.Error(), "audience") && !strings.Contains(err.Error(), "non-empty") {
		t.Fatalf("error should mention audience: %v", err)
	}
}

// TC-C08: WithKBJWT("aud", "") must be refused — empty nonce.
func TestKBJWT_EmptyNonceRefused(t *testing.T) {
	issuerPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holderPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	const issuerDID = "did:example:kb-empty-nonce"
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
		vc.WithKBJWT("verifier-1", ""),
	)
	if err == nil {
		t.Fatal("expected error for empty nonce")
	}
	if !strings.Contains(err.Error(), "nonce") && !strings.Contains(err.Error(), "non-empty") {
		t.Fatalf("error should mention nonce: %v", err)
	}
}

// TC-C09: WithKBJWT("", "nonce") on a credential without KB-JWT must NOT
// verify — the empty audience must not silently disable the requirement.
func TestKBJWT_EmptyAudienceDoesNotSkipRequirement(t *testing.T) {
	issuerPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holderPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	const issuerDID = "did:example:kb-empty-aud-skip"
	cred := issueSDJWTWithCNF(t, issuerDID, issuerPriv, &holderPriv.PublicKey)
	selected := kbDisclosures(t, cred)

	// Present WITHOUT KB-JWT.
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
		vc.WithKBJWT("", "nonce-1"),
	)
	if err == nil {
		t.Fatal("expected error: WithKBJWT(\"\", \"nonce\") must not silently verify without KB-JWT")
	}
}

// N1: PresentWithKBJWT must refuse a credential whose _sd_alg is not sha-256.
func TestKBJWT_RefuseNonSHA256AtPresent(t *testing.T) {
	issuerPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holderPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	const issuerDID = "did:example:kb-refuse-present"
	resolver := kbIssuerResolver(t, issuerDID, issuerPriv)

	// Issue with sha-384 (no cnf, so issuance succeeds).
	contents := vc.CredentialContents{
		Context:   []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:        "urn:uuid:kb-refuse-present",
		Types:     []string{"VerifiableCredential"},
		Issuer:    issuerDID,
		ValidFrom: time.Now().Add(-time.Hour),
		Subject: []vc.Subject{{
			ID:           "did:example:holder",
			CustomFields: map[string]interface{}{"name": "Alice"},
		}},
	}
	cred, err := vc.NewJOSECredential(contents,
		vc.WithSDSelectivePaths([]string{"credentialSubject.name"}),
		vc.WithSDHashAlgorithm("sha-384"),
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

	holderSigner, _ := jws.PrivateKeySigner(holderPriv)
	_, err = cred.PresentWithKBJWT(
		context.Background(), nil, holderSigner, &holderPriv.PublicKey,
		"verifier-1", "nonce-1",
	)
	if err == nil {
		t.Fatal("expected error for PresentWithKBJWT on sha-384 credential")
	}
	if !strings.Contains(err.Error(), "sha-256") {
		t.Fatalf("error should mention sha-256: %v", err)
	}
}
