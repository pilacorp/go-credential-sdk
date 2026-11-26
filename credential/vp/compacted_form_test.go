package vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// signTestPresentation creates a VP with holder and validUntil, signs it with
// ecdsa-rdfc-2019 P-256, and returns the signed JSON bytes plus resolver opts.
func signTestPresentation(t *testing.T) ([]byte, []vp.PresentationOpt) {
	t.Helper()

	did := "did:example:holder-179"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	vm, err := vmpkg.NewP256VM(did, "key-1", &priv.PublicKey)
	if err != nil {
		t.Fatalf("vm: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))
	opts := []vp.PresentationOpt{vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver)}

	// Create a minimal signed credential to embed.
	issuerDID := "did:example:issuer-179"
	issuerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	issuerProv, err := signer.NewP256Provider(issuerPriv)
	if err != nil {
		t.Fatalf("issuer provider: %v", err)
	}
	issuerVM, err := vmpkg.NewP256VM(issuerDID, "key-1", &issuerPriv.PublicKey)
	if err != nil {
		t.Fatalf("issuer vm: %v", err)
	}
	issuerResolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(issuerDID, issuerVM))

	credContents := vc.CredentialContents{
		Context: []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{"@vocab": "https://example.org/vocab#"},
		},
		ID:     "urn:uuid:179-vc",
		Types:  []string{"VerifiableCredential"},
		Issuer: issuerDID,
		ValidFrom: func() time.Time {
			t, _ := time.Parse(time.RFC3339, "2020-01-01T00:00:00Z")
			return t
		}(),
		Subject: []vc.Subject{{
			ID:           did,
			CustomFields: map[string]interface{}{"name": "Alice"},
		}},
	}
	cred, err := vc.NewJSONCredential(credContents)
	if err != nil {
		t.Fatalf("new cred: %v", err)
	}
	if err := cred.AddProofByProvider(issuerProv,
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(issuerResolver)); err != nil {
		t.Fatalf("sign cred: %v", err)
	}

	vpContents := vp.PresentationContents{
		Context: []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{"@vocab": "https://example.org/vocab#"},
		},
		ID:     "urn:uuid:179-vp",
		Types:  []string{"VerifiablePresentation"},
		Holder: did,
		ValidFrom: func() time.Time {
			t, _ := time.Parse(time.RFC3339, "2020-01-01T00:00:00Z")
			return t
		}(),
		ValidUntil: func() time.Time {
			t, _ := time.Parse(time.RFC3339, "2020-06-01T00:00:00Z")
			return t
		}(),
		VerifiableCredentials: []vc.Credential{cred},
	}

	pres, err := vp.NewJSONPresentation(vpContents)
	if err != nil {
		t.Fatalf("new vp: %v", err)
	}
	if err := pres.AddProofByProvider(prov, opts...); err != nil {
		t.Fatalf("sign vp: %v", err)
	}

	raw, err := pres.GetContents()
	if err != nil {
		t.Fatalf("get contents: %v", err)
	}

	// Add issuer resolver so embedded credential verification works.
	resolverOpts := []vp.PresentationOpt{
		vp.WithResolver(resolver),
		vp.WithVCValidation(vc.WithResolver(issuerResolver)),
	}
	return raw, resolverOpts
}

// vpMoveUnderNest moves a top-level key into "@nest": {key: value}.
func vpMoveUnderNest(raw []byte, key string) ([]byte, error) {
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	val, ok := doc[key]
	if !ok {
		return nil, fmt.Errorf("key %q not found", key)
	}
	delete(doc, key)
	nest, _ := doc["@nest"].(map[string]interface{})
	if nest == nil {
		nest = map[string]interface{}{}
	}
	nest[key] = val
	doc["@nest"] = nest
	return json.Marshal(doc)
}

// TestVP_HolderUnderNest checks that moving holder under @nest is refused.
func TestVP_HolderUnderNest(t *testing.T) {
	raw, resolverOpts := signTestPresentation(t)

	edited, err := vpMoveUnderNest(raw, "holder")
	if err != nil {
		t.Fatal(err)
	}

	pres, err := vp.ParseJSONPresentation(edited)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	err = pres.Verify(resolverOpts[0])
	if err == nil {
		t.Fatal("Verify returned nil — holder hidden by @nest rewrite")
	}
	if !errors.Is(err, processor.ErrNotCompactedForm) {
		t.Fatalf("expected ErrNotCompactedForm, got: %v", err)
	}
	t.Logf("compacted form error (expected): %v", err)
}

// TestVP_ValidUntilUnderNest checks that moving validUntil under @nest is
// refused.
func TestVP_ValidUntilUnderNest(t *testing.T) {
	raw, resolverOpts := signTestPresentation(t)

	edited, err := vpMoveUnderNest(raw, "validUntil")
	if err != nil {
		t.Fatal(err)
	}

	pres, err := vp.ParseJSONPresentation(edited)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	err = pres.Verify(resolverOpts[0])
	if err == nil {
		t.Fatal("Verify returned nil — validUntil hidden by @nest rewrite")
	}
	if !errors.Is(err, processor.ErrNotCompactedForm) {
		t.Fatalf("expected ErrNotCompactedForm, got: %v", err)
	}
}

// TestVP_VerifiableCredentialUnderNest checks that moving verifiableCredential
// under @nest is refused.
func TestVP_VerifiableCredentialUnderNest(t *testing.T) {
	raw, resolverOpts := signTestPresentation(t)

	edited, err := vpMoveUnderNest(raw, "verifiableCredential")
	if err != nil {
		t.Fatal(err)
	}

	pres, err := vp.ParseJSONPresentation(edited)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	err = pres.Verify(resolverOpts[0])
	if err == nil {
		t.Fatal("Verify returned nil — verifiableCredential hidden by @nest rewrite")
	}
	if !errors.Is(err, processor.ErrNotCompactedForm) {
		t.Fatalf("expected ErrNotCompactedForm, got: %v", err)
	}
}

// validUntil is not a VerifiablePresentation property in the v2 context, so a
// VP carrying it is refused before any rename matters; the alias rule for VP
// keys is pinned on holder here and in compacted_alias_internal_test.go.

// Signing refuses a presentation that is not in compacted form, so the SDK
// never signs a holder it would not read back.
func TestSign_RefusesHolderAlias(t *testing.T) {
	const did = "did:example:holder-179s"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatal(err)
	}
	vm, err := vmpkg.NewP256VM(did, "key-1", &priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))
	pres, err := vp.ParseJSONPresentation([]byte(`{
		"@context": ["https://www.w3.org/ns/credentials/v2",
			{"h": {"@id": "https://www.w3.org/2018/credentials#holder", "@type": "@id"}}],
		"type": ["VerifiablePresentation"], "h": "` + did + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	err = pres.AddProofByProvider(prov, vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
	if !errors.Is(err, processor.ErrNotCompactedForm) {
		t.Fatalf("err = %v, want ErrNotCompactedForm", err)
	}
}
