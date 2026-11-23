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

// vpRenameToFullIRI renames a top-level key to its full IRI.
func vpRenameToFullIRI(raw []byte, shortKey, fullIRI string) ([]byte, error) {
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	val, ok := doc[shortKey]
	if !ok {
		return nil, fmt.Errorf("key %q not found", shortKey)
	}
	delete(doc, shortKey)
	doc[fullIRI] = val
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

// TestVP_HolderFullIRI checks that renaming holder to its full IRI is refused.
func TestVP_HolderFullIRI(t *testing.T) {
	raw, resolverOpts := signTestPresentation(t)

	edited, err := vpRenameToFullIRI(raw, "holder",
		"https://www.w3.org/2018/credentials#holder")
	if err != nil {
		t.Fatal(err)
	}

	pres, err := vp.ParseJSONPresentation(edited)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	err = pres.Verify(resolverOpts[0])
	if err == nil {
		t.Fatal("Verify returned nil — holder hidden by full-IRI rename")
	}
	// holder is not a graph key this check compares. Renaming a string holder
	// to its full IRI leaves both sides without that short name, so the
	// compacted-form check does not fire. The proof fails instead.
	if errors.Is(err, processor.ErrNotCompactedForm) {
		t.Fatalf("holder full IRI must be refused by the proof, got ErrNotCompactedForm: %v", err)
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

// TestVP_VerifiableCredentialFullIRI checks that renaming verifiableCredential
// to its full IRI is refused. On the json-gold fork the proof itself refuses
// this input, so the test only requires a non-nil error.
func TestVP_VerifiableCredentialFullIRI(t *testing.T) {
	raw, resolverOpts := signTestPresentation(t)

	edited, err := vpRenameToFullIRI(raw, "verifiableCredential",
		"https://www.w3.org/2018/credentials#verifiableCredential")
	if err != nil {
		t.Fatal(err)
	}

	pres, err := vp.ParseJSONPresentation(edited)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	err = pres.Verify(resolverOpts[0])
	if err == nil {
		t.Fatal("Verify returned nil — verifiableCredential hidden by full-IRI rename")
	}
}

// vpRenameWithContextAlias renames a top-level key in a VP and adds a context
// definition that maps the new name to the same IRI as the old one.
func vpRenameWithContextAlias(raw []byte, oldKey, newKey, iri, typ string) ([]byte, error) {
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	val, ok := doc[oldKey]
	if !ok {
		return nil, fmt.Errorf("key %q not found", oldKey)
	}
	delete(doc, oldKey)
	doc[newKey] = val

	ctxArr, _ := doc["@context"].([]interface{})
	entry := map[string]interface{}{
		newKey: map[string]interface{}{"@id": iri},
	}
	if typ != "" {
		entry[newKey].(map[string]interface{})["@type"] = typ
	}
	entry[oldKey] = "@none"
	ctxArr = append(ctxArr, entry)
	doc["@context"] = ctxArr

	return json.Marshal(doc)
}

// TestVP_ContextAliasAttack_ValidUntil checks that a VP whose validUntil is
// renamed via a context alias is refused. On the json-gold fork, the proof
// itself may refuse these edits, so the test only requires a non-nil error.
func TestVP_ContextAliasAttack_ValidUntil(t *testing.T) {
	raw, resolverOpts := signTestPresentation(t)

	edited, err := vpRenameWithContextAlias(raw,
		"validUntil", "validUntilX",
		"https://www.w3.org/2018/credentials#validUntil",
		"http://www.w3.org/2001/XMLSchema#dateTime")
	if err != nil {
		t.Fatal(err)
	}

	pres, err := vp.ParseJSONPresentation(edited)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	err = pres.Verify(resolverOpts[0])
	if err == nil {
		t.Fatal("Verify returned nil — validUntil hidden by context alias rename")
	}
	t.Logf("refused as expected: %v", err)
}

// TestVP_ContextAliasAttack_Holder checks that a VP whose holder is renamed
// via a context alias is refused. On the json-gold fork, the proof itself
// may refuse these edits, so the test only requires a non-nil error.
func TestVP_ContextAliasAttack_Holder(t *testing.T) {
	raw, resolverOpts := signTestPresentation(t)

	edited, err := vpRenameWithContextAlias(raw,
		"holder", "holderX",
		"https://www.w3.org/2018/credentials#holder", "")
	if err != nil {
		t.Fatal(err)
	}

	pres, err := vp.ParseJSONPresentation(edited)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	err = pres.Verify(resolverOpts[0])
	if err == nil {
		t.Fatal("Verify returned nil — holder hidden by context alias rename")
	}
	t.Logf("refused as expected: %v", err)
}

// TestVP_UnmodifiedPresentation ensures a normally signed presentation still
// verifies (backward compatibility).
func TestVP_UnmodifiedPresentation(t *testing.T) {
	raw, resolverOpts := signTestPresentation(t)

	pres, err := vp.ParseJSONPresentation(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Proof + VC validation.
	err = pres.Verify(resolverOpts...)
	if err != nil {
		t.Fatalf("Verify failed on unmodified presentation: %v", err)
	}
}
