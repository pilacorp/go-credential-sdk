package vc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// signTestCredential creates a VC with credentialStatus and a past validUntil,
// signs it with ecdsa-rdfc-2019 P-256, and returns the signed JSON bytes plus
// the resolver opts needed to verify.
func signTestCredential(t *testing.T) ([]byte, []CredentialOpt) {
	t.Helper()

	did := "did:example:issuer-179"
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
	opts := []CredentialOpt{WithVerificationMethodKey("key-1"), WithResolver(resolver)}

	contents := CredentialContents{
		Context: []interface{}{
			"https://www.w3.org/ns/credentials/v2",
		},
		ID:     "urn:uuid:179-test",
		Types:  []string{"VerifiableCredential"},
		Issuer: did,
		ValidFrom: func() time.Time {
			t, _ := time.Parse(time.RFC3339, "2020-01-01T00:00:00Z")
			return t
		}(),
		// Past validUntil — the credential is expired.
		ValidUntil: func() time.Time {
			t, _ := time.Parse(time.RFC3339, "2020-06-01T00:00:00Z")
			return t
		}(),
		Subject: []Subject{{
			ID:           "did:example:holder",
			CustomFields: map[string]interface{}{"name": "Alice"},
		}},
		CredentialStatus: []Status{{
			ID:                   "urn:status:179#0",
			Type:                 "BitstringStatusListEntry",
			StatusPurpose:        "revocation",
			StatusListIndex:      "0",
			StatusListCredential: "https://example.org/status/179",
		}},
	}

	cred, err := NewJSONCredential(contents)
	if err != nil {
		t.Fatalf("new cred: %v", err)
	}
	if err := cred.AddProofByProvider(prov, opts...); err != nil {
		t.Fatalf("sign: %v", err)
	}

	raw, err := cred.GetContents()
	if err != nil {
		t.Fatalf("get contents: %v", err)
	}

	return raw, []CredentialOpt{WithResolver(resolver)}
}

// moveUnderNest moves a top-level key into "@nest": {key: value}.
func moveUnderNest(raw []byte, key string) ([]byte, error) {
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

// renameToFullIRI renames a top-level key to its full IRI.
func renameToFullIRI(raw []byte, shortKey, fullIRI string) ([]byte, error) {
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

// duplicateUnderNest adds a key under @nest WITHOUT removing the top-level one,
// so both the short name and the nested copy exist.
func duplicateUnderNest(raw []byte, key string) ([]byte, error) {
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	val, ok := doc[key]
	if !ok {
		return nil, fmt.Errorf("key %q not found", key)
	}
	nest, _ := doc["@nest"].(map[string]interface{})
	if nest == nil {
		nest = map[string]interface{}{}
	}
	nest[key] = val
	doc["@nest"] = nest
	return json.Marshal(doc)
}

// TestVerify_CredentialStatusUnderNest reproduces Issue #179 Row 1:
// credentialStatus moved under @nest — Verify must refuse with
// ErrNotCompactedForm.
func TestVerify_CredentialStatusUnderNest(t *testing.T) {
	raw, resolverOpts := signTestCredential(t)

	edited, err := moveUnderNest(raw, "credentialStatus")
	if err != nil {
		t.Fatalf("move under nest: %v", err)
	}

	cred, err := ParseJSONCredential(edited)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	err = cred.Verify(resolverOpts...)
	if err == nil {
		t.Fatal("Verify returned nil — credentialStatus was silently hidden by @nest rewrite")
	}
	if !errors.Is(err, processor.ErrNotCompactedForm) {
		t.Fatalf("expected ErrNotCompactedForm, got: %v", err)
	}
	t.Logf("compacted form error (expected): %v", err)
}

// TestVerify_ValidUntilUnderNest reproduces Issue #179 Row 2:
// validUntil moved under @nest — Verify must refuse.
func TestVerify_ValidUntilUnderNest(t *testing.T) {
	raw, resolverOpts := signTestCredential(t)

	edited, err := moveUnderNest(raw, "validUntil")
	if err != nil {
		t.Fatalf("move under nest: %v", err)
	}

	cred, err := ParseJSONCredential(edited)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	err = cred.Verify(resolverOpts...)
	if err == nil {
		t.Fatal("Verify returned nil — validUntil was silently hidden by @nest rewrite")
	}
	if !errors.Is(err, processor.ErrNotCompactedForm) {
		t.Fatalf("expected ErrNotCompactedForm, got: %v", err)
	}
}

// TestVerify_CredentialStatusFullIRI reproduces Issue #179 Row 3:
// credentialStatus key renamed to full IRI — Verify must refuse.
func TestVerify_CredentialStatusFullIRI(t *testing.T) {
	raw, resolverOpts := signTestCredential(t)

	edited, err := renameToFullIRI(raw,
		"credentialStatus",
		"https://www.w3.org/2018/credentials#credentialStatus")
	if err != nil {
		t.Fatalf("rename: %v", err)
	}

	cred, err := ParseJSONCredential(edited)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	err = cred.Verify(resolverOpts...)
	if err == nil {
		t.Fatal("Verify returned nil — credentialStatus hidden by full-IRI rename")
	}
	if !errors.Is(err, processor.ErrNotCompactedForm) {
		t.Fatalf("expected ErrNotCompactedForm, got: %v", err)
	}
}

// TestVerify_RenderMethodFullIRI checks that renaming renderMethod to its full
// IRI is refused with ErrNotCompactedForm.
func TestVerify_RenderMethodFullIRI(t *testing.T) {
	did := "did:example:issuer-179-render"
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
	opts := []CredentialOpt{WithVerificationMethodKey("key-1"), WithResolver(resolver)}

	contents := CredentialContents{
		Context: []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			map[string]interface{}{"@vocab": "https://example.org/vocab#"},
		},
		ID:     "urn:uuid:179-render-test",
		Types:  []string{"VerifiableCredential"},
		Issuer: did,
		ValidFrom: func() time.Time {
			t, _ := time.Parse(time.RFC3339, "2020-01-01T00:00:00Z")
			return t
		}(),
		Subject: []Subject{{
			ID:           "did:example:holder",
			CustomFields: map[string]interface{}{"name": "Alice"},
		}},
		RenderMethods: []RenderMethod{{
			Type:        "SuiteRenderMethod",
			RenderSuite: "html",
			Name:        "Test",
			Template: &Template{
				Embedded: &EmbeddedTemplate{
					MediaType: "text/html",
					Bytes:     []byte("<p>Hello</p>"),
				},
			},
		}},
	}

	cred, err := NewJSONCredential(contents)
	if err != nil {
		t.Fatalf("new cred: %v", err)
	}
	if err := cred.AddProofByProvider(prov, opts...); err != nil {
		t.Fatalf("sign: %v", err)
	}

	raw, err := cred.GetContents()
	if err != nil {
		t.Fatalf("get contents: %v", err)
	}

	edited, err := renameToFullIRI(raw, "renderMethod",
		"https://www.w3.org/2018/credentials#renderMethod")
	if err != nil {
		t.Fatalf("rename: %v", err)
	}

	cred2, err := ParseJSONCredential(edited)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	err = cred2.Verify(opts...)
	if err == nil {
		t.Fatal("Verify returned nil — renderMethod hidden by full-IRI rename")
	}
	if !errors.Is(err, processor.ErrNotCompactedForm) {
		t.Fatalf("expected ErrNotCompactedForm, got: %v", err)
	}
}

// TestVerify_KeyBothShortAndNested checks that a property present under both
// its short name and @nest is refused (the compacted form merges them).
func TestVerify_KeyBothShortAndNested(t *testing.T) {
	raw, resolverOpts := signTestCredential(t)

	edited, err := duplicateUnderNest(raw, "credentialStatus")
	if err != nil {
		t.Fatalf("duplicate under nest: %v", err)
	}

	cred, err := ParseJSONCredential(edited)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	err = cred.Verify(resolverOpts...)
	if err == nil {
		t.Fatal("Verify returned nil — credentialStatus present both short and nested should be refused")
	}
	// The error might be a proof error (changed RDF) or ErrNotCompactedForm
	// (merge differs). Either way, the document is refused.
	t.Logf("error (expected): %v", err)
}

// renameWithContextAlias renames a top-level key and adds a context definition
// that maps the new name to the same IRI as the old one. This makes the rename
// transparent to JSON-LD expansion (same RDF) and to compaction against the
// document's own @context (the compacted form uses the new name too).
func renameWithContextAlias(raw []byte, oldKey, newKey, iri, typ string) ([]byte, error) {
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

	// Append a context entry mapping newKey to the same IRI.
	ctxArr, _ := doc["@context"].([]interface{})
	entry := map[string]interface{}{
		newKey: map[string]interface{}{"@id": iri},
	}
	if typ != "" {
		entry[newKey].(map[string]interface{})["@type"] = typ
	}
	// Also remap the old key to @none so it does not compact back.
	entry[oldKey] = "@none"
	ctxArr = append(ctxArr, entry)
	doc["@context"] = ctxArr

	return json.Marshal(doc)
}

// TestVerify_ContextAliasAttack_ValidUntil is the attack from review comment
// 4659414263: the holder renames validUntil to validUntilX and adds a context
// alias. Both raw["validUntil"] and compacted["validUntil"] are nil, so the
// own-context comparison passes, but the credential is expired.
func TestVerify_ContextAliasAttack_ValidUntil(t *testing.T) {
	raw, resolverOpts := signTestCredential(t)

	edited, err := renameWithContextAlias(raw,
		"validUntil", "validUntilX",
		"https://www.w3.org/2018/credentials#validUntil",
		"http://www.w3.org/2001/XMLSchema#dateTime")
	if err != nil {
		t.Fatal(err)
	}

	cred, err := ParseJSONCredential(edited)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	err = cred.Verify(resolverOpts...)
	if err == nil {
		t.Fatal("Verify returned nil — validUntil hidden by context alias rename")
	}
	if !errors.Is(err, processor.ErrNotCompactedForm) {
		t.Fatalf("expected ErrNotCompactedForm, got: %v", err)
	}
	t.Logf("refused as expected: %v", err)
}

// TestVerify_ContextAliasAttack_CredentialStatus is the same attack on
// credentialStatus.
func TestVerify_ContextAliasAttack_CredentialStatus(t *testing.T) {
	raw, resolverOpts := signTestCredential(t)

	edited, err := renameWithContextAlias(raw,
		"credentialStatus", "credentialStatusX",
		"https://www.w3.org/2018/credentials#credentialStatus", "")
	if err != nil {
		t.Fatal(err)
	}

	cred, err := ParseJSONCredential(edited)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	err = cred.Verify(resolverOpts...)
	if err == nil {
		t.Fatal("Verify returned nil — credentialStatus hidden by context alias rename")
	}
	if !errors.Is(err, processor.ErrNotCompactedForm) {
		t.Fatalf("expected ErrNotCompactedForm, got: %v", err)
	}
	t.Logf("refused as expected: %v", err)
}

// --- secp256k1 round-trip tests for the compacted-form check ---

// TestVerify_BareObjectIssuer checks that a VC with issuer: {"id": did}
// (no other fields) verifies. JSON-LD compaction turns this into a string,
// so normalizeForCompare must treat {"id": X} as "X".
func TestVerify_BareObjectIssuer(t *testing.T) {
	const did = "did:example:bare-obj-issuer"
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

	// Issuer as a bare {"id": did} object — VCDM 2.0 allows this form.
	raw := []byte(fmt.Sprintf(`{
		"@context": [
			"https://www.w3.org/ns/credentials/v2",
			{"@vocab": "https://example.org/vocab#"}
		],
		"id": "urn:uuid:bare-obj-issuer-001",
		"type": ["VerifiableCredential"],
		"issuer": {"id": %q},
		"validFrom": "2026-01-01T00:00:00Z",
		"credentialSubject": {"id": "did:example:holder"}
	}`, did))

	cred, err := ParseJSONCredential(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := cred.AddProofByProvider(prov,
		WithVerificationMethodKey("key-1"),
		WithResolver(resolver),
	); err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := cred.Verify(WithResolver(resolver)); err != nil {
		t.Fatalf("Verify failed on bare object issuer: %v", err)
	}
}

// TestVerify_NodeRefBothDirections checks that normalizeForCompare treats
// {"id": "X"} as equal to "X" in both directions. This matters for
// credentialSubject and issuer where JSON-LD compaction collapses the object.
func TestVerify_NodeRefBothDirections(t *testing.T) {
	const did = "did:example:noderef-test"
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

	// credentialSubject as a bare {"id": did} — compaction turns it to a string.
	raw := []byte(fmt.Sprintf(`{
		"@context": [
			"https://www.w3.org/ns/credentials/v2",
			{"@vocab": "https://example.org/vocab#"}
		],
		"id": "urn:uuid:noderef-test-001",
		"type": ["VerifiableCredential"],
		"issuer": %q,
		"validFrom": "2026-01-01T00:00:00Z",
		"credentialSubject": {"id": "did:example:holder"}
	}`, did))

	cred, err := ParseJSONCredential(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := cred.AddProofByProvider(prov,
		WithVerificationMethodKey("key-1"),
		WithResolver(resolver),
	); err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := cred.Verify(WithResolver(resolver)); err != nil {
		t.Fatalf("Verify failed with bare subject object: %v", err)
	}
}

// signV1Credential signs a VC Data Model 1.1 credential that expired in 2021.
func signV1Credential(t *testing.T) ([]byte, []CredentialOpt) {
	t.Helper()
	did := "did:example:issuer-179-v1"
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	prov, _ := signer.NewP256Provider(priv)
	vm, err := vmpkg.NewP256VM(did, "key-1", &priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))
	cred, err := ParseJSONCredential([]byte(`{
		"@context": ["https://www.w3.org/2018/credentials/v1"],
		"type": ["VerifiableCredential"],
		"issuer": "` + did + `",
		"issuanceDate": "2020-01-01T00:00:00Z",
		"expirationDate": "2021-01-01T00:00:00Z",
		"credentialSubject": {"id": "did:example:holder"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := cred.AddProofByProvider(prov, WithVerificationMethodKey("key-1"), WithResolver(resolver)); err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, _ := cred.GetContents()
	return raw, []CredentialOpt{WithResolver(resolver)}
}

// editJSON applies edit to a JSON document.
func editJSON(t *testing.T, raw []byte, edit func(doc map[string]interface{})) []byte {
	t.Helper()
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	edit(doc)
	out, _ := json.Marshal(doc)
	return out
}

func requireNotCompacted(t *testing.T, raw []byte, opts []CredentialOpt, key string) {
	t.Helper()
	cred, err := ParseJSONCredential(raw)
	if err != nil {
		t.Fatal(err)
	}
	err = cred.Verify(append(opts, WithCheckExpiration())...)
	if !errors.Is(err, processor.ErrNotCompactedForm) || !strings.Contains(err.Error(), key) {
		t.Fatalf("err = %v, want ErrNotCompactedForm for %s", err, key)
	}
}

// A context alias for the status entry's type keeps the RDF, and so the
// proof, but hides the entry from the revocation check unless the type is
// read from the known context (VC Data Integrity 1.0 §4.6).
func TestVerify_StatusTypeAlias(t *testing.T) {
	raw, opts := signTestCredential(t)
	raw = editJSON(t, raw, func(doc map[string]interface{}) {
		// The type-scoped context of BitstringStatusListEntry no longer applies
		// under the alias, so the alias context defines the entry's terms too.
		const st = "https://www.w3.org/ns/credentials/status#"
		doc["@context"] = append(doc["@context"].([]interface{}), map[string]interface{}{
			"B":                    st + "BitstringStatusListEntry",
			"statusPurpose":        st + "statusPurpose",
			"statusListIndex":      st + "statusListIndex",
			"statusListCredential": map[string]interface{}{"@id": st + "statusListCredential", "@type": "@id"},
		})
		doc["credentialStatus"].(map[string]interface{})["type"] = "B"
	})
	requireNotCompacted(t, raw, opts, "credentialStatus")
}

// VC Data Model 1.1 dates are read by name too.
func TestVerify_V1ExpirationDateFullIRI(t *testing.T) {
	raw, opts := signV1Credential(t)
	raw = editJSON(t, raw, func(doc map[string]interface{}) {
		doc["https://www.w3.org/2018/credentials#expirationDate"] = map[string]interface{}{
			"@value": doc["expirationDate"], "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
		}
		delete(doc, "expirationDate")
	})
	requireNotCompacted(t, raw, opts, "expirationDate")
}

// VC Data Model 2.0 §6: issuer is a single value, so an array is not the
// compacted form.
func TestVerify_IssuerArray(t *testing.T) {
	raw, opts := signTestCredential(t)
	raw = editJSON(t, raw, func(doc map[string]interface{}) {
		doc["issuer"] = []interface{}{doc["issuer"]}
	})
	requireNotCompacted(t, raw, opts, "issuer")
}

// A member set to null carries no statement, so it does not stop a credential
// the SDK signed from verifying.
func TestVerify_NullSubjectField(t *testing.T) {
	did := "did:example:issuer-179-null"
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	prov, _ := signer.NewP256Provider(priv)
	vm, _ := vmpkg.NewP256VM(did, "key-1", &priv.PublicKey)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))
	cred, err := NewJSONCredential(CredentialContents{
		Context: []interface{}{"https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"},
		Types:   []string{"VerifiableCredential"},
		Issuer:  did,
		Subject: []Subject{{ID: "did:example:holder", CustomFields: map[string]interface{}{"middleName": nil}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cred.AddProofByProvider(prov, WithVerificationMethodKey("key-1"), WithResolver(resolver)); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := cred.Verify(WithResolver(resolver)); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// The SDK does not sign a credential Verify would refuse.
func TestSign_RefusesFullIRIKey(t *testing.T) {
	did := "did:example:issuer-179-iri"
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	prov, _ := signer.NewP256Provider(priv)
	vm, _ := vmpkg.NewP256VM(did, "key-1", &priv.PublicKey)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vm))
	cred, err := ParseJSONCredential([]byte(`{
		"@context": ["https://www.w3.org/ns/credentials/v2"],
		"type": ["VerifiableCredential"],
		"issuer": "` + did + `",
		"https://www.w3.org/2018/credentials#validUntil": {"@value": "2030-01-01T00:00:00Z", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
		"credentialSubject": {"id": "did:example:holder"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	err = cred.AddProofByProvider(prov, WithVerificationMethodKey("key-1"), WithResolver(resolver))
	if !errors.Is(err, processor.ErrNotCompactedForm) {
		t.Fatalf("sign err = %v, want ErrNotCompactedForm", err)
	}
}

// signVocabCredential signs a VC 2.0 credential whose claims come from an
// inline @vocab, so its context can be relabelled without changing its RDF.
func signVocabCredential(t *testing.T) ([]byte, []CredentialOpt) {
	t.Helper()
	return signCredentialJSON(t, `{
		"@context": ["https://www.w3.org/ns/credentials/v2", {"@vocab": "https://example.org/vocab#"}],
		"id": "urn:uuid:179-vocab", "type": ["VerifiableCredential"], "issuer": "did:example:issuer-179v",
		"validFrom": "2025-01-01T00:00:00Z",
		"credentialSubject": {"id": "did:example:holder", "name": "Alice"},
		"credentialStatus": {"id": "urn:status:179#5", "type": "BitstringStatusListEntry",
			"statusPurpose": "revocation", "statusListIndex": "5",
			"statusListCredential": "https://example.org/status/179"}}`)
}

// signCredentialJSON signs doc, whose issuer is did:example:issuer-179v, with
// a fresh P-256 key.
func signCredentialJSON(t *testing.T, doc string) ([]byte, []CredentialOpt) {
	t.Helper()
	const did = "did:example:issuer-179v"
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
	cred, err := ParseJSONCredential([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if err := cred.AddProofByProvider(prov, WithVerificationMethodKey("key-1"), WithResolver(resolver)); err != nil {
		t.Fatal(err)
	}
	raw, err := cred.GetContents()
	if err != nil {
		t.Fatal(err)
	}
	return raw, []CredentialOpt{WithResolver(resolver)}
}

// A VCDM 2.0 credential relabelled with the v1 context keeps its RDF (both
// share the credentials# vocabulary), but v1 does not define the status entry,
// so its type would come out as an IRI and the status check would skip it.
func TestVerify_V1ContextRelabel(t *testing.T) {
	raw, opts := signVocabCredential(t)
	raw = editJSON(t, raw, func(doc map[string]interface{}) {
		const st = "https://www.w3.org/ns/credentials/status#"
		doc["@context"] = []interface{}{
			"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/data-integrity/v2",
			map[string]interface{}{
				"@vocab":               "https://example.org/vocab#",
				"name":                 "https://schema.org/name", // v2 defines it
				"validFrom":            map[string]interface{}{"@id": "https://www.w3.org/2018/credentials#validFrom", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
				"B":                    st + "BitstringStatusListEntry",
				"statusPurpose":        st + "statusPurpose",
				"statusListIndex":      st + "statusListIndex",
				"statusListCredential": map[string]interface{}{"@id": st + "statusListCredential", "@type": "@id"},
			},
		}
		doc["credentialStatus"].(map[string]interface{})["type"] = "B"
	})
	requireNotCompacted(t, raw, opts, "credentialStatus")
}

// A member aliased to @index yields no triple, so nothing signs its value.
func TestVerify_IndexAliasInjection(t *testing.T) {
	raw, opts := signVocabCredential(t)
	raw = editJSON(t, raw, func(doc map[string]interface{}) {
		doc["@context"] = append(doc["@context"].([]interface{}), map[string]interface{}{"role": "@index"})
		doc["credentialSubject"].(map[string]interface{})["role"] = "admin"
	})
	requireNotCompacted(t, raw, opts, "@index")
}

// A credential type renamed through an alias keeps its IRI; the SDK reads
// type by name.
func TestVerify_TypeAlias(t *testing.T) {
	raw, opts := signVocabCredential(t)
	raw = editJSON(t, raw, func(doc map[string]interface{}) {
		// The alias loses the type-scoped context of VerifiableCredential, so it
		// carries the terms this credential uses from there.
		const c = "https://www.w3.org/2018/credentials#"
		doc["@context"] = append(doc["@context"].([]interface{}), map[string]interface{}{
			"VC": map[string]interface{}{"@id": c + "VerifiableCredential", "@context": map[string]interface{}{
				"issuer":            map[string]interface{}{"@id": c + "issuer", "@type": "@id"},
				"validFrom":         map[string]interface{}{"@id": c + "validFrom", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
				"credentialSubject": map[string]interface{}{"@id": c + "credentialSubject", "@type": "@id"},
				"credentialStatus":  map[string]interface{}{"@id": c + "credentialStatus", "@type": "@id"},
				"name":              "https://schema.org/name",
			}}})
		doc["type"] = []interface{}{"VC"}
	})
	requireNotCompacted(t, raw, opts, "type")
}

// Two claims a bundled context names, swapped through an alias pair, keep the
// RDF but the reader sees each value under the other name.
func TestVerify_SubjectClaimSwap(t *testing.T) {
	raw, opts := signCredentialJSON(t, `{
		"@context": ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"],
		"id": "urn:uuid:179-swap", "type": ["VerifiableCredential"], "issuer": "did:example:issuer-179v",
		"validFrom": "2025-01-01T00:00:00Z",
		"credentialSubject": {"id": "did:example:holder", "permissions": "read", "p0": "admin"}}`)
	raw = editJSON(t, raw, func(doc map[string]interface{}) {
		const ex = "https://www.w3.org/ns/credentials/examples#"
		doc["@context"] = append(doc["@context"].([]interface{}), map[string]interface{}{
			"permissions": ex + "p0", "p0": ex + "permissions"})
		sub := doc["credentialSubject"].(map[string]interface{})
		sub["permissions"], sub["p0"] = "admin", "read"
	})
	requireNotCompacted(t, raw, opts, "credentialSubject")
}

// Claims the issuer's context types or puts in a container are written
// differently from the known form, which has no such definitions, yet carry
// the same signed values.
func TestVerify_TypedAndContainerClaims(t *testing.T) {
	raw, opts := signCredentialJSON(t, `{
		"@context": ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2", {
			"dob": {"@type": "http://www.w3.org/2001/XMLSchema#date"},
			"steps": {"@container": "@list"},
			"title": {"@container": "@language"},
			"blob": {"@type": "@json"},
			"byId": {"@container": "@id"},
			"byType": {"@container": "@type"},
			"note": {"@container": "@language"},
			"kind": {"@type": "@vocab"},
			"cfg": {"@type": "@json"},
			"members": {"@container": "@type"}}],
		"id": "urn:uuid:179-shapes", "type": ["VerifiableCredential"], "issuer": "did:example:issuer-179v",
		"validFrom": "2025-01-01T00:00:00Z",
		"credentialSubject": {"id": "did:example:holder", "dob": "1990-01-01", "steps": ["b", "a"],
			"title": {"en": "Engineer", "vi": "Kỹ sư"}, "blob": {"a": 1, "b": [true]},
			"byId": {"urn:x:1": {"name": "A"}}, "byType": {"Person": {"name": "B"}},
			"note": {"@none": "x", "en": "y"}, "kind": "Person", "cfg": {"list": [1, null]},
			"members": {"Person": [{"type": "Employee", "name": "C"}, "urn:x:2"]}}}`)
	cred, err := ParseJSONCredential(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := cred.Verify(opts...); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// A JSON literal is signed as its exact JSON; swapping it with a string that
// a looser comparison would equate keeps the RDF.
func TestVerify_JSONLiteralSwap(t *testing.T) {
	raw, opts := signCredentialJSON(t, `{
		"@context": ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2",
			{"grant": {"@type": "@json"}}],
		"id": "urn:uuid:179-json", "type": ["VerifiableCredential"], "issuer": "did:example:issuer-179v",
		"validFrom": "2025-01-01T00:00:00Z",
		"credentialSubject": {"id": "did:example:holder", "grant": {"id": "did:example:admin"}, "note": "did:example:admin"}}`)
	raw = editJSON(t, raw, func(doc map[string]interface{}) {
		const ex = "https://www.w3.org/ns/credentials/examples#"
		ctx := doc["@context"].([]interface{})
		ctx[2] = map[string]interface{}{
			"note":  map[string]interface{}{"@id": ex + "grant", "@type": "@json"},
			"grant": ex + "note"}
		sub := doc["credentialSubject"].(map[string]interface{})
		sub["grant"], sub["note"] = sub["note"], sub["grant"]
	})
	requireNotCompacted(t, raw, opts, "credentialSubject.grant")
}

// A null array element is not compacted form, and a reader that goes by
// position sees the signed values shifted.
func TestVerify_NullArrayElement(t *testing.T) {
	raw, opts := signCredentialJSON(t, `{
		"@context": ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"],
		"id": "urn:uuid:179-null", "type": ["VerifiableCredential"], "issuer": "did:example:issuer-179v",
		"validFrom": "2025-01-01T00:00:00Z",
		"credentialSubject": {"id": "did:example:holder", "roles": ["user", "auditor"]}}`)
	raw = editJSON(t, raw, func(doc map[string]interface{}) {
		sub := doc["credentialSubject"].(map[string]interface{})
		sub["roles"] = append([]interface{}{nil}, sub["roles"].([]interface{})...)
	})
	requireNotCompacted(t, raw, opts, "credentialSubject.roles[0]")
}
