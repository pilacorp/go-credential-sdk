package vc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
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

// TestVerify_Control_ChangedSubjectInvalidatesProof is the control row:
// changing credentialSubject.id breaks the proof.
func TestVerify_Control_ChangedSubjectInvalidatesProof(t *testing.T) {
	raw, resolverOpts := signTestCredential(t)

	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	subj := doc["credentialSubject"].(map[string]interface{})
	subj["id"] = "did:example:attacker"
	edited, _ := json.Marshal(doc)

	cred, err := ParseJSONCredential(edited)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = cred.Verify(resolverOpts...)
	if err == nil {
		t.Fatal("Verify should fail — credentialSubject was changed")
	}
	if errors.Is(err, processor.ErrNotCompactedForm) {
		t.Fatalf("should be a proof error, not compacted form error: %v", err)
	}
}

// TestVerify_UnmodifiedCredential ensures a normally signed credential still
// verifies after the fix (backward compatibility).
func TestVerify_UnmodifiedCredential(t *testing.T) {
	raw, resolverOpts := signTestCredential(t)

	cred, err := ParseJSONCredential(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	err = cred.Verify(resolverOpts...)
	if err != nil {
		t.Fatalf("Verify failed on unmodified credential: %v", err)
	}

	// Expiration check should catch the past validUntil.
	err = cred.Verify(append(resolverOpts, WithCheckExpiration())...)
	if err == nil {
		t.Fatal("expected expiration error on unmodified credential with past validUntil")
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

// TestVerify_DataUnchangedAfterVerify checks that Verify does NOT mutate the
// caller's data. GetContents before and after Verify must return identical bytes.
// This uses a credential with custom subject fields defined via @vocab.
func TestVerify_DataUnchangedAfterVerify(t *testing.T) {
	did := "did:example:issuer-179-unchanged"
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
		ID:     "urn:uuid:179-unchanged",
		Types:  []string{"VerifiableCredential"},
		Issuer: did,
		ValidFrom: func() time.Time {
			t, _ := time.Parse(time.RFC3339, "2020-01-01T00:00:00Z")
			return t
		}(),
		Subject: []Subject{{
			ID: "did:example:holder",
			CustomFields: map[string]interface{}{
				"name":        "Alice",
				"dateOfBirth": "1990-01-01",
				"score":       float64(42),
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

	// Parse from raw JSON to get a fresh object.
	raw, err := cred.GetContents()
	if err != nil {
		t.Fatalf("get contents: %v", err)
	}

	cred2, err := ParseJSONCredential(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// GetContents before Verify.
	before, err := cred2.GetContents()
	if err != nil {
		t.Fatalf("get contents before verify: %v", err)
	}

	// Verify.
	err = cred2.Verify(opts...)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// GetContents after Verify.
	after, err := cred2.GetContents()
	if err != nil {
		t.Fatalf("get contents after verify: %v", err)
	}

	if !bytes.Equal(before, after) {
		t.Fatalf("data changed after Verify:\nbefore: %s\nafter:  %s", before, after)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
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
// old VerifyCompactedKeys check passes, but the credential is expired.
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

const testSecpPriv = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

func testSecpPubHex(t *testing.T) string {
	t.Helper()
	priv, err := ethcrypto.HexToECDSA(testSecpPriv)
	if err != nil {
		t.Fatalf("priv: %v", err)
	}
	return hex.EncodeToString(ethcrypto.CompressPubkey(&priv.PublicKey))
}

func testSecpProvider(t *testing.T) signer.SignerProvider {
	t.Helper()
	p, err := signer.NewDefaultProvider(testSecpPriv)
	if err != nil {
		t.Fatalf("secp provider: %v", err)
	}
	return p
}

func testSecpResolver(t *testing.T, did string) vmpkg.ResolverProvider {
	t.Helper()
	return vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(did, vmpkg.NewSecp256k1VM(did, "key-1", testSecpPubHex(t))))
}

// TestSecp256k1_CompactedForm_StringIssuer signs a VC 2.0 credential with
// EcdsaSecp256k1Signature2019 (string issuer) and verifies that the
// compacted-form check does not reject it. This pins the fact that the
// credentials authen-service issues today (all string issuers, all standard
// fields) pass the new guard.
func TestSecp256k1_CompactedForm_StringIssuer(t *testing.T) {
	const did = "did:example:secp-compacted-string"
	resolver := testSecpResolver(t, did)

	raw := []byte(fmt.Sprintf(`{
		"@context": [
			"https://www.w3.org/ns/credentials/v2",
			{"@vocab": "https://example.org/vocab#"}
		],
		"id": "urn:uuid:secp-compacted-string-001",
		"type": ["VerifiableCredential"],
		"issuer": %q,
		"validFrom": "2026-01-01T00:00:00Z",
		"validUntil": "2027-01-01T00:00:00Z",
		"credentialStatus": {
			"id": "https://example.org/status/1#42",
			"type": "BitstringStatusListEntry",
			"statusPurpose": "revocation",
			"statusListIndex": "42",
			"statusListCredential": "https://example.org/status/1"
		},
		"credentialSubject": {
			"id": "did:example:subject",
			"name": "Nguyen Van A"
		}
	}`, did))

	cred, err := ParseJSONCredential(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := cred.AddProofByProvider(
		testSecpProvider(t),
		WithVerificationMethodKey("key-1"),
		WithResolver(resolver),
	); err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Verify includes WithVerifyProof automatically.
	if err := cred.Verify(WithResolver(resolver)); err != nil {
		t.Fatalf("Verify failed on secp256k1 credential with string issuer: %v", err)
	}

	// Confirm data is not mutated.
	before, err := cred.GetContents()
	if err != nil {
		t.Fatalf("get contents: %v", err)
	}
	cred2, err := ParseJSONCredential(before)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if err := cred2.Verify(WithResolver(resolver)); err != nil {
		t.Fatalf("second Verify failed: %v", err)
	}
	after, err := cred2.GetContents()
	if err != nil {
		t.Fatalf("get contents after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("data changed after Verify:\nbefore: %s\nafter:  %s", before, after)
	}
}

// TestSecp256k1_CompactedForm_ObjectIssuer signs with secp256k1 using an
// object issuer whose fields are all defined in the VCDM 2.0 context.
// Must pass: an issuer like {"id": "did:...", "name": "..."} where "name"
// is defined by @vocab survives expansion+compaction unchanged.
func TestSecp256k1_CompactedForm_ObjectIssuer(t *testing.T) {
	const did = "did:example:secp-compacted-obj-issuer"
	resolver := testSecpResolver(t, did)

	// @vocab defines "name", so it survives expansion. The issuer object
	// round-trips through expand+compact unchanged.
	raw := []byte(fmt.Sprintf(`{
		"@context": [
			"https://www.w3.org/ns/credentials/v2",
			{"@vocab": "https://example.org/vocab#"}
		],
		"id": "urn:uuid:secp-compacted-obj-issuer-001",
		"type": ["VerifiableCredential"],
		"issuer": {"id": %q, "name": "Example Corp"},
		"validFrom": "2026-01-01T00:00:00Z",
		"credentialSubject": {
			"id": "did:example:subject",
			"name": "Nguyen Van B"
		}
	}`, did))

	cred, err := ParseJSONCredential(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := cred.AddProofByProvider(
		testSecpProvider(t),
		WithVerificationMethodKey("key-1"),
		WithResolver(resolver),
	); err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := cred.Verify(WithResolver(resolver)); err != nil {
		t.Fatalf("Verify failed on secp256k1 credential with object issuer: %v", err)
	}
}

// TestSecp256k1_CompactedForm_ObjectIssuerUndefinedField verifies that an
// object issuer with a field not defined in any context cannot be signed.
//
// Both signing paths (Canonicalize for secp256k1/P-256 and CanonicalizeWithIdMap
// for ecdsa-sd-2023) use ExpandJSONLD with SafeMode, which rejects undefined
// terms at signing time. CanonicalizeDocument (which silently drops terms) is
// only used by the legacy hex proofValue path, not the current suites.
//
// This confirms the compatibility risk the cross-review flagged does not
// apply: a credential with an undefined field inside a checked key (issuer,
// credentialStatus, etc.) cannot be signed by this SDK in the first place.
// The compacted-form check is defense-in-depth for documents signed outside
// this SDK. Decision: keep strict.
func TestSecp256k1_CompactedForm_ObjectIssuerUndefinedField(t *testing.T) {
	const did = "did:example:secp-compacted-undef"
	resolver := testSecpResolver(t, did)

	// "customField" is not defined in credentials/v2 and there is no @vocab.
	raw := []byte(fmt.Sprintf(`{
		"@context": ["https://www.w3.org/ns/credentials/v2"],
		"id": "urn:uuid:secp-compacted-undef-001",
		"type": ["VerifiableCredential"],
		"issuer": {"id": %q, "customField": "val"},
		"validFrom": "2026-01-01T00:00:00Z",
		"credentialSubject": {"id": "did:example:subject"}
	}`, did))

	cred, err := ParseJSONCredential(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Signing itself rejects the undefined term. The signing path uses
	// Canonicalize → ExpandJSONLD (SafeMode), which refuses undefined terms.
	err = cred.AddProofByProvider(
		testSecpProvider(t),
		WithVerificationMethodKey("key-1"),
		WithResolver(resolver),
	)
	if err == nil {
		t.Fatal("expected signing to refuse an undefined term in the issuer object")
	}
	if !containsAny(err.Error(), "invalid property", "canonicalize") {
		t.Fatalf("expected a canonicalization error for the undefined term, got: %v", err)
	}
	t.Logf("signing refused as expected: %v", err)
}

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

// TestVerify_CredentialSubjectSwap checks that a holder cannot swap
// credentialSubject claims via a context alias attack. Because
// ParseJSONCredential requires credentialSubject, we construct the edited
// document as a raw JSON map and re-add a fake credentialSubject to pass
// parsing, while the signed one lives under the alias.
func TestVerify_CredentialSubjectSwap(t *testing.T) {
	raw, resolverOpts := signTestCredential(t)

	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}

	// Move credentialSubject to credentialSubjectX via context alias.
	subj := doc["credentialSubject"]
	delete(doc, "credentialSubject")
	doc["credentialSubjectX"] = subj
	// Add a fake credentialSubject so parsing does not refuse the document.
	doc["credentialSubject"] = map[string]interface{}{
		"id":          "did:example:attacker",
		"permissions": []interface{}{"admin"},
	}
	// Add context alias.
	ctxArr, _ := doc["@context"].([]interface{})
	ctxArr = append(ctxArr, map[string]interface{}{
		"credentialSubjectX": map[string]interface{}{
			"@id": "https://www.w3.org/2018/credentials#credentialSubject",
		},
	})
	doc["@context"] = ctxArr

	edited, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	cred, err := ParseJSONCredential(edited)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	err = cred.Verify(resolverOpts...)
	if err == nil {
		t.Fatal("Verify returned nil — credentialSubject claims swapped via context alias")
	}
	t.Logf("refused as expected: %v", err)
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
