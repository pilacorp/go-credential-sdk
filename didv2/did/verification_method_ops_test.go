package did

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestAddVerificationMethod_AssignsSequentialID(t *testing.T) {
	doc := GenerateDIDDocument("0x02", "did:nda:0x0000000000000000000000000000000000000001", "", "did:nda:0xissuer", DIDTypePeople, nil)

	id, err := doc.AddVerificationMethod(VerificationMethod{
		PublicKeyHex: "0x03",
	}, []VerificationPurpose{PurposeAuthentication})
	if err != nil {
		t.Fatalf("AddVerificationMethod err: %v", err)
	}
	if id != doc.Id+"#key-2" {
		t.Fatalf("expected #key-2, got %s", id)
	}
}

func TestAddVerificationMethodPurposes_RejectUnknownKid(t *testing.T) {
	doc := GenerateDIDDocument("0x02", "did:nda:0x0000000000000000000000000000000000000001", "", "did:nda:0xissuer", DIDTypePeople, nil)

	if err := doc.AddVerificationMethodPurposes(doc.Id+"#key-9", []VerificationPurpose{PurposeAuthentication}); err == nil {
		t.Fatalf("expected error")
	}
}

func TestRemoveVerificationMethodPurposes_RejectUnknownKid(t *testing.T) {
	doc := GenerateDIDDocument("0x02", "did:nda:0x0000000000000000000000000000000000000001", "", "did:nda:0xissuer", DIDTypePeople, nil)

	if err := doc.RemoveVerificationMethodPurposes(doc.Id+"#key-9", []VerificationPurpose{PurposeAuthentication}); err == nil {
		t.Fatalf("expected error")
	}
}

func TestRotateVerificationMethod_CopiesPurposesAndRevokesOld(t *testing.T) {
	doc := GenerateDIDDocument("0x02", "did:nda:0x0000000000000000000000000000000000000001", "", "did:nda:0xissuer", DIDTypePeople, nil)

	old := doc.Id + "#key-1"
	newID, err := doc.RotateVerificationMethod(old, VerificationMethod{PublicKeyHex: "0x04"}, "superseded", time.Now().UTC())
	if err != nil {
		t.Fatalf("RotateVerificationMethod err: %v", err)
	}
	if newID != doc.Id+"#key-2" {
		t.Fatalf("expected #key-2, got %s", newID)
	}
	if doc.FindVerificationMethod(old).Revoked == nil {
		t.Fatalf("expected old key revoked")
	}
	if !containsKidRef(doc.Authentication, newID, doc.Id) {
		t.Fatalf("expected new key in authentication")
	}
	if !containsKidRef(doc.AssertionMethod, newID, doc.Id) {
		t.Fatalf("expected new key in assertionMethod")
	}
}

// TestAddPurposes_DedupesFragmentAndFull guards against duplicate refs when
// a caller adds a purpose using a fragment kid that already exists as the
// canonical full-URL form (or vice versa). Each VM must appear at most once
// in any relationship array.
func TestAddPurposes_DedupesFragmentAndFull(t *testing.T) {
	doc := GenerateDIDDocument("0x02", "did:nda:0x0000000000000000000000000000000000000001", "", "did:nda:0xissuer", DIDTypePeople, nil)

	// #key-1 is already in both arrays (full URL form, from GenerateDIDDocument).
	// Adding again via fragment must NOT duplicate.
	if err := doc.AddVerificationMethodPurposes("#key-1", []VerificationPurpose{PurposeAuthentication, PurposeAssertionMethod}); err != nil {
		t.Fatalf("AddVerificationMethodPurposes err: %v", err)
	}
	if len(doc.Authentication) != 1 {
		t.Fatalf("authentication: expected 1 entry, got %d: %v", len(doc.Authentication), doc.Authentication)
	}
	if len(doc.AssertionMethod) != 1 {
		t.Fatalf("assertionMethod: expected 1 entry, got %d: %v", len(doc.AssertionMethod), doc.AssertionMethod)
	}
}

// TestAddPurposes_NormalizesToFullURL guards that any add op writes the
// canonical full-URL form, never the fragment shorthand, regardless of how
// the caller supplied the kid.
func TestAddPurposes_NormalizesToFullURL(t *testing.T) {
	doc := GenerateDIDDocument("0x02", "did:nda:0x0000000000000000000000000000000000000001", "", "did:nda:0xissuer", DIDTypePeople, nil)

	// Add a 2nd VM without any purpose, then grant via fragment kid.
	id, err := doc.AddVerificationMethod(VerificationMethod{PublicKeyHex: "0x03"}, nil)
	if err != nil {
		t.Fatalf("AddVerificationMethod err: %v", err)
	}
	if err := doc.AddVerificationMethodPurposes("#key-2", []VerificationPurpose{PurposeAuthentication}); err != nil {
		t.Fatalf("AddVerificationMethodPurposes err: %v", err)
	}

	// Authentication must contain only canonical full-URL references.
	for _, ref := range doc.Authentication {
		if !startsWithDID(ref, doc.Id+"#") {
			t.Fatalf("expected canonical full-URL ref, got fragment-form: %s", ref)
		}
	}

	// And the new VM must be present exactly once.
	count := 0
	for _, ref := range doc.Authentication {
		if ref == id {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 entry for %s, got %d", id, count)
	}
}

// TestRemovePurpose_MatchesFragmentAndFull guards that the kid passed to
// remove resolves both fragment and full-URL refs already in the array,
// rather than only the exact string the caller supplied.
func TestRemovePurpose_MatchesFragmentAndFull(t *testing.T) {
	doc := GenerateDIDDocument("0x02", "did:nda:0x0000000000000000000000000000000000000001", "", "did:nda:0xissuer", DIDTypePeople, nil)

	// Caller passes fragment; array currently holds the canonical full URL.
	if err := doc.RemoveVerificationMethodPurposes("#key-1", []VerificationPurpose{PurposeAuthentication}); err != nil {
		t.Fatalf("RemoveVerificationMethodPurposes err: %v", err)
	}
	if len(doc.Authentication) != 0 {
		t.Fatalf("expected authentication empty after remove, got %v", doc.Authentication)
	}
}

// TestRotate_NoDuplicateAfterPurposeReplacement guards against the rotate
// flow producing duplicate refs when both AddVerificationMethod (which wrote
// the new kid into the relationship arrays) and replacePurposeRefs (which
// rewrites oldID → newID) touch the same array.
func TestRotate_NoDuplicateAfterPurposeReplacement(t *testing.T) {
	doc := GenerateDIDDocument("0x02", "did:nda:0x0000000000000000000000000000000000000001", "", "did:nda:0xissuer", DIDTypePeople, nil)

	old := doc.Id + "#key-1"
	newID, err := doc.RotateVerificationMethod(old, VerificationMethod{PublicKeyHex: "0x04"}, "superseded", time.Now().UTC())
	if err != nil {
		t.Fatalf("RotateVerificationMethod err: %v", err)
	}

	for _, arr := range [][]string{doc.Authentication, doc.AssertionMethod} {
		count := 0
		for _, ref := range arr {
			if ref == newID {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("expected new ID %s exactly once, got %d in %v", newID, count, arr)
		}
	}
}

// startsWithDID is a tiny test helper to assert a ref is in canonical form.
func startsWithDID(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// mixedDoc builds a document that carries both key material kinds, mirroring
// what GenerateDID publishes: #key-1 secp256k1 hex, #key-2 P-256 Multikey.
func mixedDoc(t *testing.T) *DIDDocument {
	t.Helper()

	p256, err := NewP256MultikeyVM(testDID, "#key-2", p256PubFromSecretMultibase(t, w3cP256SecretMultibase))
	if err != nil {
		t.Fatalf("NewP256MultikeyVM: %v", err)
	}
	return GenerateDIDDocument("0x02aa", testDID, "", testIssuer, DIDTypePeople, nil, NewSpec(p256))
}

// TestAddVerificationMethod_AcceptsMultikey guards that a P-256 Multikey VM
// can be added to a document that already holds a secp256k1 VM — the whole
// point of a mixed verificationMethod list.
func TestAddVerificationMethod_AcceptsMultikey(t *testing.T) {
	doc := mixedDoc(t)

	vm, err := NewP256MultikeyVM(doc.Id, "#key-3", freshP256Pub(t))
	if err != nil {
		t.Fatalf("NewP256MultikeyVM: %v", err)
	}
	vm.Type = ""

	id, err := doc.AddVerificationMethod(vm, []VerificationPurpose{PurposeAssertionMethod})
	if err != nil {
		t.Fatalf("AddVerificationMethod: %v", err)
	}
	added := doc.FindVerificationMethod(id)
	if added == nil {
		t.Fatalf("added VM not found: %s", id)
	}
	if added.Type != multikeyVMType {
		t.Fatalf("expected type %s defaulted from multibase, got %s", multikeyVMType, added.Type)
	}
	if added.PublicKeyHex != "" {
		t.Fatalf("Multikey VM must not carry hex: %q", added.PublicKeyHex)
	}
	if !containsKidRef(doc.AssertionMethod, id, doc.Id) {
		t.Fatalf("expected %s in assertionMethod", id)
	}
}

// TestAddVerificationMethod_RejectsAmbiguousKeyMaterial guards the mutual
// exclusivity declared on VerificationMethod, and that the deprecated
// publicKeyJwk is not accepted — only secp256k1 hex and P-256 Multikey are.
func TestAddVerificationMethod_RejectsAmbiguousKeyMaterial(t *testing.T) {
	doc := mixedDoc(t)

	for name, vm := range map[string]VerificationMethod{
		"none": {},
		"hex+multibase": {
			PublicKeyHex:       "0x03aa",
			PublicKeyMultibase: w3cP256PublicMultibase,
		},
		"deprecated jwk": {
			PublicKeyJwk: map[string]any{"kty": "EC", "crv": "P-256"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := doc.AddVerificationMethod(vm, nil); err == nil {
				t.Fatalf("expected error for %s key material", name)
			}
		})
	}
}

// TestAddVerificationMethod_DuplicateKeyPerField guards that duplicate
// detection compares the right field, and that an empty field never counts as
// a match against another VM's empty field.
func TestAddVerificationMethod_DuplicateKeyPerField(t *testing.T) {
	doc := mixedDoc(t)

	dup, err := NewP256MultikeyVM(doc.Id, "#key-9", p256PubFromSecretMultibase(t, w3cP256SecretMultibase))
	if err != nil {
		t.Fatalf("NewP256MultikeyVM: %v", err)
	}
	if _, err := doc.AddVerificationMethod(dup, nil); err == nil {
		t.Fatalf("expected duplicate multibase key to be rejected")
	}

	// A fresh multibase key must still go in: the secp VM's empty multibase
	// field must not match anything.
	fresh, err := NewP256MultikeyVM(doc.Id, "", freshP256Pub(t))
	if err != nil {
		t.Fatalf("NewP256MultikeyVM: %v", err)
	}
	fresh.Id = ""
	if _, err := doc.AddVerificationMethod(fresh, nil); err != nil {
		t.Fatalf("expected distinct multibase key to be accepted: %v", err)
	}
}

// TestAddVerificationMethod_DuplicateSecpAcrossEncodings guards that the same
// secp256k1 key does not slip in twice as compressed and uncompressed hex.
func TestAddVerificationMethod_DuplicateSecpAcrossEncodings(t *testing.T) {
	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	compressed := hex.EncodeToString(crypto.CompressPubkey(&priv.PublicKey))
	uncompressed := hex.EncodeToString(crypto.FromECDSAPub(&priv.PublicKey))

	doc := GenerateDIDDocument("0x"+compressed, testDID, "", testIssuer, DIDTypePeople, nil)

	if _, err := doc.AddVerificationMethod(VerificationMethod{PublicKeyHex: "0x" + uncompressed}, nil); err == nil {
		t.Fatalf("expected the same key in uncompressed form to be rejected")
	}
}

// TestRotateVerificationMethod_RejectsKeyMaterialChange guards that a rotation
// keeps the suite relying parties expect.
func TestRotateVerificationMethod_RejectsKeyMaterialChange(t *testing.T) {
	doc := mixedDoc(t)

	newVM, err := NewP256MultikeyVM(doc.Id, "#key-3", freshP256Pub(t))
	if err != nil {
		t.Fatalf("NewP256MultikeyVM: %v", err)
	}
	if _, err := doc.RotateVerificationMethod("#key-1", newVM, "superseded", time.Time{}); err == nil {
		t.Fatalf("expected secp256k1 -> Multikey rotation to be rejected")
	}
}

// TestAddVerificationMethodPurposes_RejectsRevoked guards that a retired key
// cannot be handed new purposes.
func TestAddVerificationMethodPurposes_RejectsRevoked(t *testing.T) {
	doc := mixedDoc(t)

	if err := doc.RevokeVerificationMethod("#key-2", "superseded", time.Time{}); err != nil {
		t.Fatalf("RevokeVerificationMethod: %v", err)
	}
	if err := doc.AddVerificationMethodPurposes("#key-2", []VerificationPurpose{PurposeAuthentication}); err == nil {
		t.Fatalf("expected revoked VM to reject new purposes")
	}
}

// TestAddVerificationMethod_UnsupportedPurposeLeavesDocUntouched guards that a
// rejected call does not append the VM anyway.
func TestAddVerificationMethod_UnsupportedPurposeLeavesDocUntouched(t *testing.T) {
	doc := mixedDoc(t)
	before := len(doc.VerificationMethod)

	if _, err := doc.AddVerificationMethod(VerificationMethod{PublicKeyHex: "0x03aa"}, []VerificationPurpose{"keyAgreement"}); err == nil {
		t.Fatalf("expected unsupported purpose to be rejected")
	}
	if len(doc.VerificationMethod) != before {
		t.Fatalf("document mutated by a failed add: %d -> %d VMs", before, len(doc.VerificationMethod))
	}
}

// freshP256Pub returns a random P-256 public key, distinct from the W3C vector.
func freshP256Pub(t *testing.T) *ecdsa.PublicKey {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	return &priv.PublicKey
}

// TestAddVerificationMethod_RejectsTypeKeyMaterialMismatch guards that a
// caller-supplied type cannot contradict the key material it is published
// with — a Multikey VM labelled secp256k1 would send verifiers to the wrong
// suite.
func TestAddVerificationMethod_RejectsTypeKeyMaterialMismatch(t *testing.T) {
	doc := mixedDoc(t)

	vm, err := NewP256MultikeyVM(doc.Id, "#key-3", freshP256Pub(t))
	if err != nil {
		t.Fatalf("NewP256MultikeyVM: %v", err)
	}
	vm.Type = secp256k1VMType

	if _, err := doc.AddVerificationMethod(vm, nil); err == nil {
		t.Fatalf("expected a Multikey VM typed as secp256k1 to be rejected")
	}

	// The matching type stays accepted.
	vm.Type = multikeyVMType
	if _, err := doc.AddVerificationMethod(vm, nil); err != nil {
		t.Fatalf("AddVerificationMethod with matching type: %v", err)
	}
}
