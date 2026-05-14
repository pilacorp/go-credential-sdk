package did

import (
	"testing"
	"time"
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
