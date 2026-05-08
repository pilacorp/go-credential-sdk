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

func TestUpdateVerificationMethodPurposes_RejectUnknownKid(t *testing.T) {
	doc := GenerateDIDDocument("0x02", "did:nda:0x0000000000000000000000000000000000000001", "", "did:nda:0xissuer", DIDTypePeople, nil)

	if err := doc.UpdateVerificationMethodPurposes(doc.Id+"#key-9", []VerificationPurpose{PurposeAuthentication}, nil); err == nil {
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
