package verificationmethod

import (
	"testing"
	"time"
)

func TestSelectVMForPurpose_AcceptsKidForms(t *testing.T) {
	const did = "did:pila:abc123"
	doc := &DIDDocument{
		ID: did,
		VerificationMethod: []VerificationMethodEntry{
			{ID: did + "#key-1", Type: "EcdsaSecp256k1VerificationKey2019", Controller: did},
			{ID: did + "#key-2", Type: "EcdsaSecp256k1VerificationKey2019", Controller: did},
		},
		Authentication:  []string{did + "#key-1", did + "#key-2"},
		AssertionMethod: []string{did + "#key-1"},
	}

	tests := []struct {
		name   string
		kid    string
		wantID string
	}{
		{"full URL", did + "#key-1", did + "#key-1"},
		{"hash fragment", "#key-2", did + "#key-2"},
		{"bare fragment", "key-2", did + "#key-2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vm, err := SelectVMForPurpose(doc, "authentication", tt.kid)
			if err != nil {
				t.Fatalf("SelectVMForPurpose(%q) err: %v", tt.kid, err)
			}
			if vm.ID != tt.wantID {
				t.Errorf("SelectVMForPurpose(%q) returned %q, want %q", tt.kid, vm.ID, tt.wantID)
			}
		})
	}
}

func TestSelectVMForPurpose_NotFound(t *testing.T) {
	const did = "did:pila:abc123"
	doc := &DIDDocument{
		ID: did,
		VerificationMethod: []VerificationMethodEntry{
			{ID: did + "#key-1", Type: "EcdsaSecp256k1VerificationKey2019", Controller: did},
		},
		Authentication: []string{did + "#key-1"},
	}

	if _, err := SelectVMForPurpose(doc, "authentication", "#key-9"); err == nil {
		t.Fatalf("expected error for unknown kid")
	}
}

func TestSelectVMForPurpose_EmptyKidFallsBackToLatest(t *testing.T) {
	const did = "did:pila:abc123"
	doc := &DIDDocument{
		ID: did,
		VerificationMethod: []VerificationMethodEntry{
			{ID: did + "#key-1", Type: "EcdsaSecp256k1VerificationKey2019", Controller: did},
			{ID: did + "#key-2", Type: "EcdsaSecp256k1VerificationKey2019", Controller: did},
		},
		Authentication: []string{did + "#key-1", did + "#key-2"},
	}

	vm, err := SelectVMForPurpose(doc, "authentication", "")
	if err != nil {
		t.Fatalf("SelectVMForPurpose err: %v", err)
	}
	if vm.ID != did+"#key-2" {
		t.Errorf("expected latest key #key-2, got %q", vm.ID)
	}
}

func TestVMHelpers_NilVMDoesNotPanic(t *testing.T) {
	if VMIsRSA(nil) || VMIsP256(nil) || VMIsSecp256k1(nil) {
		t.Fatal("nil VM must not match any key kind")
	}
	if _, ok := VMKeyKind(nil); ok {
		t.Fatal("VMKeyKind(nil) must report unrecognized")
	}
	if vmMatchesKind(nil, KeyP256) {
		t.Fatal("vmMatchesKind(nil, ...) must be false")
	}
}

func TestEnsureVMAuthorizedForPurpose_NilDoc(t *testing.T) {
	if err := EnsureVMAuthorizedForPurpose(nil, "did:x:y#key-1", "assertionMethod"); err == nil {
		t.Fatal("expected error for nil DID document")
	}
}

// A key past its expires time is not picked for signing even when it has the
// highest #key-N: the latest live key is chosen instead (CID 1.0 §2.2).
func TestSelectLatestActiveVMForPurpose_SkipsExpired(t *testing.T) {
	const did = "did:pila:abc123"
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	doc := &DIDDocument{
		ID: did,
		VerificationMethod: []VerificationMethodEntry{
			{ID: did + "#key-1", Type: "EcdsaSecp256k1VerificationKey2019", Controller: did, Expires: &future},
			{ID: did + "#key-2", Type: "EcdsaSecp256k1VerificationKey2019", Controller: did, Expires: &past},
		},
		AssertionMethod: []string{did + "#key-1", did + "#key-2"},
	}

	vm, err := SelectLatestActiveVMForPurpose(doc, "assertionMethod")
	if err != nil {
		t.Fatal(err)
	}
	if vm.ID != did+"#key-1" {
		t.Fatalf("picked %s, want the live %s#key-1", vm.ID, did)
	}

	doc.VerificationMethod[0].Expires = &past
	if _, err := SelectLatestActiveVMForPurpose(doc, "assertionMethod"); err == nil {
		t.Fatal("picked a key although every key has expired")
	}
}
