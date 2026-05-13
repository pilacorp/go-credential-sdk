package verificationmethod

import "testing"

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
