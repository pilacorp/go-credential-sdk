package verificationmethod

import (
	"encoding/json"
	"testing"
)

// TC-B07: DID document with embedded VM in assertionMethod.
func TestDIDDocument_UnmarshalEmbeddedVM(t *testing.T) {
	doc := `{
		"@context": ["https://www.w3.org/ns/did/v1"],
		"id": "did:example:emb",
		"verificationMethod": [],
		"assertionMethod": [
			{
				"id": "did:example:emb#k1",
				"type": "JsonWebKey",
				"controller": "did:example:emb",
				"publicKeyJwk": {"kty":"EC","crv":"P-256","x":"abc","y":"def"}
			}
		],
		"authentication": [
			"did:example:emb#k2",
			{
				"id": "did:example:emb#k3",
				"type": "JsonWebKey",
				"controller": "did:example:emb",
				"publicKeyJwk": {"kty":"EC","crv":"P-256","x":"ghi","y":"jkl"}
			}
		]
	}`

	var d DIDDocument
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// assertionMethod should contain the id string.
	if len(d.AssertionMethod) != 1 || d.AssertionMethod[0] != "did:example:emb#k1" {
		t.Fatalf("AssertionMethod = %v, want [did:example:emb#k1]", d.AssertionMethod)
	}

	// authentication should contain the string and the extracted id.
	if len(d.Authentication) != 2 {
		t.Fatalf("Authentication len = %d, want 2", len(d.Authentication))
	}
	if d.Authentication[0] != "did:example:emb#k2" {
		t.Errorf("Authentication[0] = %q, want did:example:emb#k2", d.Authentication[0])
	}
	if d.Authentication[1] != "did:example:emb#k3" {
		t.Errorf("Authentication[1] = %q, want did:example:emb#k3", d.Authentication[1])
	}

	// The embedded VMs should appear in VerificationMethod.
	found := map[string]bool{}
	for _, vm := range d.VerificationMethod {
		found[vm.ID] = true
	}
	if !found["did:example:emb#k1"] {
		t.Error("embedded VM did:example:emb#k1 not in VerificationMethod")
	}
	if !found["did:example:emb#k3"] {
		t.Error("embedded VM did:example:emb#k3 not in VerificationMethod")
	}

	// FindVerificationMethod should find the embedded VMs.
	vm, err := FindVerificationMethod(&d, "did:example:emb#k1")
	if err != nil {
		t.Fatalf("FindVerificationMethod(k1): %v", err)
	}
	if vm.Type != "JsonWebKey" || vm.PublicKeyJwk == nil {
		t.Errorf("VM k1 = %+v, want JsonWebKey with publicKeyJwk", vm)
	}
}

// A document with only string references should still unmarshal.
func TestDIDDocument_UnmarshalStringOnlyRelationships(t *testing.T) {
	doc := `{
		"@context": ["https://www.w3.org/ns/did/v1"],
		"id": "did:example:str",
		"verificationMethod": [
			{"id": "did:example:str#k1", "type": "JsonWebKey", "controller": "did:example:str"}
		],
		"assertionMethod": ["did:example:str#k1"],
		"authentication": ["did:example:str#k1"]
	}`
	var d DIDDocument
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(d.AssertionMethod) != 1 || d.AssertionMethod[0] != "did:example:str#k1" {
		t.Fatalf("AssertionMethod = %v, want [did:example:str#k1]", d.AssertionMethod)
	}
}

// Marshal round-trip: relationship arrays are written as string arrays.
func TestDIDDocument_MarshalRelationships(t *testing.T) {
	d := DIDDocument{
		Context:         []string{"https://www.w3.org/ns/did/v1"},
		ID:              "did:example:rt",
		AssertionMethod: []string{"did:example:rt#k1"},
		Authentication:  []string{"did:example:rt#k2"},
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	// assertionMethod should be an array of strings.
	arr, ok := m["assertionMethod"].([]interface{})
	if !ok || len(arr) != 1 {
		t.Fatalf("assertionMethod = %v", m["assertionMethod"])
	}
	if s, ok := arr[0].(string); !ok || s != "did:example:rt#k1" {
		t.Errorf("assertionMethod[0] = %v, want did:example:rt#k1", arr[0])
	}
}
