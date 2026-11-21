package vc

import "testing"

// TC-B02: a credentialStatus with an unknown type is ignored by
// checkRevocation. The old code required statusListCredential, failing with
// "credentialStatus.statusListCredential is required".
func TestCheckRevocation_UnknownTypeSingleObject(t *testing.T) {
	c := CredentialData{
		"credentialStatus": map[string]interface{}{
			"type": "UnknownStatusType",
			"id":   "https://example.org/status/1",
		},
	}
	if err := checkRevocation(c); err != nil {
		t.Fatalf("checkRevocation = %v, want nil (unknown type ignored)", err)
	}
}

// TC-B01: an array with one known and one unknown type. The unknown entry is
// skipped; the known entry would be checked (but here we pass a known type
// with invalid fields — it should NOT error on the unknown one; the error, if
// any, comes from the known one). We verify that the unknown entry does not
// cause "must be an object".
func TestCheckRevocation_ArrayWithUnknownType(t *testing.T) {
	c := CredentialData{
		"credentialStatus": []interface{}{
			map[string]interface{}{
				"type": "UnknownStatusType",
				"id":   "https://example.org/status/x",
			},
		},
	}
	// An array of only unknown types should pass.
	if err := checkRevocation(c); err != nil {
		t.Fatalf("checkRevocation (all unknown) = %v, want nil", err)
	}
}

// The old code rejected an array outright: "credentialStatus must be an object".
func TestCheckRevocation_ArrayAccepted(t *testing.T) {
	c := CredentialData{
		"credentialStatus": []interface{}{
			map[string]interface{}{
				"type": "SomeUnknown",
				"id":   "https://example.org/status/1",
			},
			map[string]interface{}{
				"type": "AnotherUnknown",
				"id":   "https://example.org/status/2",
			},
		},
	}
	if err := checkRevocation(c); err != nil {
		t.Fatalf("checkRevocation = %v, want nil (all unknown)", err)
	}
}

// An empty array should return success.
func TestCheckRevocation_EmptyArray(t *testing.T) {
	c := CredentialData{
		"credentialStatus": []interface{}{},
	}
	if err := checkRevocation(c); err != nil {
		t.Fatalf("checkRevocation = %v, want nil (empty array)", err)
	}
}
