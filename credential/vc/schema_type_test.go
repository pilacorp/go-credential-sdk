package vc

import (
	"fmt"
	"strings"
	"testing"
)

// TC-B03 / AC-B03: credentialSchema with an unknown type must be SKIPPED,
// not validated as JSON Schema. The loader errors for the unknown entry;
// old code calls it and fails, new code skips it.
func TestValidateCredential_UnknownSchemaTypeSkipped(t *testing.T) {
	c := CredentialData{
		"@context":          []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":              []interface{}{"VerifiableCredential"},
		"issuer":            "did:example:issuer",
		"credentialSubject": map[string]interface{}{"id": "did:example:subject"},
		"credentialSchema": []interface{}{
			map[string]interface{}{
				"type": "JsonSchema",
				"id":   "https://example.org/schema/known",
			},
			map[string]interface{}{
				"type": "UnknownType",
				"id":   "https://example.org/schema/unknown",
			},
		},
	}
	opts := &credentialOptions{
		loadedSchemaLoader: func(id string) ([]byte, error) {
			if strings.Contains(id, "unknown") {
				return nil, fmt.Errorf("should not be called for unknown type")
			}
			return []byte(`{"type": "object"}`), nil
		},
	}
	err := validateCredential(c, opts)
	if err != nil {
		t.Fatalf("validateCredential = %v, want nil (unknown type skipped)", err)
	}
}

// TC-B03 / AC-B04: when ALL schemas have unknown types, validation succeeds.
// VC-JOSE-COSE §5.4: "If the extension mechanism type is not understood, this
// property MUST be ignored." — there is nothing to reject.
func TestValidateCredential_AllUnknownSchemaTypesSucceeds(t *testing.T) {
	c := CredentialData{
		"@context":          []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":              []interface{}{"VerifiableCredential"},
		"issuer":            "did:example:issuer",
		"credentialSubject": map[string]interface{}{"id": "did:example:subject"},
		"credentialSchema": map[string]interface{}{
			"type": "UnknownSchemaType",
			"id":   "https://example.org/schema/1",
		},
	}
	// Use a loader that would succeed; the unknown type is skipped entirely.
	opts := &credentialOptions{
		loadedSchemaLoader: func(id string) ([]byte, error) {
			return []byte(`{"type": "object"}`), nil
		},
	}
	if err := validateCredential(c, opts); err != nil {
		t.Fatalf("validateCredential with all unknown schema types = %v, want nil", err)
	}
}

// Regression guard: a known type like JsonSchema still validates.
func TestValidateCredential_KnownTypeJsonSchema(t *testing.T) {
	c := CredentialData{
		"@context":          []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":              []interface{}{"VerifiableCredential"},
		"issuer":            "did:example:issuer",
		"credentialSubject": map[string]interface{}{"id": "did:example:subject"},
		"credentialSchema": map[string]interface{}{
			"type": "JsonSchema",
			"id":   "https://example.org/schema/1",
		},
	}
	opts := &credentialOptions{
		loadedSchemaLoader: func(id string) ([]byte, error) {
			return []byte(`{"type": "object"}`), nil
		},
	}
	if err := validateCredential(c, opts); err != nil {
		t.Fatalf("validateCredential with JsonSchema = %v, want nil", err)
	}
}

// Regression guard: JsonSchemaValidator2018 is also a known type.
func TestValidateCredential_KnownTypeJsonSchemaValidator2018(t *testing.T) {
	c := CredentialData{
		"@context":          []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":              []interface{}{"VerifiableCredential"},
		"issuer":            "did:example:issuer",
		"credentialSubject": map[string]interface{}{"id": "did:example:subject"},
		"credentialSchema": map[string]interface{}{
			"type": "JsonSchemaValidator2018",
			"id":   "https://example.org/schema/1",
		},
	}
	opts := &credentialOptions{
		loadedSchemaLoader: func(id string) ([]byte, error) {
			return []byte(`{"type": "object"}`), nil
		},
	}
	if err := validateCredential(c, opts); err != nil {
		t.Fatalf("validateCredential with JsonSchemaValidator2018 = %v, want nil", err)
	}
}
