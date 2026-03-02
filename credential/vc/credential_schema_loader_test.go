package vc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateCredential_WithCustomSchemaLoader_Succeeds(t *testing.T) {
	// Minimal credential that satisfies validateCredential's required keys.
	cred := CredentialData{
		"type": []interface{}{"VerifiableCredential"},
		"credentialSubject": map[string]interface{}{
			"id": "did:example:123",
		},
		"credentialSchema": map[string]interface{}{
			"id":   "https://example.org/schema/1",
			"type": "JsonSchema",
		},
	}

	// Schema that accepts any object.
	schemaJSON := []byte(`{"type":"object"}`)

	opts := getOptions(
		WithSchemaValidation(),
		WithSchemaLoader(func(schemaID string) ([]byte, error) {
			assert.Equal(t, "https://example.org/schema/1", schemaID)
			return schemaJSON, nil
		}),
	)

	err := validateCredential(cred, opts)
	assert.NoError(t, err)
}

func TestValidateCredential_WithCustomSchemaLoader_EmptySchemaFails(t *testing.T) {
	cred := CredentialData{
		"type": []interface{}{"VerifiableCredential"},
		"credentialSubject": map[string]interface{}{
			"id": "did:example:123",
		},
		"credentialSchema": map[string]interface{}{
			"id":   "https://example.org/schema/1",
			"type": "JsonSchema",
		},
	}

	opts := getOptions(
		WithSchemaValidation(),
		WithSchemaLoader(func(schemaID string) ([]byte, error) {
			return []byte{}, nil
		}),
	)

	err := validateCredential(cred, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "schema is empty")
}

