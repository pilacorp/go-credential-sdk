package vc

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
)

func TestParseCredential(t *testing.T) {
	fixedTime, _ := time.Parse(time.RFC3339, "2025-08-05T10:00:00Z")
	validJSON := []byte(`{
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": "urn:uuid:1234",
        "type": ["VerifiableCredential"],
        "issuer": "did:example:issuer",
        "validFrom": "2025-08-05T10:00:00Z",
        "credentialSubject": {"id": "did:example:subject1", "name": "John Doe"},
        "credentialSchema": {"id": "https://example.org/schema/1", "type": "JsonSchemaValidator2019"},
        "credentialStatus": {"id": "https://example.org/status/1", "type": "StatusList2021Entry"},
        "proof": {"type": "Ed25519Signature2020", "created": "2025-08-05T10:00:00Z", "proofValue": "signature"}
    }`)

	tests := []struct {
		name        string
		inputJSON   []byte
		opts        []CredentialOpt
		expected    jsonmap.JSONMap
		expectError bool
		errorMsg    string
	}{
		{
			name:      "Valid credential JSON",
			inputJSON: validJSON,
			opts:      []CredentialOpt{WithDisableValidation()},
			expected: jsonmap.JSONMap{
				"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
				"id":                "urn:uuid:1234",
				"type":              []interface{}{"VerifiableCredential"},
				"issuer":            "did:example:issuer",
				"validFrom":         fixedTime.Format(time.RFC3339),
				"credentialSubject": map[string]interface{}{"id": "did:example:subject1", "name": "John Doe"},
				"credentialSchema":  map[string]interface{}{"id": "https://example.org/schema/1", "type": "JsonSchemaValidator2019"},
				"credentialStatus":  map[string]interface{}{"id": "https://example.org/status/1", "type": "StatusList2021Entry"},
				"proof":             map[string]interface{}{"type": "Ed25519Signature2020", "created": fixedTime.Format(time.RFC3339), "proofValue": "signature"},
			},
			expectError: false,
		},
		{
			name:        "Empty JSON",
			inputJSON:   []byte{},
			opts:        []CredentialOpt{},
			expectError: true,
			errorMsg:    "JSON string is empty",
		},
		{
			name:        "Invalid JSON",
			inputJSON:   []byte(`{invalid}`),
			opts:        []CredentialOpt{},
			expectError: true,
			errorMsg:    "failed to unmarshal credential",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseCredential(tt.inputJSON, tt.opts...)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				return
			}

			assert.NoError(t, err)
			// Check the credential type and access the appropriate field
			if result.Type() == CredentialTypeEmbedded {
				embeddedCred := result.(*EmbededCredential)
				assert.Equal(t, tt.expected, jsonmap.JSONMap(embeddedCred.jsonCredential), "Credential mismatch")
			} else if result.Type() == CredentialTypeJWT {
				jwtCred := result.(*JWTCredential)
				assert.Equal(t, tt.expected, jsonmap.JSONMap(jwtCred.Payload), "Credential mismatch")
			}
		})
	}
}

func TestCreateCredentialWithContents(t *testing.T) {
	tests := []struct {
		name        string
		credType    CredentialType
		input       CredentialContents
		expected    jsonmap.JSONMap
		expectError bool
		errorMsg    string
	}{
		{
			name:     "Valid JWT contents",
			credType: CredentialTypeJWT,
			input: CredentialContents{
				Context: []interface{}{"https://www.w3.org/2018/credentials/v1"},
				ID:      "urn:uuid:1234",
				Issuer:  "did:example:issuer",
			},
			expected: jsonmap.JSONMap{
				"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
				"id":       "urn:uuid:1234",
				"issuer":   "did:example:issuer",
			},
			expectError: false,
		},
		{
			name:     "Valid Embedded contents",
			credType: CredentialTypeEmbedded,
			input: CredentialContents{
				Context: []interface{}{"https://www.w3.org/2018/credentials/v1"},
				ID:      "urn:uuid:1234",
				Issuer:  "did:example:issuer",
			},
			expected: jsonmap.JSONMap{
				"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
				"id":       "urn:uuid:1234",
				"issuer":   "did:example:issuer",
			},
			expectError: false,
		},
		{
			name:        "Empty contents",
			credType:    CredentialTypeJWT,
			input:       CredentialContents{},
			expectError: true,
			errorMsg:    "contents must have context, ID, or issuer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CreateCredentialWithContents(tt.credType, tt.input)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				return
			}

			assert.NoError(t, err)
			// For JWT credentials, we need to check the payload
			if tt.credType == CredentialTypeJWT {
				jwtCred := result.(*JWTCredential)
				assert.Equal(t, tt.expected, jsonmap.JSONMap(jwtCred.Payload), "JWT Credential payload mismatch")
			} else {
				// For embedded credentials, we need to check the jsonCredential
				embeddedCred := result.(*EmbededCredential)
				assert.Equal(t, tt.expected, jsonmap.JSONMap(embeddedCred.jsonCredential), "Embedded Credential mismatch")
			}
		})
	}
}

// TestToJSON removed - JSONCredential doesn't have ToJSON method

// TestParseCredentialContents removed - JSONCredential doesn't have ParseCredentialContents method

func TestParseContext(t *testing.T) {
	tests := []struct {
		name        string
		credential  JSONCredential
		expected    []interface{}
		expectError bool
		errorMsg    string
	}{
		{
			name:       "Valid context",
			credential: JSONCredential(jsonmap.JSONMap{"@context": []interface{}{"https://www.w3.org/2018/credentials/v1", map[string]interface{}{"custom": "context"}}}),
			expected:   []interface{}{"https://www.w3.org/2018/credentials/v1", map[string]interface{}{"custom": "context"}},
		},
		{
			name:        "Invalid context type",
			credential:  JSONCredential(jsonmap.JSONMap{"@context": []interface{}{1}}),
			expectError: true,
			errorMsg:    "unsupported context type: int",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var contents CredentialContents
			err := parseContext(tt.credential, &contents)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, contents.Context)
		})
	}
}

func TestParseID(t *testing.T) {
	credential := JSONCredential(jsonmap.JSONMap{"id": "urn:uuid:1234"})
	var contents CredentialContents
	err := parseID(credential, &contents)
	assert.NoError(t, err)
	assert.Equal(t, "urn:uuid:1234", contents.ID)
}

func TestParseTypes(t *testing.T) {
	tests := []struct {
		name        string
		credential  JSONCredential
		expected    []string
		expectError bool
		errorMsg    string
	}{
		{
			name:       "Single type",
			credential: JSONCredential(jsonmap.JSONMap{"type": "VerifiableCredential"}),
			expected:   []string{"VerifiableCredential"},
		},
		{
			name:       "Multiple types",
			credential: JSONCredential(jsonmap.JSONMap{"type": []interface{}{"VerifiableCredential", "CustomCredential"}}),
			expected:   []string{"VerifiableCredential", "CustomCredential"},
		},
		{
			name:        "Invalid type",
			credential:  JSONCredential(jsonmap.JSONMap{"type": 123}),
			expectError: true,
			errorMsg:    "unsupported type field: int",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var contents CredentialContents
			err := parseTypes(tt.credential, &contents)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, contents.Types)
		})
	}
}

func TestParseIssuer(t *testing.T) {
	credential := JSONCredential(jsonmap.JSONMap{"issuer": "did:example:issuer"})
	var contents CredentialContents
	err := parseIssuer(credential, &contents)
	assert.NoError(t, err)
	assert.Equal(t, "did:example:issuer", contents.Issuer)
}

func TestParseDates(t *testing.T) {
	fixedTime, _ := time.Parse(time.RFC3339, "2025-08-05T10:00:00Z")
	credential := JSONCredential(jsonmap.JSONMap{
		"validFrom":  fixedTime.Format(time.RFC3339),
		"validUntil": fixedTime.Add(24 * time.Hour).Format(time.RFC3339),
	})

	var contents CredentialContents
	err := parseDates(credential, &contents)
	assert.NoError(t, err)
	assert.Equal(t, fixedTime, contents.ValidFrom)
	assert.Equal(t, fixedTime.Add(24*time.Hour), contents.ValidUntil)
}

func TestParseSubject(t *testing.T) {
	tests := []struct {
		name        string
		credential  JSONCredential
		expected    []Subject
		expectError bool
		errorMsg    string
	}{
		{
			name:       "Single subject",
			credential: JSONCredential(jsonmap.JSONMap{"credentialSubject": map[string]interface{}{"id": "did:example:subject1", "name": "John Doe"}}),
			expected:   []Subject{{ID: "did:example:subject1", CustomFields: map[string]interface{}{"name": "John Doe"}}},
		},
		{
			name:       "Multiple subjects",
			credential: JSONCredential(jsonmap.JSONMap{"credentialSubject": []interface{}{map[string]interface{}{"id": "did:example:subject1"}, map[string]interface{}{"id": "did:example:subject2"}}}),
			expected:   []Subject{{ID: "did:example:subject1", CustomFields: map[string]interface{}{}}, {ID: "did:example:subject2", CustomFields: map[string]interface{}{}}},
		},
		{
			name:        "Invalid subject format",
			credential:  JSONCredential(jsonmap.JSONMap{"credentialSubject": 123}),
			expectError: true,
			errorMsg:    "unsupported subject format: int",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var contents CredentialContents
			err := parseSubject(tt.credential, &contents)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, contents.Subject)
		})
	}
}

func TestParseSchema(t *testing.T) {
	credential := JSONCredential(jsonmap.JSONMap{
		"credentialSchema": map[string]interface{}{"id": "https://example.org/schema/1", "type": "JsonSchemaValidator2019"},
	})

	var contents CredentialContents
	err := parseSchema(credential, &contents)
	assert.NoError(t, err)
	assert.Equal(t, []Schema{{ID: "https://example.org/schema/1", Type: "JsonSchemaValidator2019"}}, contents.Schemas)
}

func TestParseStatus(t *testing.T) {
	credential := JSONCredential(jsonmap.JSONMap{
		"credentialStatus": map[string]interface{}{"id": "https://example.org/status/1", "type": "StatusList2021Entry"},
	})

	var contents CredentialContents
	err := parseStatus(credential, &contents)
	assert.NoError(t, err)
	assert.Equal(t, []Status{{ID: "https://example.org/status/1", Type: "StatusList2021Entry"}}, contents.CredentialStatus)
}

func TestParseProofs(t *testing.T) {
	fixedTime, _ := time.Parse(time.RFC3339, "2025-08-05T10:00:00Z")
	credential := JSONCredential(jsonmap.JSONMap{
		"proof": map[string]interface{}{"type": "Ed25519Signature2020", "created": fixedTime.Format(time.RFC3339)},
	})

	var contents CredentialContents
	err := parseProofs(credential, &contents)
	assert.NoError(t, err)
	// Note: parseProofs now returns nil since CredentialContents doesn't have Proofs field
	// The test just verifies no error occurs
}

func TestSubjectFromJSON(t *testing.T) {
	input := jsonmap.JSONMap{"id": "did:example:subject1", "name": "John Doe"}
	expected := Subject{ID: "did:example:subject1", CustomFields: map[string]interface{}{"name": "John Doe"}}

	result, err := SubjectFromJSON(input)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
}

func TestParseStatusEntry(t *testing.T) {
	input := map[string]interface{}{
		"id":                   "https://example.org/status/1",
		"type":                 "StatusList2021Entry",
		"statusPurpose":        "revocation",
		"statusListIndex":      "123",
		"statusListCredential": "https://example.org/credential/1",
	}
	expected := Status{
		ID:                   "https://example.org/status/1",
		Type:                 "StatusList2021Entry",
		StatusPurpose:        "revocation",
		StatusListIndex:      "123",
		StatusListCredential: "https://example.org/credential/1",
	}

	result, err := parseStatusEntry(input)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
}

func TestParseSchemaID(t *testing.T) {
	input := map[string]interface{}{"id": "https://example.org/schema/1", "type": "JsonSchemaValidator2019"}
	expected := Schema{ID: "https://example.org/schema/1", Type: "JsonSchemaValidator2019"}

	result, err := parseSchemaID(input)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
}

func TestParseStringField(t *testing.T) {
	input := jsonmap.JSONMap{"id": "did:example:subject1"}
	result, err := parseStringField(input, "id")
	assert.NoError(t, err)
	assert.Equal(t, "did:example:subject1", result)

	_, err = parseStringField(jsonmap.JSONMap{"id": 123}, "id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "field \"id\" must be a string")
}

func TestCreateCredentialJWT(t *testing.T) {
	// Initialize the credential package
	Init("https://auth-dev.pila.vn/api/v1/did")

	// Test data
	privateKeyHex := "e5c9a597b20e13627a3850d38439b61ec9ee7aefd77c7cb6c01dc3866e1db19a"
	issuerDID := "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce"
	subjectDID := "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbsEYvdrjxMjQ4tpnje9BDBTzuNDP3knn6qLZErzd4bJ5go2CChoPjd5GAH3zpFJP5fuwSk66U5Pq6EhF4nKnHzDnznEP8fX99nZGgwbAh1o7Gj1X52Tdhf7U4KTk66xsA5r"

	// Create credential contents
	credentialContents := CredentialContents{
		Context: []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2",
		},
		ID:     "urn:uuid:jwt-test-credential-12345678",
		Types:  []string{"VerifiableCredential", "EducationalCredential"},
		Issuer: issuerDID,
		ValidFrom: func() time.Time {
			t, _ := time.Parse(time.RFC3339, "2024-01-01T00:00:00Z")
			return t
		}(),
		ValidUntil: func() time.Time {
			t, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
			return t
		}(),
		Subject: []Subject{
			{
				ID: subjectDID,
				CustomFields: map[string]interface{}{
					"name":           "John Doe",
					"degree":         "Bachelor of Science",
					"university":     "Test University",
					"graduationYear": 2023,
				},
			},
		},
		CredentialStatus: []Status{
			{
				ID:              "https://example.org/credentials/status/123",
				Type:            "BitstringStatusListEntry",
				StatusPurpose:   "revocation",
				StatusListIndex: "123",
			},
		},
		Schemas: []Schema{
			{
				ID:   "https://example.org/schemas/educational-credential.json",
				Type: "JsonSchema",
			},
		},
	}

	// Create credential from contents
	credential, err := CreateCredentialWithContents(CredentialTypeJWT, credentialContents)
	assert.NoError(t, err, "Failed to create credential from contents")

	// Add proof to the credential
	err = credential.AddProof(privateKeyHex)
	assert.NoError(t, err, "Failed to add proof to credential")

	// Serialize the credential to get JWT string
	serialized, err := credential.Serialize()
	assert.NoError(t, err, "Failed to serialize credential")
	jwtToken, ok := serialized.(string)
	assert.True(t, ok, "Serialized credential should be a string for JWT")
	assert.NotEmpty(t, jwtToken, "JWT token should not be empty")

	// Verify the JWT token structure (should have 3 parts)
	assert.Equal(t, 3, len(strings.Split(jwtToken, ".")), "JWT should have 3 parts separated by dots")

	// Parse the JWT credential back
	parsedCredential, err := ParseCredentialJWT(jwtToken, WithDisableValidation())
	assert.NoError(t, err, "Failed to parse JWT credential")
	assert.NotNil(t, parsedCredential, "Parsed credential should not be nil")

	// Verify the credential type
	assert.Equal(t, CredentialTypeJWT, parsedCredential.Type(), "Credential type should be JWT")

	// For JWT credentials, we can check the payload directly
	jwtCred := parsedCredential.(*JWTCredential)
	assert.Equal(t, credentialContents.ID, jwtCred.Payload["id"], "Credential ID should match")
	assert.Equal(t, credentialContents.Issuer, jwtCred.Payload["issuer"], "Issuer should match")
}
