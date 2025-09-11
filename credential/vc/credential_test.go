package vc

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/jwt"
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
	validJWTtoken := "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHg4YjNiMWRlZThlMDBjYjk1ZjhiMmExZDFhOWE3Y2I4ZmU3ZDQ5MGNlI2tleS0xIiwidHlwIjoiSldUIn0.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vZXhhbXBsZS5vcmcvc2NoZW1hcy9lZHVjYXRpb25hbC1jcmVkZW50aWFsLmpzb24iLCJ0eXBlIjoiSnNvblNjaGVtYSJ9LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiaHR0cHM6Ly9leGFtcGxlLm9yZy9jcmVkZW50aWFscy9zdGF0dXMvMTIzIiwic3RhdHVzTGlzdEluZGV4IjoiMTIzIiwic3RhdHVzUHVycG9zZSI6InJldm9jYXRpb24iLCJ0eXBlIjoiQml0c3RyaW5nU3RhdHVzTGlzdEVudHJ5In0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImRlZ3JlZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UiLCJncmFkdWF0aW9uWWVhciI6MjAyMywiaWQiOiJkaWQ6a2V5OnoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BnWW95dHlrVVozZXlxaHQxajlLYnNFWXZkcmp4TWpRNHRwbmplOUJEQlR6dU5EUDNrbm42cUxaRXJ6ZDRiSjVnbzJDQ2hvUGpkNUdBSDN6cEZKUDVmdXdTazY2VTVQcTZFaEY0bktuSHpEbnpuRVA4Zlg5OW5aR2d3YkFoMW83R2oxWDUyVGRoZjdVNEtUazY2eHNBNXIiLCJuYW1lIjoiSm9obiBEb2UiLCJ1bml2ZXJzaXR5IjoiVGVzdCBVbml2ZXJzaXR5In0sImlkIjoidXJuOnV1aWQ6c2lnbmF0dXJlLXRlc3QtY3JlZGVudGlhbC0xMjM0NTY3OCIsImlzc3VlciI6ImRpZDpuZGE6dGVzdG5ldDoweDhiM2IxZGVlOGUwMGNiOTVmOGIyYTFkMWE5YTdjYjhmZTdkNDkwY2UiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRWR1Y2F0aW9uYWxDcmVkZW50aWFsIl0sInZhbGlkRnJvbSI6IjIwMjQtMDEtMDFUMDA6MDA6MDBaIiwidmFsaWRVbnRpbCI6IjIwMjUtMDEtMDFUMDA6MDA6MDBaIn19.aDZAa9pMUFaK5F0LE1S9B-ZL1814OwFaQNKvNr5G-HQTPLPNkIFB0ii9fTeDFMQXUiuEf09oBa7s0k0IHdrP0w"

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
			errorMsg:    "failed to parse credential",
		},
		{
			name:        "Valid Educational Credential",
			inputJSON:   []byte(validJWTtoken),
			opts:        []CredentialOpt{WithDisableValidation()},
			expectError: false,
			expected: jsonmap.JSONMap{
				"@context": []interface{}{
					"https://www.w3.org/ns/credentials/v2",
					"https://www.w3.org/ns/credentials/examples/v2",
				},
				"id":         "urn:uuid:signature-test-credential-12345678",
				"type":       []interface{}{"VerifiableCredential", "EducationalCredential"},
				"issuer":     "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce",
				"validFrom":  "2024-01-01T00:00:00Z",
				"validUntil": "2025-01-01T00:00:00Z",
				"credentialSubject": map[string]interface{}{
					"degree":         "Bachelor of Science",
					"graduationYear": float64(2023),
					"id":             "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbsEYvdrjxMjQ4tpnje9BDBTzuNDP3knn6qLZErzd4bJ5go2CChoPjd5GAH3zpFJP5fuwSk66U5Pq6EhF4nKnHzDnznEP8fX99nZGgwbAh1o7Gj1X52Tdhf7U4KTk66xsA5r",
					"name":           "John Doe",
					"university":     "Test University",
				},
				"credentialSchema": map[string]interface{}{
					"id":   "https://example.org/schemas/educational-credential.json",
					"type": "JsonSchema",
				},
				"credentialStatus": map[string]interface{}{
					"id":              "https://example.org/credentials/status/123",
					"statusListIndex": "123",
					"statusPurpose":   "revocation",
					"type":            "BitstringStatusListEntry",
				},
			},
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
			if _, ok := result.(*EmbededCredential); ok {
				embeddedCred := result.(*EmbededCredential)
				assert.Equal(t, tt.expected, jsonmap.JSONMap(embeddedCred.jsonCredential), "Credential mismatch")
			} else if _, ok := result.(*JWTCredential); ok {
				jwtCred := result.(*JWTCredential)
				assert.Equal(t, tt.expected, jsonmap.JSONMap(jwtCred.Payload), "Credential mismatch")
			}
		})
	}
}

func TestCreateCredentialWithContents(t *testing.T) {
	tests := []struct {
		name        string
		input       CredentialContents
		expected    jsonmap.JSONMap
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid JWT contents",
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
			name: "Valid Embedded contents",
			input: CredentialContents{
				Context: []interface{}{"https://www.w3.org/2018/credentials/v1"},
				ID:      "urn:uuid:1234",
				Issuer:  "did:example:issuer",
				Types:   []string{"VerifiableCredential"},
			},
			expected: jsonmap.JSONMap{
				"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
				"id":       "urn:uuid:1234",
				"issuer":   "did:example:issuer",
				"type":     "VerifiableCredential",
			},
			expectError: false,
		},
		{
			name:        "Empty contents",
			input:       CredentialContents{},
			expectError: true,
			errorMsg:    "credential contents must have at least one of: context, ID, or issuer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NewEmbededCredential(tt.input)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, result, "Result should be nil when error is expected")
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result, "Result should not be nil when no error is expected")

			// For embedded credentials, we need to check the jsonCredential
			embeddedCred, ok := result.(*EmbededCredential)
			assert.True(t, ok, "Result should be *EmbededCredential")
			assert.Equal(t, tt.expected, jsonmap.JSONMap(embeddedCred.jsonCredential), "Embedded Credential mismatch")
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
	credential, err := NewJWTCredential(credentialContents)
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
	_, ok = parsedCredential.(*JWTCredential)
	assert.True(t, ok, "Credential type should be JWT")

	// For JWT credentials, we can check the payload directly
	jwtCred := parsedCredential.(*JWTCredential)
	assert.Equal(t, credentialContents.ID, jwtCred.Payload["id"], "Credential ID should match")
	assert.Equal(t, credentialContents.Issuer, jwtCred.Payload["issuer"], "Issuer should match")

	// Verify the credential
	err = credential.Verify()
	assert.NoError(t, err, "Failed to verify credential")
}

func TestCredentialSignatureFlows(t *testing.T) {
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
		ID:     "urn:uuid:signature-test-credential-12345678",
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

	t.Run("Embedded Credential - AddProof Flow", func(t *testing.T) {
		// Create embedded credential
		credential, err := NewEmbededCredential(credentialContents)
		assert.NoError(t, err, "Failed to create embedded credential")

		// Add proof using AddProof method
		err = credential.AddProof(privateKeyHex)
		assert.NoError(t, err, "Failed to add proof to embedded credential")

		// Verify the credential
		err = credential.Verify()
		assert.NoError(t, err, "Failed to verify embedded credential with proof")

		// Serialize and verify it has proof
		serialized, err := credential.Serialize()
		assert.NoError(t, err, "Failed to serialize embedded credential")

		// Check that serialized credential contains proof
		credMap, ok := serialized.(map[string]interface{})
		assert.True(t, ok, "Serialized credential should be a map")
		assert.Contains(t, credMap, "proof", "Serialized credential should contain proof")
	})

	t.Run("Embedded Credential - GetSigningInput + AddCustomProof Flow", func(t *testing.T) {
		// Create embedded credential
		credential, err := NewEmbededCredential(credentialContents)
		assert.NoError(t, err, "Failed to create embedded credential")

		// Get signing input
		signingInput, err := credential.GetSigningInput()
		assert.NoError(t, err, "Failed to get signing input")
		assert.NotEmpty(t, signingInput, "Signing input should not be empty")

		// Create a custom proof (simulating external signing)
		customProof := &dto.Proof{
			Type:               "EcdsaSecp256k1Signature2019",
			Created:            "2024-01-01T00:00:00Z",
			VerificationMethod: issuerDID + "#key-1",
			ProofPurpose:       "assertionMethod",
			ProofValue:         "mock-signature-value",
		}

		// Add custom proof
		err = credential.AddCustomProof(customProof)
		assert.NoError(t, err, "Failed to add custom proof to embedded credential")

		// Serialize and verify it has proof
		serialized, err := credential.Serialize()
		assert.NoError(t, err, "Failed to serialize embedded credential with custom proof")

		// Check that serialized credential contains proof
		credMap, ok := serialized.(map[string]interface{})
		assert.True(t, ok, "Serialized credential should be a map")
		assert.Contains(t, credMap, "proof", "Serialized credential should contain proof")
	})

	t.Run("JWT Credential - AddProof Flow", func(t *testing.T) {
		// Create JWT credential
		credential, err := NewJWTCredential(credentialContents)
		assert.NoError(t, err, "Failed to create JWT credential")

		// Add proof using AddProof method
		err = credential.AddProof(privateKeyHex)
		assert.NoError(t, err, "Failed to add proof to JWT credential")

		// Serialize to get JWT token
		serialized, err := credential.Serialize()
		assert.NoError(t, err, "Failed to serialize JWT credential")

		jwtToken, ok := serialized.(string)
		assert.True(t, ok, "Serialized JWT credential should be a string")
		assert.NotEmpty(t, jwtToken, "JWT token should not be empty")
		assert.Equal(t, 3, len(strings.Split(jwtToken, ".")), "JWT should have 3 parts")

		// Parse and verify the JWT credential
		parsedCredential, err := ParseCredentialJWT(jwtToken, WithDisableValidation())
		assert.NoError(t, err, "Failed to parse JWT credential")
		assert.NotNil(t, parsedCredential, "Parsed credential should not be nil")

		// verify
		err = parsedCredential.Verify()
		assert.NoError(t, err, "Failed to verify JWT credential")
	})

	t.Run("JWT Credential - GetSigningInput + AddCustomProof Flow", func(t *testing.T) {
		// Create JWT credential
		credential, err := NewJWTCredential(credentialContents)
		assert.NoError(t, err, "Failed to create JWT credential")

		// Get signing input
		signingInput, err := credential.GetSigningInput()
		assert.NoError(t, err, "Failed to get signing input")
		assert.NotEmpty(t, signingInput, "Signing input should not be empty")

		// Sign message with ES256K
		signer := jwt.SigningMethodES256K{}
		signatureBytes, err := signer.Sign(string(signingInput), privateKeyHex)
		assert.NoError(t, err, "Failed to sign message")
		assert.NotEmpty(t, signatureBytes, "Signature should not be empty")

		// Create a custom proof with JWT signature
		customProof := &dto.Proof{
			Signature: signatureBytes,
		}

		// Add custom proof (this will set the JWT signature)
		err = credential.AddCustomProof(customProof)
		assert.NoError(t, err, "Failed to add custom proof to JWT credential")

		// Serialize to get JWT token
		serialized, err := credential.Serialize()
		assert.NoError(t, err, "Failed to serialize JWT credential with custom proof")

		jwtToken, ok := serialized.(string)
		assert.True(t, ok, "Serialized JWT credential should be a string")
		assert.NotEmpty(t, jwtToken, "JWT token should not be empty")
	})

	t.Run("Error Cases", func(t *testing.T) {
		// Test AddCustomProof with nil proof
		credential, err := NewEmbededCredential(credentialContents)
		assert.NoError(t, err, "Failed to create embedded credential")

		err = credential.AddCustomProof(nil)
		assert.Error(t, err, "Should return error for nil proof")
		assert.Contains(t, err.Error(), "proof cannot be nil", "Error message should mention nil proof")

		// Test JWT credential with nil proof
		jwtCredential, err := NewJWTCredential(credentialContents)
		assert.NoError(t, err, "Failed to create JWT credential")

		err = jwtCredential.AddCustomProof(nil)
		assert.Error(t, err, "Should return error for nil proof")
		assert.Contains(t, err.Error(), "proof cannot be nil", "Error message should mention nil proof")
	})
}

func TestCreateECDSACredentialWithValidateSchema(t *testing.T) {
	issuerPrivateKey := "5a369512f8f8a0e6973abd6241ce38103c232966c6153bf8377ac85582812aa4"
	issuerDID := "did:nda:testnet:0x084ce14ef7c6e76a5ff3d58c160de7e1d385d9ee"
	schema := Schema{
		ID:   "https://auth-dev.pila.vn/api/v1/schemas/03d53d01-1841-4ab1-987c-bf96a0907db7",
		Type: "JsonSchema",
	}
	credentialContents := CredentialContents{
		Context: []interface{}{"https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"},
		Schemas: []Schema{schema},
		Subject: []Subject{Subject{
			ID: "did:nda:testnet:0x78e43d3bd308b0522c8f6fcfb4785d9b841556c8",
			CustomFields: map[string]interface{}{
				"age":        10,
				"department": "Engineering",
				"name":       "Test Create",
				"salary":     50000,
			},
		}},
		ID:         "did:nda:testnet:f5dd72fe-75d3-4a3b-b679-8b9fb5df5177",
		Issuer:     issuerDID,
		Types:      []string{"VerifiableCredential"},
		ValidFrom:  time.Now(),
		ValidUntil: time.Now().Add(time.Hour * 24 * 30),
		CredentialStatus: []Status{
			{
				ID:                   "did:nda:testnet:0x084ce14ef7c6e76a5ff3d58c160de7e1d385d9ee/credentials/status/0#0",
				Type:                 "BitstringStatusListEntry",
				StatusPurpose:        "revocation",
				StatusListIndex:      "0",
				StatusListCredential: "https://auth-dev.pila.vn/api/v1/issuers/did:nda:testnet:0x084ce14ef7c6e76a5ff3d58c160de7e1d385d9ee/credentials/status/0",
			},
		},
	}

	embededCredential, err := NewEmbededCredential(credentialContents, WithEnableValidation(), WithCredentialSchemaLoader(schema.ID, schema.Type))
	if err != nil {
		t.Fatalf("Failed to create embedded credential: %v", err)
	}

	// add proof
	err = embededCredential.AddProof(issuerPrivateKey)
	if err != nil {
		t.Fatalf("Failed to add proof: %v", err)
	}

	// verify
	err = embededCredential.Verify()
	if err != nil {
		t.Fatalf("Failed to verify embedded credential: %v", err)
	}

	credentailBytes, err := embededCredential.ToJSON()
	if err != nil {
		t.Fatalf("Failed to convert embedded credential to JSON: %v", err)
	}
	println(string(credentailBytes))
}

func TestCreateJWTCredentialWithValidateSchema(t *testing.T) {
	issuerPrivateKey := "5a369512f8f8a0e6973abd6241ce38103c232966c6153bf8377ac85582812aa4"
	issuerDID := "did:nda:testnet:0x084ce14ef7c6e76a5ff3d58c160de7e1d385d9ee"
	schema := Schema{
		ID:   "https://auth-dev.pila.vn/api/v1/schemas/03d53d01-1841-4ab1-987c-bf96a0907db7",
		Type: "JsonSchema",
	}
	credentialContents := CredentialContents{
		Context: []interface{}{"https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"},
		Schemas: []Schema{schema},
		Subject: []Subject{Subject{
			ID: "did:nda:testnet:0x78e43d3bd308b0522c8f6fcfb4785d9b841556c8",
			CustomFields: map[string]interface{}{
				"age":        10,
				"department": "Engineering",
				"name":       "Test Create",
				"salary":     50000,
			},
		}},
		ID:         "did:nda:testnet:f5dd72fe-75d3-4a3b-b679-8b9fb5df5177",
		Issuer:     issuerDID,
		Types:      []string{"VerifiableCredential"},
		ValidFrom:  time.Now(),
		ValidUntil: time.Now().Add(time.Hour * 24 * 30),
		CredentialStatus: []Status{
			{
				ID:                   "did:nda:testnet:0x084ce14ef7c6e76a5ff3d58c160de7e1d385d9ee/credentials/status/0#0",
				Type:                 "BitstringStatusListEntry",
				StatusPurpose:        "revocation",
				StatusListIndex:      "0",
				StatusListCredential: "https://auth-dev.pila.vn/api/v1/issuers/did:nda:testnet:0x084ce14ef7c6e76a5ff3d58c160de7e1d385d9ee/credentials/status/0",
			},
		},
	}

	jwtCredential, err := NewJWTCredential(credentialContents, WithEnableValidation(), WithCredentialSchemaLoader(schema.ID, schema.Type))
	if err != nil {
		t.Fatalf("Failed to create JWT credential: %v", err)
	}

	// add proof
	err = jwtCredential.AddProof(issuerPrivateKey)
	if err != nil {
		t.Fatalf("Failed to add proof: %v", err)
	}

	// verify
	err = jwtCredential.Verify()
	if err != nil {
		t.Fatalf("Failed to verify JWT credential: %v", err)
	}
}

func TestJWTCredentialAddCustomProofMustEqualsToAddProof(t *testing.T) {
	issuerPrivateKey := "5a369512f8f8a0e6973abd6241ce38103c232966c6153bf8377ac85582812aa4"
	issuerDID := "did:nda:testnet:0x084ce14ef7c6e76a5ff3d58c160de7e1d385d9ee"
	schema := Schema{
		ID:   "https://auth-dev.pila.vn/api/v1/schemas/03d53d01-1841-4ab1-987c-bf96a0907db7",
		Type: "JsonSchema",
	}
	credentialContents := CredentialContents{
		Context: []interface{}{"https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"},
		Schemas: []Schema{schema},
		Subject: []Subject{Subject{
			ID: "did:nda:testnet:0x78e43d3bd308b0522c8f6fcfb4785d9b841556c8",
		}},
		ID:         "did:nda:testnet:f5dd72fe-75d3-4a3b-b679-8b9fb5df5177",
		Issuer:     issuerDID,
		Types:      []string{"VerifiableCredential"},
		ValidFrom:  time.Now(),
		ValidUntil: time.Now().Add(time.Hour * 24 * 30),
		CredentialStatus: []Status{
			{
				ID:                   "did:nda:testnet:0x084ce14ef7c6e76a5ff3d58c160de7e1d385d9ee/credentials/status/0#0",
				Type:                 "BitstringStatusListEntry",
				StatusPurpose:        "revocation",
				StatusListIndex:      "0",
				StatusListCredential: "https://auth-dev.pila.vn/api/v1/issuers/did:nda:testnet:0x084ce14ef7c6e76a5ff3d58c160de7e1d385d9ee/credentials/status/0",
			},
		},
	}
	jwtCredential, err := NewJWTCredential(credentialContents, WithEnableValidation())
	if err != nil {
		t.Fatalf("Failed to create JWT credential: %v", err)
	}

	// add proof
	err = jwtCredential.AddProof(issuerPrivateKey)
	if err != nil {
		t.Fatalf("Failed to add proof: %v", err)
	}

	// another jwt with custom proof
	anotherJwtCredential, err := NewJWTCredential(credentialContents, WithEnableValidation())
	if err != nil {
		t.Fatalf("Failed to create another JWT credential: %v", err)
	}

	// calculate signature
	getSigningInput, err := anotherJwtCredential.GetSigningInput()
	if err != nil {
		t.Fatalf("Failed to get signing input: %v", err)
	}
	signer := jwt.SigningMethodES256K{}
	signatureBytes, err := signer.Sign(string(getSigningInput), issuerPrivateKey)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// add custom proof
	err = anotherJwtCredential.AddCustomProof(&dto.Proof{
		Signature: signatureBytes,
	})
	if err != nil {
		t.Fatalf("Failed to add custom proof: %v", err)
	}

	// verify
	err = anotherJwtCredential.Verify()
	if err != nil {
		t.Fatalf("Failed to verify JWT credential: %v", err)
	}

	// compare jwt
	jwtToken, err := jwtCredential.Serialize()
	if err != nil {
		t.Fatalf("Failed to serialize JWT credential: %v", err)
	}
	anotherJwtToken, err := anotherJwtCredential.Serialize()
	assert.Equal(t, jwtToken, anotherJwtToken, "JWT token should be the same")
}
