package vc

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
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
			assert.Equal(t, tt.expected, jsonmap.JSONMap(*result), "Credential mismatch") // Cast *result to jsonmap.JSONMap
		})
	}
}

func TestCreateCredentialWithContent(t *testing.T) {
	tests := []struct {
		name        string
		input       CredentialContents
		expected    jsonmap.JSONMap
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid contents",
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
			input:       CredentialContents{},
			expectError: true,
			errorMsg:    "contents must have context, ID, or issuer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CreateCredentialWithContent(tt.input)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, jsonmap.JSONMap(*result), "Credential mismatch") // Cast *result to jsonmap.JSONMap
		})
	}
}

func TestToJSON(t *testing.T) {
	credential := Credential(jsonmap.JSONMap{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"id":       "urn:uuid:1234",
	})
	expectedJSON := `{"@context":["https://www.w3.org/2018/credentials/v1"],"id":"urn:uuid:1234"}`

	result, err := credential.ToJSON()
	assert.NoError(t, err)
	assert.JSONEq(t, expectedJSON, string(result))
}

func TestParseCredentialContents(t *testing.T) {
	fixedTime, _ := time.Parse(time.RFC3339, "2025-08-05T10:00:00Z")
	credential := Credential(jsonmap.JSONMap{
		"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"id":                "urn:uuid:1234",
		"type":              []interface{}{"VerifiableCredential"},
		"issuer":            "did:example:issuer",
		"validFrom":         fixedTime.Format(time.RFC3339),
		"credentialSubject": map[string]interface{}{"id": "did:example:subject1", "name": "John Doe"},
		"credentialSchema":  map[string]interface{}{"id": "https://example.org/schema/1", "type": "JsonSchemaValidator2019"},
		"credentialStatus":  map[string]interface{}{"id": "https://example.org/status/1", "type": "StatusList2021Entry"},
		"proof":             map[string]interface{}{"type": "Ed25519Signature2020", "created": fixedTime.Format(time.RFC3339)},
	})

	expected := CredentialContents{
		Context:   []interface{}{"https://www.w3.org/2018/credentials/v1"},
		ID:        "urn:uuid:1234",
		Types:     []string{"VerifiableCredential"},
		Issuer:    "did:example:issuer",
		ValidFrom: fixedTime,
		Subject: []Subject{
			{ID: "did:example:subject1", CustomFields: map[string]interface{}{"name": "John Doe"}},
		},
		Schemas: []Schema{
			{ID: "https://example.org/schema/1", Type: "JsonSchemaValidator2019"},
		},
		CredentialStatus: []Status{
			{ID: "https://example.org/status/1", Type: "StatusList2021Entry"},
		},
		Proofs: []dto.Proof{
			{Type: "Ed25519Signature2020", Created: fixedTime.Format(time.RFC3339)},
		},
	}

	result, err := credential.ParseCredentialContents()
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
}

func TestParseContext(t *testing.T) {
	tests := []struct {
		name        string
		credential  Credential
		expected    []interface{}
		expectError bool
		errorMsg    string
	}{
		{
			name:       "Valid context",
			credential: Credential(jsonmap.JSONMap{"@context": []interface{}{"https://www.w3.org/2018/credentials/v1", map[string]interface{}{"custom": "context"}}}),
			expected:   []interface{}{"https://www.w3.org/2018/credentials/v1", map[string]interface{}{"custom": "context"}},
		},
		{
			name:        "Invalid context type",
			credential:  Credential(jsonmap.JSONMap{"@context": []interface{}{1}}),
			expectError: true,
			errorMsg:    "unsupported context type: int",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var contents CredentialContents
			err := parseContext(&tt.credential, &contents)

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
	credential := Credential(jsonmap.JSONMap{"id": "urn:uuid:1234"})
	var contents CredentialContents
	err := parseID(&credential, &contents)
	assert.NoError(t, err)
	assert.Equal(t, "urn:uuid:1234", contents.ID)
}

func TestParseTypes(t *testing.T) {
	tests := []struct {
		name        string
		credential  Credential
		expected    []string
		expectError bool
		errorMsg    string
	}{
		{
			name:       "Single type",
			credential: Credential(jsonmap.JSONMap{"type": "VerifiableCredential"}),
			expected:   []string{"VerifiableCredential"},
		},
		{
			name:       "Multiple types",
			credential: Credential(jsonmap.JSONMap{"type": []interface{}{"VerifiableCredential", "CustomCredential"}}),
			expected:   []string{"VerifiableCredential", "CustomCredential"},
		},
		{
			name:        "Invalid type",
			credential:  Credential(jsonmap.JSONMap{"type": 123}),
			expectError: true,
			errorMsg:    "unsupported type field: int",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var contents CredentialContents
			err := parseTypes(&tt.credential, &contents)

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
	credential := Credential(jsonmap.JSONMap{"issuer": "did:example:issuer"})
	var contents CredentialContents
	err := parseIssuer(&credential, &contents)
	assert.NoError(t, err)
	assert.Equal(t, "did:example:issuer", contents.Issuer)
}

func TestParseDates(t *testing.T) {
	fixedTime, _ := time.Parse(time.RFC3339, "2025-08-05T10:00:00Z")
	credential := Credential(jsonmap.JSONMap{
		"validFrom":  fixedTime.Format(time.RFC3339),
		"validUntil": fixedTime.Add(24 * time.Hour).Format(time.RFC3339),
	})

	var contents CredentialContents
	err := parseDates(&credential, &contents)
	assert.NoError(t, err)
	assert.Equal(t, fixedTime, contents.ValidFrom)
	assert.Equal(t, fixedTime.Add(24*time.Hour), contents.ValidUntil)
}

func TestParseSubject(t *testing.T) {
	tests := []struct {
		name        string
		credential  Credential
		expected    []Subject
		expectError bool
		errorMsg    string
	}{
		{
			name:       "Single subject",
			credential: Credential(jsonmap.JSONMap{"credentialSubject": map[string]interface{}{"id": "did:example:subject1", "name": "John Doe"}}),
			expected:   []Subject{{ID: "did:example:subject1", CustomFields: map[string]interface{}{"name": "John Doe"}}},
		},
		{
			name:       "Multiple subjects",
			credential: Credential(jsonmap.JSONMap{"credentialSubject": []interface{}{map[string]interface{}{"id": "did:example:subject1"}, map[string]interface{}{"id": "did:example:subject2"}}}),
			expected:   []Subject{{ID: "did:example:subject1", CustomFields: map[string]interface{}{}}, {ID: "did:example:subject2", CustomFields: map[string]interface{}{}}},
		},
		{
			name:        "Invalid subject format",
			credential:  Credential(jsonmap.JSONMap{"credentialSubject": 123}),
			expectError: true,
			errorMsg:    "unsupported subject format: int",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var contents CredentialContents
			err := parseSubject(&tt.credential, &contents)

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
	credential := Credential(jsonmap.JSONMap{
		"credentialSchema": map[string]interface{}{"id": "https://example.org/schema/1", "type": "JsonSchemaValidator2019"},
	})

	var contents CredentialContents
	err := parseSchema(&credential, &contents)
	assert.NoError(t, err)
	assert.Equal(t, []Schema{{ID: "https://example.org/schema/1", Type: "JsonSchemaValidator2019"}}, contents.Schemas)
}

func TestParseStatus(t *testing.T) {
	credential := Credential(jsonmap.JSONMap{
		"credentialStatus": map[string]interface{}{"id": "https://example.org/status/1", "type": "StatusList2021Entry"},
	})

	var contents CredentialContents
	err := parseStatus(&credential, &contents)
	assert.NoError(t, err)
	assert.Equal(t, []Status{{ID: "https://example.org/status/1", Type: "StatusList2021Entry"}}, contents.CredentialStatus)
}

func TestParseProofs(t *testing.T) {
	fixedTime, _ := time.Parse(time.RFC3339, "2025-08-05T10:00:00Z")
	credential := Credential(jsonmap.JSONMap{
		"proof": map[string]interface{}{"type": "Ed25519Signature2020", "created": fixedTime.Format(time.RFC3339)},
	})

	var contents CredentialContents
	err := parseProofs(&credential, &contents)
	assert.NoError(t, err)
	assert.Equal(t, []dto.Proof{{Type: "Ed25519Signature2020", Created: fixedTime.Format(time.RFC3339)}}, contents.Proofs)
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
	credential, err := CreateCredentialWithContent(credentialContents)
	assert.NoError(t, err, "Failed to create credential from contents")

	// Sign the credential as JWT
	additionalClaims := map[string]interface{}{
		"aud": "did:example:verifier",
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	}

	jwtToken, err := credential.SignJWT(privateKeyHex, issuerDID, additionalClaims)
	assert.NoError(t, err, "Failed to sign credential as JWT")
	assert.NotEmpty(t, jwtToken, "JWT token should not be empty")

	// Verify the JWT token structure (should have 3 parts)
	parts := []string{}
	for _, part := range []string{"header", "payload", "signature"} {
		parts = append(parts, part)
	}
	assert.Equal(t, 3, len(strings.Split(jwtToken, ".")), "JWT should have 3 parts separated by dots")

	// Verify the JWT credential
	verifiedData, err := VerifyJWT(jwtToken, WithDisableValidation())
	assert.NoError(t, err, "Failed to verify JWT credential")
	assert.NotNil(t, verifiedData, "Verified data should not be nil")

	// Verify the credential data matches
	verifiedCredential := Credential(verifiedData)
	verifiedContents, err := verifiedCredential.ParseCredentialContents()
	assert.NoError(t, err, "Failed to parse verified credential contents")

	// Check key fields match
	assert.Equal(t, credentialContents.ID, verifiedContents.ID, "Credential ID should match")
	assert.Equal(t, credentialContents.Issuer, verifiedContents.Issuer, "Issuer should match")
	assert.Equal(t, len(credentialContents.Types), len(verifiedContents.Types), "Number of types should match")
	assert.Equal(t, len(credentialContents.Subject), len(verifiedContents.Subject), "Number of subjects should match")

	// Check subject data
	if len(verifiedContents.Subject) > 0 {
		assert.Equal(t, credentialContents.Subject[0].ID, verifiedContents.Subject[0].ID, "Subject ID should match")
		assert.Equal(t, credentialContents.Subject[0].CustomFields["name"], verifiedContents.Subject[0].CustomFields["name"], "Subject name should match")
	}
}
