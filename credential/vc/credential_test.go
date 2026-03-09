package vc

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/sdjwt"
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
		expected    CredentialData
		expectError bool
		errorMsg    string
	}{
		{
			name:      "Valid credential JSON",
			inputJSON: validJSON,
			opts:      []CredentialOpt{},
			expected: CredentialData{
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
			opts:        []CredentialOpt{},
			expectError: false,
			expected:    buildExpectedEducationalCredential(),
		},
		{
			name:        "Valid Educational Credential SD-JWT (wrapper)",
			inputJSON:   []byte(buildDummySDJWT(validJWTtoken)),
			opts:        []CredentialOpt{},
			expectError: false,
			expected:    buildExpectedEducationalCredential(),
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
			if _, ok := result.(*JSONCredential); ok {
				embeddedCred := result.(*JSONCredential)
				assert.Equal(t, tt.expected, CredentialData(embeddedCred.credentialData), "Credential mismatch")
			} else if _, ok := result.(*JWTCredential); ok {
				jwtCred := result.(*JWTCredential)
				payloadData, err := jwtCred.GetContents()
				if err != nil {
					t.Fatalf("GetContents failed: %v", err)
				}
				var payloadMap map[string]interface{}
				err = json.Unmarshal(payloadData, &payloadMap)
				if err != nil {
					t.Fatalf("Failed to unmarshal payload: %v", err)
				}
				assert.Equal(t, tt.expected, CredentialData(payloadMap), "Credential mismatch")
			}
		})
	}
}

// buildDummySDJWT wraps a plain JWT into an SD-JWT by appending a
// syntactically valid disclosure that does not affect the payload.
func buildDummySDJWT(jwtStr string) string {
	// Simple disclosure array [salt, name, value]
	arr := []interface{}{"salt", "x", "y"}
	b, _ := json.Marshal(arr)
	D := base64.RawURLEncoding.EncodeToString(b)

	sd := jwtStr + "~" + D + "~"

	if !sdjwt.IsSDJWT(sd) {
		// In case of unexpected format change, we still return the original JWT.
		return jwtStr
	}

	return sd
}

func buildExpectedEducationalCredential() CredentialData {
	return CredentialData{
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
	}
}

func TestCreateCredentialWithContents(t *testing.T) {
	tests := []struct {
		name        string
		input       CredentialContents
		expected    CredentialData
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
			expected: CredentialData{
				"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
				"id":       "urn:uuid:1234",
				"issuer":   "did:example:issuer",
			},
			expectError: false,
		},
		{
			name: "Valid JSON contents",
			input: CredentialContents{
				Context: []interface{}{"https://www.w3.org/2018/credentials/v1"},
				ID:      "urn:uuid:1234",
				Issuer:  "did:example:issuer",
				Types:   []string{"VerifiableCredential"},
			},
			expected: CredentialData{
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
			result, err := NewJSONCredential(tt.input)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, result, "Result should be nil when error is expected")
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result, "Result should not be nil when no error is expected")

			// For JSON credentials, we need to check the jsonCredential
			embeddedCred, ok := result.(*JSONCredential)
			assert.True(t, ok, "Result should be *JSONCredential")
			assert.Equal(t, tt.expected, CredentialData(embeddedCred.credentialData), "JSON Credential mismatch")
		})
	}
}

func TestParseContext(t *testing.T) {
	tests := []struct {
		name        string
		credential  CredentialData
		expected    []interface{}
		expectError bool
		errorMsg    string
	}{
		{
			name:       "Valid context",
			credential: CredentialData{"@context": []interface{}{"https://www.w3.org/2018/credentials/v1", map[string]interface{}{"custom": "context"}}},
			expected:   []interface{}{"https://www.w3.org/2018/credentials/v1", map[string]interface{}{"custom": "context"}},
		},
		{
			name:        "Invalid context type",
			credential:  CredentialData{"@context": []interface{}{1}},
			expectError: true,
			errorMsg:    "unsupported context type: int",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var contents CredentialContents
			err := parseContext(CredentialData(tt.credential), &contents)

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
	credential := CredentialData{"id": "urn:uuid:1234"}
	var contents CredentialContents
	err := parseID(credential, &contents)
	assert.NoError(t, err)
	assert.Equal(t, "urn:uuid:1234", contents.ID)
}

func TestParseTypes(t *testing.T) {
	tests := []struct {
		name        string
		credential  CredentialData
		expected    []string
		expectError bool
		errorMsg    string
	}{
		{
			name:       "Single type",
			credential: CredentialData{"type": "VerifiableCredential"},
			expected:   []string{"VerifiableCredential"},
		},
		{
			name:       "Multiple types",
			credential: CredentialData{"type": []interface{}{"VerifiableCredential", "CustomCredential"}},
			expected:   []string{"VerifiableCredential", "CustomCredential"},
		},
		{
			name:        "Invalid type",
			credential:  CredentialData{"type": 123},
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
	credential := CredentialData{"issuer": "did:example:issuer"}
	var contents CredentialContents
	err := parseIssuer(credential, &contents)
	assert.NoError(t, err)
	assert.Equal(t, "did:example:issuer", contents.Issuer)
}

func TestParseDates(t *testing.T) {
	fixedTime, _ := time.Parse(time.RFC3339, "2025-08-05T10:00:00Z")
	credential := CredentialData{
		"validFrom":  fixedTime.Format(time.RFC3339),
		"validUntil": fixedTime.Add(24 * time.Hour).Format(time.RFC3339),
	}

	var contents CredentialContents
	err := parseDates(credential, &contents)
	assert.NoError(t, err)
	assert.Equal(t, fixedTime, contents.ValidFrom)
	assert.Equal(t, fixedTime.Add(24*time.Hour), contents.ValidUntil)
}

func TestCheckExpiration_ValidWindow(t *testing.T) {
	now := time.Now()
	credential := CredentialData{
		"validFrom":  now.Add(-1 * time.Hour).Format(time.RFC3339),
		"validUntil": now.Add(1 * time.Hour).Format(time.RFC3339),
	}

	err := checkExpiration(credential)
	assert.NoError(t, err)
}

func TestCheckExpiration_NotValidYet(t *testing.T) {
	now := time.Now()
	credential := CredentialData{
		"validFrom": now.Add(1 * time.Hour).Format(time.RFC3339),
	}

	err := checkExpiration(credential)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credential is not valid yet")
}

func TestCheckExpiration_Expired(t *testing.T) {
	now := time.Now()
	credential := CredentialData{
		"validUntil": now.Add(-1 * time.Hour).Format(time.RFC3339),
	}

	err := checkExpiration(credential)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credential is expired")
}

func TestParseSubject(t *testing.T) {
	tests := []struct {
		name        string
		credential  CredentialData
		expected    []Subject
		expectError bool
		errorMsg    string
	}{
		{
			name:       "Single subject",
			credential: CredentialData{"credentialSubject": map[string]interface{}{"id": "did:example:subject1", "name": "John Doe"}},
			expected:   []Subject{{ID: "did:example:subject1", CustomFields: map[string]interface{}{"name": "John Doe"}}},
		},
		{
			name:       "Multiple subjects",
			credential: CredentialData{"credentialSubject": []interface{}{map[string]interface{}{"id": "did:example:subject1"}, map[string]interface{}{"id": "did:example:subject2"}}},
			expected:   []Subject{{ID: "did:example:subject1", CustomFields: map[string]interface{}{}}, {ID: "did:example:subject2", CustomFields: map[string]interface{}{}}},
		},
		{
			name:        "Invalid subject format",
			credential:  CredentialData{"credentialSubject": 123},
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
	credential := CredentialData{
		"credentialSchema": map[string]interface{}{"id": "https://example.org/schema/1", "type": "JsonSchemaValidator2019"},
	}

	var contents CredentialContents
	err := parseSchema(credential, &contents)
	assert.NoError(t, err)
	assert.Equal(t, []Schema{{ID: "https://example.org/schema/1", Type: "JsonSchemaValidator2019"}}, contents.Schemas)
}

func TestParseStatus(t *testing.T) {
	credential := CredentialData{
		"credentialStatus": map[string]interface{}{"id": "https://example.org/status/1", "type": "StatusList2021Entry"},
	}

	var contents CredentialContents
	err := parseStatus(credential, &contents)
	assert.NoError(t, err)
	assert.Equal(t, []Status{{ID: "https://example.org/status/1", Type: "StatusList2021Entry"}}, contents.CredentialStatus)
}

func TestParseProofs(t *testing.T) {
	fixedTime, _ := time.Parse(time.RFC3339, "2025-08-05T10:00:00Z")
	credential := CredentialData{
		"proof": map[string]interface{}{"type": "Ed25519Signature2020", "created": fixedTime.Format(time.RFC3339)},
	}

	var contents CredentialContents
	err := parseProofs(credential, &contents)
	assert.NoError(t, err)
	// Note: parseProofs now returns nil since CredentialContents doesn't have Proofs field
	// The test just verifies no error occurs
}

func TestSubjectFromJSON(t *testing.T) {
	input := CredentialData{"id": "did:example:subject1", "name": "John Doe"}
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
	input := CredentialData{"id": "did:example:subject1"}
	result, err := parseStringField(input, "id")
	assert.NoError(t, err)
	assert.Equal(t, "did:example:subject1", result)

	_, err = parseStringField(CredentialData{"id": 123}, "id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "field \"id\" must be a string")
}

func TestCheckRevocation_RevokedJSONCredential(t *testing.T) {
	credentialJSON := []byte(`{
	  "id": "did:nda:testnet:95c00e62-76ff-46a1-b2bc-f1d3b80d0aa9",
	  "type": "VerifiableCredential",
	  "proof": {
	    "type": "DataIntegrityProof",
	    "created": "2025-12-03T14:31:25Z",
	    "proofValue": "e693cea7102b8edee4ccc12a48682fe2836a28c52cc6936600ec39e962cec89b729ccf98d96c2124ee23cee9cdacaef0c31565a98a09b3a5087bb0c7cdf1df48",
	    "cryptosuite": "ecdsa-rdfc-2019",
	    "proofPurpose": "assertionMethod",
	    "verificationMethod": "did:nda:testnet:0x222137fb0099115bd0b0446c4d66c81ccf41e0bb#key-1"
	  },
	  "issuer": "did:nda:testnet:0x222137fb0099115bd0b0446c4d66c81ccf41e0bb",
	  "@context": [
	    "https://www.w3.org/ns/credentials/v2",
	    "https://www.w3.org/ns/credentials/examples/v2"
	  ],
	  "validFrom": "2025-08-29T09:01:51Z",
	  "validUntil": "2026-08-29T09:01:51Z",
	  "credentialSchema": {
	    "id": "https://auth-dev.pila.vn/api/v1/schemas/71a14ce1-c8fa-4df4-960b-e18bb6282cee",
	    "type": "JsonSchema"
	  },
	  "credentialStatus": {
	    "id": "did:nda:testnet:0x222137fb0099115bd0b0446c4d66c81ccf41e0bb/credentials/status/0#18",
	    "type": "BitstringStatusListEntry",
	    "statusPurpose": "revocation",
	    "statusListIndex": "18",
	    "statusListCredential": "https://auth-dev.pila.vn/api/v1/issuers/did:nda:testnet:0x222137fb0099115bd0b0446c4d66c81ccf41e0bb/credentials/status/0"
	  },
	  "credentialSubject": {
	    "id": "did:nda:testnet:0x222137fb0099115bd0b0446c4d66c81ccf41e0bb",
	    "age": 10,
	    "name": "Test Create",
	    "salary": 50000,
	    "department": "Engineering"
	  }
	}`)

	_, err := ParseCredential(credentialJSON, WithCheckRevocation())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credential is revoked")
}

func TestCheckRevocation_NotRevokedJSONCredential(t *testing.T) {
	credentialJSON := []byte(`{
	  "id": "did:nda:testnet:593c544e-6df8-4bfa-bc61-c45b53b07b03",
	  "type": "VerifiableCredential",
	  "issuer": "did:pila:testnet:0xedf82c5366eeffcbef566b2edffab102d140f212",
	  "@context": [
	    "https://www.w3.org/ns/credentials/v2",
	    "https://www.w3.org/ns/credentials/examples/v2"
	  ],
	  "validFrom": "2025-09-25T07:57:04Z",
	  "validUntil": "2026-09-25T07:57:04Z",
	  "credentialSchema": {
	    "id": "https://auth-dev.pila.vn/api/v1/schemas/63a39bc9-b52b-42cb-be7e-28c096d93174",
	    "type": "JsonSchema"
	  },
	  "credentialStatus": {
	    "id": "did:pila:testnet:0xedf82c5366eeffcbef566b2edffab102d140f212/credentials/status/260#790",
	    "type": "BitstringStatusListEntry",
	    "statusPurpose": "revocation",
	    "statusListIndex": "790",
	    "statusListCredential": "https://auth-dev.pila.vn/api/v1/issuers/did:pila:testnet:0xedf82c5366eeffcbef566b2edffab102d140f212/credentials/status/260"
	  },
	  "credentialSubject": {
	    "id": "did:pila:testnet:0xedf82c5366eeffcbef566b2edffab102d140f212",
	    "age": 10,
	    "name": "Test Create JSON",
	    "salary": 50000,
	    "department": "Engineering"
	  }
	}`)

	_, err := ParseCredential(credentialJSON, WithCheckRevocation())
	assert.NoError(t, err)
}

func TestCheckRevocation_EmptyStatusJSONCredential(t *testing.T) {
	credentialJSON := []byte(`{
	  "id": "did:nda:testnet:593c544e-6df8-4bfa-bc61-c45b53b07b03",
	  "type": "VerifiableCredential",
	  "issuer": "did:pila:testnet:0xedf82c5366eeffcbef566b2edffab102d140f212",
	  "@context": [
	    "https://www.w3.org/ns/credentials/v2",
	    "https://www.w3.org/ns/credentials/examples/v2"
	  ],
	  "validFrom": "2025-09-25T07:57:04Z",
	  "validUntil": "2026-09-25T07:57:04Z",
	  "credentialSchema": {
	    "id": "https://auth-dev.pila.vn/api/v1/schemas/63a39bc9-b52b-42cb-be7e-28c096d93174",
	    "type": "JsonSchema"
	  },
	  "credentialStatus": {},
	  "credentialSubject": {
	    "id": "did:pila:testnet:0xedf82c5366eeffcbef566b2edffab102d140f212",
	    "age": 10,
	    "name": "Test Create JSON",
	    "salary": 50000,
	    "department": "Engineering"
	  }
	}`)

	_, err := ParseCredential(credentialJSON, WithCheckRevocation())
	assert.NoError(t, err)
}

func TestCheckRevocation_NoStatusFieldJSONCredential(t *testing.T) {
	credentialJSON := []byte(`{
	  "id": "did:nda:testnet:593c544e-6df8-4bfa-bc61-c45b53b07b03",
	  "type": "VerifiableCredential",
	  "issuer": "did:pila:testnet:0xedf82c5366eeffcbef566b2edffab102d140f212",
	  "@context": [
	    "https://www.w3.org/ns/credentials/v2",
	    "https://www.w3.org/ns/credentials/examples/v2"
	  ],
	  "validFrom": "2025-09-25T07:57:04Z",
	  "validUntil": "2026-09-25T07:57:04Z",
	  "credentialSchema": {
	    "id": "https://auth-dev.pila.vn/api/v1/schemas/63a39bc9-b52b-42cb-be7e-28c096d93174",
	    "type": "JsonSchema"
	  },
	  "credentialSubject": {
	    "id": "did:pila:testnet:0xedf82c5366eeffcbef566b2edffab102d140f212",
	    "age": 10,
	    "name": "Test Create JSON",
	    "salary": 50000,
	    "department": "Engineering"
	  }
	}`)

	_, err := ParseCredential(credentialJSON, WithCheckRevocation())
	assert.NoError(t, err)
}

func TestCheckRevocation_RevokedJWTCredential(t *testing.T) {
	revokedJWT := "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgyMjIxMzdmYjAwOTkxMTViZDBiMDQ0NmM0ZDY2YzgxY2NmNDFlMGJiI2tleS0xIiwidHlwIjoiSldUIn0.eyJleHAiOjE3ODc5OTQxMTEsImlhdCI6MTc1NjQ1ODExMSwiaXNzIjoiZGlkOm5kYTp0ZXN0bmV0OjB4MjIyMTM3ZmIwMDk5MTE1YmQwYjA0NDZjNGQ2NmM4MWNjZjQxZTBiYiIsImp0aSI6ImRpZDpuZGE6dGVzdG5ldDpjOGFjZjdmNC05ZDQzLTRhYjctYWRhOC03NjZmYmU3NTA2ZDMiLCJuYmYiOjE3NTY0NTgxMTEsInN1YiI6ImRpZDpuZGE6dGVzdG5ldDoweDIyMjEzN2ZiMDA5OTExNWJkMGIwNDQ2YzRkNjZjODFjY2Y0MWUwYmIiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vYXV0aC1kZXYucGlsYS52bi9hcGkvdjEvc2NoZW1hcy83MWExNGNlMS1jOGZhLTRkZjQtOTYwYi1lMThiYjYyODJjZWUiLCJ0eXBlIjoiSnNvblNjaGVtYSJ9LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiZGlkOm5kYTp0ZXN0bmV0OjB4MjIyMTM3ZmIwMDk5MTE1YmQwYjA0NDZjNGQ2NmM4MWNjZjQxZTBiYi9jcmVkZW50aWFscy9zdGF0dXMvMCMxNSIsInN0YXR1c0xpc3RDcmVkZW50aWFsIjoiaHR0cHM6Ly9hdXRoLWRldi5waWxhLnZuL2FwaS92MS9pc3N1ZXJzL2RpZDpuZGE6dGVzdG5ldDoweDIyMjEzN2ZiMDA5OTExNWJkMGIwNDQ2YzRkNjZjODFjY2Y0MWUwYmIvY3JlZGVudGlhbHMvc3RhdHVzLzAiLCJzdGF0dXNMaXN0SW5kZXgiOiIxNSIsInN0YXR1c1B1cnBvc2UiOiJyZXZvY2F0aW9uIiwidHlwZSI6IkJpdHN0cmluZ1N0YXR1c0xpc3RFbnRyeSJ9LCJjcmVkZW50aWFsU3ViamVjdCI6eyJhZ2UiOjEwLCJkZXBhcnRtZW50IjoiRW5naW5lZXJpbmciLCJpZCI6ImRpZDpuZGE6dGVzdG5ldDoweDIyMjEzN2ZiMDA5OTExNWJkMGIwNDQ2YzRkNjZjODFjY2Y0MWUwYmIiLCJuYW1lIjoiVGVzdCBDcmVhdGUiLCJzYWxhcnkiOjUwMDAwfSwiaWQiOiJkaWQ6bmRhOnRlc3RuZXQ6YzhhY2Y3ZjQtOWQ0My00YWI3LWFkYTgtNzY2ZmJlNzUwNmQzIiwiaXNzdWVyIjoiZGlkOm5kYTp0ZXN0bmV0OjB4MjIyMTM3ZmIwMDk5MTE1YmQwYjA0NDZjNGQ2NmM4MWNjZjQxZTBiYiIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInZhbGlkRnJvbSI6IjIwMjUtMDgtMjlUMDk6MDE6NTFaIiwidmFsaWRVbnRpbCI6IjIwMjYtMDgtMjlUMDk6MDE6NTFaIn19.P5ulGrKwY9KlxwqSN3Bs6aTQSGqS4z--brmJp3XtcTomXe8mse7gD3MHZF8C74V9zvgXV6RIM0vFzqdxzVUfnQ"

	_, err := ParseCredential([]byte(revokedJWT), WithCheckRevocation())
	assert.Error(t, err)
}

func TestCheckRevocation_NotRevokedJWTCredential(t *testing.T) {
	notRevokedJWT := "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgyMjIxMzdmYjAwOTkxMTViZDBiMDQ0NmM0ZDY2YzgxY2NmNDFlMGJiI2tleS0xIiwidHlwIjoiSldUIn0.eyJleHAiOjE3ODc5OTQxMTEsImlhdCI6MTc1NjQ1ODExMSwiaXNzIjoiZGlkOm5kYTp0ZXN0bmV0OjB4MjIyMTM3ZmIwMDk5MTE1YmQwYjA0NDZjNGQ2NmM4MWNjZjQxZTBiYiIsImp0aSI6ImRpZDpuZGE6dGVzdG5ldDpjMGExNDU3YS1kYTdmLTRlYTQtOWZmOC0xYTgxMDFhZjViMjAiLCJuYmYiOjE3NTY0NTgxMTEsInN1YiI6ImRpZDpuZGE6dGVzdG5ldDoweDIyMjEzN2ZiMDA5OTExNWJkMGIwNDQ2YzRkNjZjODFjY2Y0MWUwYmIiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vYXV0aC1kZXYucGlsYS52bi9hcGkvdjEvc2NoZW1hcy83MWExNGNlMS1jOGZhLTRkZjQtOTYwYi1lMThiYjYyODJjZWUiLCJ0eXBlIjoiSnNvblNjaGVtYSJ9LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiZGlkOm5kYTp0ZXN0bmV0OjB4MjIyMTM3ZmIwMDk5MTE1YmQwYjA0NDZjNGQ2NmM4MWNjZjQxZTBiYi9jcmVkZW50aWFscy9zdGF0dXMvMCMxNyIsInN0YXR1c0xpc3RDcmVkZW50aWFsIjoiaHR0cHM6Ly9hdXRoLWRldi5waWxhLnZuL2FwaS92MS9pc3N1ZXJzL2RpZDpuZGE6dGVzdG5ldDoweDIyMjEzN2ZiMDA5OTExNWJkMGIwNDQ2YzRkNjZjODFjY2Y0MWUwYmIvY3JlZGVudGlhbHMvc3RhdHVzLzAiLCJzdGF0dXNMaXN0SW5kZXgiOiIxNyIsInN0YXR1c1B1cnBvc2UiOiJyZXZvY2F0aW9uIiwidHlwZSI6IkJpdHN0cmluZ1N0YXR1c0xpc3RFbnRyeSJ9LCJjcmVkZW50aWFsU3ViamVjdCI6eyJhZ2UiOjEwLCJkZXBhcnRtZW50IjoiRW5naW5lZXJpbmciLCJpZCI6ImRpZDpuZGE6dGVzdG5ldDoweDIyMjEzN2ZiMDA5OTExNWJkMGIwNDQ2YzRkNjZjODFjY2Y0MWUwYmIiLCJuYW1lIjoiVGVzdCBDcmVhdGUiLCJzYWxhcnkiOjUwMDAwfSwiaWQiOiJkaWQ6bmRhOnRlc3RuZXQ6YzBhMTQ1N2EtZGE3Zi00ZWE0LTlmZjgtMWE4MTAxYWY1YjIwIiwiaXNzdWVyIjoiZGlkOm5kYTp0ZXN0bmV0OjB4MjIyMTM3ZmIwMDk5MTE1YmQwYjA0NDZjNGQ2NmM4MWNjZjQxZTBiYiIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInZhbGlkRnJvbSI6IjIwMjUtMDgtMjlUMDk6MDE6NTFaIiwidmFsaWRVbnRpbCI6IjIwMjYtMDgtMjlUMDk6MDE6NTFaIn19.95u0K9WTZdmAr-s7jCTppk75VqpM-vyMZVARhopZBoE418g4T3tT_1UhNZMrgFmPgvEqvLl1xJ-ZvHXqpwMKqw"

	_, err := ParseCredential([]byte(notRevokedJWT), WithCheckRevocation())
	assert.NoError(t, err)
}

func TestCreateCredentialJWT(t *testing.T) {
	// Initialize the credential package
	Init("https://auth-dev.pila.vn/api/v1/did")

	// Test data
	testIssuerPrivateKey := "e5c9a597b20e13627a3850d38439b61ec9ee7aefd77c7cb6c01dc3866e1db19a"
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
	err = credential.AddProof(testIssuerPrivateKey)
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
	parsedCredential, err := ParseJWTCredential(jwtToken)
	assert.NoError(t, err, "Failed to parse JWT credential")
	assert.NotNil(t, parsedCredential, "Parsed credential should not be nil")

	// Verify the credential type
	_, ok = parsedCredential.(*JWTCredential)
	assert.True(t, ok, "Credential type should be JWT")

	// For JWT credentials, we can check the payload directly
	jwtCred := parsedCredential.(*JWTCredential)
	payloadData, err := jwtCred.GetContents()
	if err != nil {
		t.Fatalf("GetContents failed: %v", err)
	}
	var payloadMap map[string]interface{}
	err = json.Unmarshal(payloadData, &payloadMap)
	if err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}
	assert.Equal(t, credentialContents.ID, payloadMap["id"], "Credential ID should match")
	assert.Equal(t, credentialContents.Issuer, payloadMap["issuer"], "Issuer should match")

	// Verify the credential
	err = credential.Verify()
	assert.NoError(t, err, "Failed to verify credential")
}

func TestCredentialSignatureFlows(t *testing.T) {
	// Initialize the credential package
	Init("https://auth-dev.pila.vn/api/v1/did")

	// Test data
	testIssuerPrivateKey := "e5c9a597b20e13627a3850d38439b61ec9ee7aefd77c7cb6c01dc3866e1db19a"
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

	t.Run("JSON Credential - AddProof Flow", func(t *testing.T) {
		// Create JSON credential
		credential, err := NewJSONCredential(credentialContents)
		assert.NoError(t, err, "Failed to create JSON credential")

		// Add proof using AddProof method
		err = credential.AddProof(testIssuerPrivateKey)
		assert.NoError(t, err, "Failed to add proof to JSON credential")

		// Verify the credential
		err = credential.Verify()
		assert.NoError(t, err, "Failed to verify JSON credential with proof")

		// Serialize and verify it has proof
		serialized, err := credential.Serialize()
		assert.NoError(t, err, "Failed to serialize JSON credential")

		// Check that serialized credential contains proof
		credMap, ok := serialized.(map[string]interface{})
		assert.True(t, ok, "Serialized credential should be a map")
		assert.Contains(t, credMap, "proof", "Serialized credential should contain proof")
	})

	t.Run("JSON Credential - GetSigningInput + AddCustomProof Flow", func(t *testing.T) {
		// Create JSON credential
		credential, err := NewJSONCredential(credentialContents)
		assert.NoError(t, err, "Failed to create JSON credential")

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
		assert.NoError(t, err, "Failed to add custom proof to JSON credential")

		// Serialize and verify it has proof
		serialized, err := credential.Serialize()
		assert.NoError(t, err, "Failed to serialize JSON credential with custom proof")

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
		err = credential.AddProof(testIssuerPrivateKey)
		assert.NoError(t, err, "Failed to add proof to JWT credential")

		// Serialize to get JWT token
		serialized, err := credential.Serialize()
		assert.NoError(t, err, "Failed to serialize JWT credential")

		jwtToken, ok := serialized.(string)
		assert.True(t, ok, "Serialized JWT credential should be a string")
		assert.NotEmpty(t, jwtToken, "JWT token should not be empty")
		assert.Equal(t, 3, len(strings.Split(jwtToken, ".")), "JWT should have 3 parts")
		byteJwkToken, err := json.Marshal(jwtToken)
		if err != nil {
			t.Fatalf("Failed to marshal JWT credential: %v", err)
		}
		// Parse and verify the JWT credential
		parsedCredential, err := ParseCredential(byteJwkToken)
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
		signatureBytes, err := signer.Sign(string(signingInput), testIssuerPrivateKey)
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
		credential, err := NewJSONCredential(credentialContents)
		assert.NoError(t, err, "Failed to create JSON credential")

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
		ID:   "https://auth-dev.pila.vn/api/v1/schemas/7250251f-141e-47a2-aa5f-a5d3499d30da",
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

	embededCredential, err := NewJSONCredential(credentialContents, WithSchemaValidation())
	if err != nil {
		t.Fatalf("Failed to create JSON credential: %v", err)
	}

	// add proof
	err = embededCredential.AddProof(issuerPrivateKey)
	if err != nil {
		t.Fatalf("Failed to add proof: %v", err)
	}

	// verify
	err = embededCredential.Verify(WithSchemaValidation())
	if err != nil {
		t.Fatalf("Failed to verify JSON credential: %v", err)
	}
}

// Helper function to create base credential contents with default values
func createBaseCredentialContents(issuerDID string, customFields map[string]interface{}) CredentialContents {
	schema := Schema{
		ID:   "https://auth-dev.pila.vn/api/v1/schemas/7250251f-141e-47a2-aa5f-a5d3499d30da",
		Type: "JsonSchema",
	}

	return CredentialContents{
		Context: []interface{}{"https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"},
		Schemas: []Schema{schema},
		Subject: []Subject{Subject{
			ID:           "did:nda:testnet:0x78e43d3bd308b0522c8f6fcfb4785d9b841556c8",
			CustomFields: customFields,
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
}

// Helper function to create valid default custom fields
func createValidCustomFields() map[string]interface{} {
	return map[string]interface{}{
		"age":        10,
		"name":       "Test Create",
		"salary":     50000,
		"department": "Engineering",
	}
}

// Test constants
const (
	testIssuerPrivateKey = "5a369512f8f8a0e6973abd6241ce38103c232966c6153bf8377ac85582812aa4"
	testIssuerDID        = "did:nda:testnet:0x084ce14ef7c6e76a5ff3d58c160de7e1d385d9ee"
)

func TestCreateJWTCredentialWithValidateSchema(t *testing.T) {
	credentialContents := createBaseCredentialContents(testIssuerDID, createValidCustomFields())

	jwtCredential, err := NewJWTCredential(credentialContents, WithSchemaValidation())
	if err != nil {
		t.Fatalf("Failed to create JWT credential: %v", err)
	}

	// add proof
	err = jwtCredential.AddProof(testIssuerPrivateKey)
	if err != nil {
		t.Fatalf("Failed to add proof: %v", err)
	}

	// verify
	err = jwtCredential.Verify(WithSchemaValidation())
	if err != nil {
		t.Fatalf("Failed to verify JWT credential: %v", err)
	}
}

func TestJWTCredentialAddCustomProofMustEqualsToAddProof(t *testing.T) {
	// Create credential with empty custom fields for this test
	credentialContents := createBaseCredentialContents(testIssuerDID, createValidCustomFields())
	jwtCredential, err := NewJWTCredential(credentialContents, WithSchemaValidation())
	if err != nil {
		t.Fatalf("Failed to create JWT credential: %v", err)
	}

	// add proof
	err = jwtCredential.AddProof(testIssuerPrivateKey)
	if err != nil {
		t.Fatalf("Failed to add proof: %v", err)
	}

	// another jwt with custom proof
	anotherJwtCredential, err := NewJWTCredential(credentialContents, WithSchemaValidation())
	if err != nil {
		t.Fatalf("Failed to create another JWT credential: %v", err)
	}

	// calculate signature
	getSigningInput, err := anotherJwtCredential.GetSigningInput()
	if err != nil {
		t.Fatalf("Failed to get signing input: %v", err)
	}
	signer := jwt.SigningMethodES256K{}
	signatureBytes, err := signer.Sign(string(getSigningInput), testIssuerPrivateKey)
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
	err = anotherJwtCredential.Verify(WithSchemaValidation())
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

func TestCreateJWTCredentialWithValidateSchemaFailInvalidFieldValue(t *testing.T) {
	// Invalid field value - negative age
	customFields := map[string]interface{}{
		"name":       "Test Create",
		"salary":     -50000,
		"department": "Engineering",
	}
	credentialContents := createBaseCredentialContents(testIssuerDID, customFields)

	_, err := NewJWTCredential(credentialContents, WithSchemaValidation())
	if err == nil {
		t.Fatalf("Expected validation error for invalid field value, but got no error")
	}
}

func TestCreateJWTCredentialWithValidateSchemaFailEmptySubject(t *testing.T) {
	// Create credential with empty subject array
	schema := Schema{
		ID:   "https://auth-dev.pila.vn/api/v1/schemas/7250251f-141e-47a2-aa5f-a5d3499d30da",
		Type: "JsonSchema",
	}
	credentialContents := CredentialContents{
		Context:    []interface{}{"https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"},
		Schemas:    []Schema{schema},
		Subject:    []Subject{}, // Empty subject array
		ID:         "did:nda:testnet:f5dd72fe-75d3-4a3b-b679-8b9fb5df5177",
		Issuer:     testIssuerDID,
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

	_, err := NewJWTCredential(credentialContents, WithSchemaValidation())
	if err == nil {
		t.Fatalf("Expected validation error for empty subject, but got no error")
	}
}

func TestCreateJWTCredentialWithValidateSchemaFailInvalidDepartment(t *testing.T) {
	customFields := map[string]interface{}{
		"age":        10,
		"name":       "Test Create",
		"department": 100,
		"salary":     100000,
	}
	credentialContents := createBaseCredentialContents(testIssuerDID, customFields)

	_, err := NewJWTCredential(credentialContents, WithSchemaValidation())
	if err == nil {
		t.Fatalf("Expected validation error for invalid department field, but got no error")
	}
}

func TestCreateJWTCredentialWithValidateSchemaFailInvalidSalaryType(t *testing.T) {
	// Invalid salary type - should be number, not string
	customFields := map[string]interface{}{
		"age":        10,
		"name":       "Test Create",
		"salary":     "not_a_number",
		"department": "Engineering",
	}
	credentialContents := createBaseCredentialContents(testIssuerDID, customFields)

	_, err := NewJWTCredential(credentialContents, WithSchemaValidation())
	if err == nil {
		t.Fatalf("Expected validation error for invalid salary type, but got no error")
	}
}

func TestCreateJWTCredentialWithValidateSchemaFailNegativeSalary(t *testing.T) {
	// Invalid salary value - negative salary
	customFields := map[string]interface{}{
		"age":        10,
		"name":       "Test Create",
		"salary":     -1000,
		"department": "Engineering",
	}
	credentialContents := createBaseCredentialContents(testIssuerDID, customFields)

	_, err := NewJWTCredential(credentialContents, WithSchemaValidation())
	if err == nil {
		t.Fatalf("Expected validation error for negative salary, but got no error")
	}
}

func TestSerializeJSONCredential(t *testing.T) {
	// create a json credential
	credentialContents := createBaseCredentialContents(testIssuerDID, createValidCustomFields())
	jsonCredential, err := NewJSONCredential(credentialContents, WithSchemaValidation())
	if err != nil {
		t.Fatalf("Failed to create JSON credential: %v", err)
	}
	// add proof
	err = jsonCredential.AddProof(testIssuerPrivateKey)
	if err != nil {
		t.Fatalf("Failed to add proof: %v", err)
	}
	// serialize the credential
	serialized, err := jsonCredential.Serialize()
	if err != nil {
		t.Fatalf("Failed to serialize JSON credential: %v", err)
	}
	// serialized must be a json object
	bytes, err := json.Marshal(serialized)
	if err != nil {
		t.Fatalf("Failed to marshal JSON credential: %v", err)
	}
	assert.True(t, json.Valid(bytes), "Serialized credential must be a json object")
}

func TestNewJWTCredential_WithSDDisclosures_SerializesSDJWT(t *testing.T) {
	vcc := CredentialContents{
		Context: []interface{}{"https://www.w3.org/2018/credentials/v1"},
		ID:      "urn:uuid:1234",
		Issuer:  "did:example:issuer",
		Types:   []string{"VerifiableCredential"},
		Subject: []Subject{
			{
				ID: "did:example:subject1",
				CustomFields: map[string]interface{}{
					"name": "Alice",
				},
			},
		},
		ValidFrom:  time.Now(),
		ValidUntil: time.Now().Add(24 * time.Hour),
	}

	// Use simple, syntactically valid disclosures to avoid depending on BuildDisclosures behavior here.
	arr := []interface{}{"salt", "x", "y"}
	b, _ := json.Marshal(arr)
	D := base64.RawURLEncoding.EncodeToString(b)
	disclosures := []string{D}

	// selective paths for name
	selectivePaths := []string{"credentialSubject.name"}

	cred, err := NewJWTCredential(vcc, WithSDDisclosures(disclosures), WithSDSelectivePaths(selectivePaths))
	assert.NoError(t, err)
	assert.NotNil(t, cred)

	serialized, err := cred.Serialize()
	assert.NoError(t, err)

	s, ok := serialized.(string)
	if !ok {
		t.Fatalf("expected serialized credential to be string, got %T", serialized)
	}

	// Inspect issuer-signed JWT payload to ensure "name" is hidden.
	parts := strings.SplitN(s, "~", 2)
	if len(parts) < 2 {
		t.Fatalf("expected SD-JWT with disclosures, got %q", s)
	}
	jwtPart := parts[0]

	segs := strings.Split(jwtPart, ".")
	if len(segs) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d", len(segs))
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(segs[1])
	assert.NoError(t, err)

	var payload map[string]interface{}
	err = json.Unmarshal(payloadBytes, &payload)
	assert.NoError(t, err)

	vcAny, ok := payload["vc"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected vc map in JWT payload")
	}
	csAny, ok := vcAny["credentialSubject"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected credentialSubject map in vc")
	}

	if _, has := csAny["name"]; has {
		t.Fatalf("expected name to be hidden in issuer-signed JWT payload")
	}

	// Ensure SD-JWT format
	assert.True(t, sdjwt.IsSDJWT(s), "expected SD-JWT format")

	// Parse back and ensure we still get a JWTCredential
	parsed, err := ParseCredential([]byte(s))
	assert.NoError(t, err)
	_, ok = parsed.(*JWTCredential)
	assert.True(t, ok, "expected parsed credential to be JWTCredential")
}

func TestNewJWTCredential_WithSDSelectivePaths_ArrayElement(t *testing.T) {
	vcc := CredentialContents{
		Context: []interface{}{"https://www.w3.org/2018/credentials/v1"},
		ID:      "urn:uuid:array",
		Issuer:  "did:example:issuer",
		Types:   []string{"VerifiableCredential"},
		Subject: []Subject{
			{
				ID: "did:example:subject1",
				CustomFields: map[string]interface{}{
					"emails": []interface{}{"a@example.com", "b@example.com", "c@example.com"},
				},
			},
		},
		ValidFrom:  time.Now(),
		ValidUntil: time.Now().Add(24 * time.Hour),
	}

	selectivePaths := []string{"credentialSubject.emails[1]"}

	cred, err := NewJWTCredential(vcc, WithSDSelectivePaths(selectivePaths))
	assert.NoError(t, err)
	assert.NotNil(t, cred)

	serialized, err := cred.Serialize()
	assert.NoError(t, err)

	s, ok := serialized.(string)
	if !ok {
		t.Fatalf("expected serialized credential to be string, got %T", serialized)
	}

	// Inspect issuer-signed JWT payload to ensure emails[1] is hidden via placeholder.
	parts := strings.SplitN(s, "~", 2)
	if len(parts) < 2 {
		t.Fatalf("expected SD-JWT with disclosures, got %q", s)
	}
	jwtPart := parts[0]

	segs := strings.Split(jwtPart, ".")
	if len(segs) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d", len(segs))
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(segs[1])
	assert.NoError(t, err)

	var payload map[string]interface{}
	err = json.Unmarshal(payloadBytes, &payload)
	assert.NoError(t, err)

	vcAny, ok := payload["vc"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected vc map in JWT payload")
	}
	csAny, ok := vcAny["credentialSubject"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected credentialSubject map in vc")
	}

	rawEmails, ok := csAny["emails"]
	if !ok {
		t.Fatalf("expected emails in credentialSubject")
	}
	emailsArr, ok := rawEmails.([]interface{})
	if !ok {
		t.Fatalf("expected emails to be array, got %T", rawEmails)
	}
	if len(emailsArr) != 3 {
		t.Fatalf("expected 3 emails elements, got %d", len(emailsArr))
	}
	if _, isPlaceholder := emailsArr[1].(map[string]interface{}); !isPlaceholder {
		t.Fatalf("expected emails[1] to be SD-JWT placeholder, got %T", emailsArr[1])
	}

	assert.True(t, sdjwt.IsSDJWT(s), "expected SD-JWT format")

	parsed, err := ParseCredential([]byte(s))
	assert.NoError(t, err)

	jwtCred, ok := parsed.(*JWTCredential)
	assert.True(t, ok, "expected parsed credential to be JWTCredential")

	payloadBytes2, err := jwtCred.GetContents()
	assert.NoError(t, err)

	var m2 map[string]interface{}
	err = json.Unmarshal(payloadBytes2, &m2)
	assert.NoError(t, err)

	cs2, ok := m2["credentialSubject"].(map[string]interface{})
	assert.True(t, ok)

	emails2, ok := cs2["emails"].([]interface{})
	assert.True(t, ok)
	assert.Equal(t, []interface{}{"a@example.com", "b@example.com", "c@example.com"}, emails2)
}

func TestNewJWTCredential_WithSDSelectivePaths_RecursiveObject(t *testing.T) {
	vcc := CredentialContents{
		Context: []interface{}{"https://www.w3.org/2018/credentials/v1"},
		ID:      "urn:uuid:recursive",
		Issuer:  "did:example:issuer",
		Types:   []string{"VerifiableCredential"},
		Subject: []Subject{
			{
				ID: "did:example:subject1",
				CustomFields: map[string]interface{}{
					"profile": map[string]interface{}{
						"name": "Alice",
						"age":  float64(30),
					},
				},
			},
		},
		ValidFrom:  time.Now(),
		ValidUntil: time.Now().Add(24 * time.Hour),
	}

	selectivePaths := []string{"credentialSubject.profile.name"}

	cred, err := NewJWTCredential(vcc, WithSDSelectivePaths(selectivePaths))
	assert.NoError(t, err)
	assert.NotNil(t, cred)

	serialized, err := cred.Serialize()
	assert.NoError(t, err)

	s, ok := serialized.(string)
	if !ok {
		t.Fatalf("expected serialized credential to be string, got %T", serialized)
	}

	// Inspect issuer-signed JWT payload to ensure profile.name is hidden.
	parts := strings.SplitN(s, "~", 2)
	if len(parts) < 2 {
		t.Fatalf("expected SD-JWT with disclosures, got %q", s)
	}
	jwtPart := parts[0]

	segs := strings.Split(jwtPart, ".")
	if len(segs) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d", len(segs))
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(segs[1])
	assert.NoError(t, err)

	var payload map[string]interface{}
	err = json.Unmarshal(payloadBytes, &payload)
	assert.NoError(t, err)

	vcAny, ok := payload["vc"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected vc map in JWT payload")
	}
	csAny, ok := vcAny["credentialSubject"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected credentialSubject map in vc")
	}

	rawProfile, ok := csAny["profile"]
	if !ok {
		t.Fatalf("expected profile in credentialSubject")
	}
	profile, ok := rawProfile.(map[string]interface{})
	if !ok {
		t.Fatalf("expected profile to be object, got %T", rawProfile)
	}

	if _, has := profile["name"]; has {
		t.Fatalf("expected profile.name to be hidden in issuer-signed JWT payload")
	}
	if _, has := profile["_sd"]; !has {
		t.Fatalf("expected profile to contain _sd digests")
	}

	assert.True(t, sdjwt.IsSDJWT(s), "expected SD-JWT format")

	parsed, err := ParseCredential([]byte(s))
	assert.NoError(t, err)

	jwtCred, ok := parsed.(*JWTCredential)
	assert.True(t, ok, "expected parsed credential to be JWTCredential")

	payloadBytes2, err := jwtCred.GetContents()
	assert.NoError(t, err)

	var m2 map[string]interface{}
	err = json.Unmarshal(payloadBytes2, &m2)
	assert.NoError(t, err)

	cs2, ok := m2["credentialSubject"].(map[string]interface{})
	assert.True(t, ok)

	profile2, ok := cs2["profile"].(map[string]interface{})
	assert.True(t, ok)

	assert.Equal(t, "Alice", profile2["name"])
	assert.Equal(t, float64(30), profile2["age"])
}

func TestSDJWT_HolderFlow(t *testing.T) {
	vcc := CredentialContents{
		Context: []interface{}{"https://www.w3.org/2018/credentials/v1"},
		ID:      "urn:uuid:holder-test",
		Issuer:  "did:example:issuer",
		Types:   []string{"VerifiableCredential"},
		Subject: []Subject{
			{
				ID: "did:example:subject1",
				CustomFields: map[string]interface{}{
					"firstname": "Alice",
					"email":     "alice@example.com",
				},
			},
		},
		ValidFrom:  time.Now(),
		ValidUntil: time.Now().Add(24 * time.Hour),
	}
	selectivePaths := []string{"credentialSubject.firstname", "credentialSubject.email"}

	cred, err := NewJWTCredential(vcc, WithSDSelectivePaths(selectivePaths))
	assert.NoError(t, err)
	serialized, err := cred.Serialize()
	assert.NoError(t, err)
	s, ok := serialized.(string)
	assert.True(t, ok)
	assert.True(t, sdjwt.IsSDJWT(s), "expected SD-JWT format")

	parsed, err := sdjwt.Parse(s)
	assert.NoError(t, err)

	disclosures := parsed.Disclosures
	assert.Len(t, disclosures, 2, "expected two disclosures (firstname, email)")

	issuerJWT := parsed.BaseJWT
	assert.NotEmpty(t, issuerJWT)
	assert.True(t, sdjwt.IsSDJWT(issuerJWT+"~"+disclosures[0]+"~"), "issuer JWT should form valid SD-JWT with disclosures")

	presentation := sdjwt.BuildSDJWTPresentation(issuerJWT, []string{disclosures[0]})
	assert.True(t, sdjwt.IsSDJWT(presentation))

	parsedPres, err := ParseCredential([]byte(presentation))
	assert.NoError(t, err)
	contents, err := parsedPres.GetContents()
	assert.NoError(t, err)
	var m map[string]interface{}
	err = json.Unmarshal(contents, &m)
	assert.NoError(t, err)
	cs, ok := m["credentialSubject"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "Alice", cs["firstname"])
	_, hasEmail := cs["email"]
	assert.False(t, hasEmail, "Holder chose not to disclose email; verifier should not see it")

	emptyPres := sdjwt.BuildSDJWTPresentation(issuerJWT, nil)
	assert.Equal(t, issuerJWT, emptyPres, "presentation with no disclosures returns bare JWT")
}

func TestAddSelectiveDisclosures(t *testing.T) {
	vcc := CredentialContents{
		Context: []interface{}{"https://www.w3.org/2018/credentials/v1"},
		ID:      "urn:uuid:add-disclosure-test",
		Issuer:  "did:example:issuer",
		Types:   []string{"VerifiableCredential"},
		Subject: []Subject{
			{
				ID: "did:example:subject1",
				CustomFields: map[string]interface{}{
					"firstname": "Alice",
					"lastname":  "Smith",
					"email":     "alice@example.com",
					"phone":     "+1234567890",
				},
			},
		},
		ValidFrom:  time.Now(),
		ValidUntil: time.Now().Add(24 * time.Hour),
	}

	// Step 1: Issue SD-JWT with initial selective disclosure (firstname only)
	initialPaths := []string{"credentialSubject.firstname"}
	cred, err := NewJWTCredential(vcc, WithSDSelectivePaths(initialPaths))
	assert.NoError(t, err)

	// Sign the credential
	err = cred.AddProof(testIssuerPrivateKey)
	assert.NoError(t, err)

	// Serialize to get SD-JWT string
	initialSDJWT, err := cred.Serialize()
	assert.NoError(t, err)
	initialStr, ok := initialSDJWT.(string)
	assert.True(t, ok)
	assert.True(t, sdjwt.IsSDJWT(initialStr), "expected SD-JWT format")

	// Step 2: Parse the SD-JWT
	parsedCred, err := ParseCredential([]byte(initialStr))
	assert.NoError(t, err)

	// Step 3: Add more selective disclosures (email and phone)
	// Note: Adding disclosures changes the payload, so we need to re-sign
	additionalPaths := []string{"credentialSubject.email", "credentialSubject.phone"}
	newCred, err := parsedCred.AddSelectiveDisclosures(additionalPaths)
	assert.NoError(t, err)

	// The new credential has more disclosures but is not yet signed
	// Verify that disclosures are merged
	newSerialized, err := newCred.Serialize()
	assert.NoError(t, err)
	newStr, ok := newSerialized.(string)
	assert.True(t, ok)

	// Parse the new SD-JWT to verify disclosures are present
	parsedNew, err := sdjwt.Parse(newStr)
	assert.NoError(t, err)
	assert.Len(t, parsedNew.Disclosures, 3, "expected 3 disclosures: firstname + email + phone")

	// Step 4: Re-sign the credential with new disclosures
	err = newCred.AddProof(testIssuerPrivateKey)
	assert.NoError(t, err)

	// Step 5: Serialize and verify the final SD-JWT
	finalSDJWT, err := newCred.Serialize()
	assert.NoError(t, err)
	finalStr, ok := finalSDJWT.(string)
	assert.True(t, ok)
	assert.True(t, sdjwt.IsSDJWT(finalStr), "expected SD-JWT format after re-sign")

	// Verify the final SD-JWT can be parsed and reconstructed correctly
	parsedFinal, err := sdjwt.Parse(finalStr)
	assert.NoError(t, err)
	assert.Len(t, parsedFinal.Disclosures, 3)

	// Reconstruct the credential to verify all disclosures work
	reconstructed, err := sdjwt.Reconstruct(
		func() map[string]interface{} {
			parts := strings.Split(parsedFinal.BaseJWT, ".")
			payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
			var payload map[string]interface{}
			json.Unmarshal(payloadBytes, &payload)
			vcData := payload["vc"].(map[string]interface{})
			return vcData
		}(),
		parsedFinal.Disclosures,
		true,
	)
	assert.NoError(t, err)
	assert.Equal(t, "Alice", reconstructed["credentialSubject"].(map[string]interface{})["firstname"])
	assert.Equal(t, "alice@example.com", reconstructed["credentialSubject"].(map[string]interface{})["email"])
	assert.Equal(t, "+1234567890", reconstructed["credentialSubject"].(map[string]interface{})["phone"])
}

func TestAddSelectiveDisclosures_EmptyPaths(t *testing.T) {
	vcc := CredentialContents{
		Context: []interface{}{"https://www.w3.org/2018/credentials/v1"},
		ID:      "urn:uuid:add-disclosure-test-empty",
		Issuer:  "did:example:issuer",
		Types:   []string{"VerifiableCredential"},
		Subject: []Subject{
			{
				ID: "did:example:subject1",
				CustomFields: map[string]interface{}{
					"firstname": "Bob",
				},
			},
		},
		ValidFrom:  time.Now(),
		ValidUntil: time.Now().Add(24 * time.Hour),
	}

	// Create credential without selective disclosures
	cred, err := NewJWTCredential(vcc)
	assert.NoError(t, err)

	// Try to add empty selective paths - should error
	_, err = cred.AddSelectiveDisclosures([]string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "selective paths cannot be empty")
}

func TestAddSelectiveDisclosures_PlainJWT(t *testing.T) {
	vcc := CredentialContents{
		Context: []interface{}{"https://www.w3.org/2018/credentials/v1"},
		ID:      "urn:uuid:add-disclosure-plain-jwt",
		Issuer:  "did:example:issuer",
		Types:   []string{"VerifiableCredential"},
		Subject: []Subject{
			{
				ID: "did:example:subject1",
				CustomFields: map[string]interface{}{
					"firstname": "Charlie",
				},
			},
		},
		ValidFrom:  time.Now(),
		ValidUntil: time.Now().Add(24 * time.Hour),
	}

	// Create plain JWT (no selective disclosures)
	cred, err := NewJWTCredential(vcc)
	assert.NoError(t, err)

	// Add selective disclosures to plain JWT - should work
	newCred, err := cred.AddSelectiveDisclosures([]string{"credentialSubject.firstname"})
	assert.NoError(t, err)

	// Verify it returns SD-JWT format
	serialized, err := newCred.Serialize()
	assert.NoError(t, err)
	str, ok := serialized.(string)
	assert.True(t, ok)
	assert.True(t, sdjwt.IsSDJWT(str), "expected SD-JWT format after adding disclosures")
}

// TestWithSDDecoyDigests_Array tests decoy digests for array elements
func TestWithSDDecoyDigests_Array(t *testing.T) {
	vcc := CredentialContents{
		Context: []interface{}{"https://www.w3.org/2018/credentials/v1"},
		ID:      "urn:uuid:decoy-test-array",
		Issuer:  "did:example:issuer",
		Types:   []string{"VerifiableCredential"},
		Subject: []Subject{
			{
				ID: "did:example:subject1",
				CustomFields: map[string]interface{}{
					"emails": []interface{}{"alice@example.com", "alice@work.com"},
				},
			},
		},
		ValidFrom:  time.Now(),
		ValidUntil: time.Now().Add(24 * time.Hour),
	}

	// Issue SD-JWT with selective disclosure on first email and decoy on second
	cred, err := NewJWTCredential(vcc,
		WithSDSelectivePaths([]string{"credentialSubject.emails[0]"}),
		WithSDDecoyDigests([]Decoy{
			{Path: "credentialSubject.emails[1]", Count: 1},
		}),
	)
	assert.NoError(t, err)
	assert.NotNil(t, cred)
}

// TestExtractField tests the ExtractField method for both JWT and JSON credentials
func TestExtractField(t *testing.T) {
	// Test with JSONCredential
	jsonCred := `{
		"@context": ["https://www.w3.org/2018/credentials/v1"],
		"id": "urn:uuid:extract-test",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {
			"id": "did:example:subject",
			"name": "John Doe",
			"age": 30,
			"address": {
				"city": "Hanoi",
				"country": "Vietnam"
			},
			"emails": ["john@example.com", "john@work.com"]
		}
	}`

	cred, err := ParseCredential([]byte(jsonCred))
	assert.NoError(t, err)

	// Test extracting top-level field
	name := cred.ExtractField("credentialSubject.name")
	assert.Equal(t, "John Doe", name)

	// Test extracting nested field
	city := cred.ExtractField("credentialSubject.address.city")
	assert.Equal(t, "Hanoi", city)

	// Test extracting array element (not supported, should return nil for now)
	email := cred.ExtractField("credentialSubject.emails[0]")
	assert.Nil(t, email) // Current implementation doesn't support array index

	// Test extracting non-existent field
	notExist := cred.ExtractField("credentialSubject.nonexistent")
	assert.Nil(t, notExist)

	// Test with nested path that doesn't exist
	notExistNested := cred.ExtractField("credentialSubject.address.zipcode")
	assert.Nil(t, notExistNested)

	// Test with JWT credential
	vcc := CredentialContents{
		Context: []interface{}{"https://www.w3.org/2018/credentials/v1"},
		ID:      "urn:uuid:jwt-extract-test",
		Issuer:  "did:example:issuer",
		Types:   []string{"VerifiableCredential"},
		Subject: []Subject{
			{
				ID: "did:example:subject1",
				CustomFields: map[string]interface{}{
					"name":    "Alice",
					"age":     float64(25),
					"address": map[string]interface{}{"city": "HoChiMinh"},
				},
			},
		},
		ValidFrom:  time.Now(),
		ValidUntil: time.Now().Add(24 * time.Hour),
	}

	jwtCred, err := NewJWTCredential(vcc)
	assert.NoError(t, err)

	// Test extracting from JWT credential
	jwtName := jwtCred.ExtractField("credentialSubject.name")
	assert.Equal(t, "Alice", jwtName)

	jwtCity := jwtCred.ExtractField("credentialSubject.address.city")
	assert.Equal(t, "HoChiMinh", jwtCity)

	// Test non-existent field on JWT credential
	jwtNotExist := jwtCred.ExtractField("credentialSubject.email")
	assert.Nil(t, jwtNotExist)
}

// TestExtractField_EdgeCases tests edge cases for ExtractField
func TestExtractField_EdgeCases(t *testing.T) {
	jsonCred := `{
		"@context": ["https://www.w3.org/2018/credentials/v1"],
		"id": "urn:uuid:edge-test",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {
			"id": "did:example:subject"
		}
	}`

	cred, err := ParseCredential([]byte(jsonCred))
	assert.NoError(t, err)

	// Test empty path
	emptyPath := cred.ExtractField("")
	assert.Nil(t, emptyPath)

	// Test single-level path on root
	id := cred.ExtractField("id")
	assert.Equal(t, "urn:uuid:edge-test", id)

	// Test with empty credential
	emptyJsonCred := `{}`
	emptyCred, err := ParseCredential([]byte(emptyJsonCred))
	assert.NoError(t, err)

	emptyResult := emptyCred.ExtractField("any.path")
	assert.Nil(t, emptyResult)
}
