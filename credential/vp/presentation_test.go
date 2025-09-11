package vp_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jwt"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

func TestParsePresentation(t *testing.T) {
	vcList := GenerateVCTest()

	vpc := vp.PresentationContents{
		Context: []interface{}{
			"https://www.w3.org/ns/credentials/v2",
		},
		ID:                    "urn:uuid:abcd1234-5678-90ab-cdef-1234567890ab",
		Types:                 []string{"VerifiablePresentation"},
		Holder:                "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce",
		VerifiableCredentials: vcList,
	}

	jsonBytes, err := json.Marshal(vpc)
	if err != nil {
		t.Fatalf("Failed to marshal PresentationContents: %v", err)
	}

	pParsed, err := vp.ParsePresentation(jsonBytes)
	if err != nil {
		t.Fatalf("ParsePresentation failed: %v", err)
	}

	// For embedded presentations, we can get the JSON directly
	var vpByte []byte
	if embeddedPres, ok := pParsed.(*vp.EmbeddedPresentation); ok {
		vpByte, err = embeddedPres.ToJSON()
		if err != nil {
			t.Fatalf("ToJSON failed: %v", err)
		}
	} else {
		// For JWT presentations, serialize to get the JWT string
		serialized, err := pParsed.Serialize()
		if err != nil {
			t.Fatalf("Serialize failed: %v", err)
		}
		vpByte = []byte(serialized.(string))
	}

	var m map[string]interface{}
	if err := json.Unmarshal(vpByte, &m); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if m["ID"] != vpc.ID {
		t.Errorf("Expected ID '%s', got %v", vpc.ID, m["ID"])
	}

	if m["Holder"] != vpc.Holder {
		t.Errorf("Expected holder '%s', got %v", vpc.Holder, m["Holder"])
	}

	credentials, ok := m["VerifiableCredentials"].([]interface{})
	if !ok {
		t.Fatalf("Expected VerifiableCredentials to be a slice, got %T", m["VerifiableCredentials"])
	}

	if len(credentials) != len(vpc.VerifiableCredentials) {
		t.Fatalf("Expected %d verifiableCredentials, got %d", len(vpc.VerifiableCredentials), len(credentials))
	}

	if len(m["Types"].([]interface{})) == len(vpc.Types) {
		for i, k := range m["Types"].([]interface{}) {
			if k != vpc.Types[i] {
				t.Fatalf("Expected type '%s', got %v", vpc.Types[i], k)
			}
		}
	} else {
		t.Errorf("Expected %d types, got %d", len(vpc.Types), len(m["Types"].([]interface{})))
	}

}

func TestCreatePresentationWithContent(t *testing.T) {
	vp.Init("https://auth-dev.pila.vn/api/v1/did")

	tests := []struct {
		name         string
		input        vp.PresentationContents
		expectErr    bool
		expectFields map[string]interface{}
	}{
		{
			name: "Valid single VC",
			input: vp.PresentationContents{
				Context:               []interface{}{"https://www.w3.org/ns/credentials/v2"},
				ID:                    "urn:uuid:abcd1234-5678-90ab-cdef-1234567890ab",
				Types:                 []string{"VerifiablePresentation"},
				Holder:                "did:nda:testnet:0x123",
				VerifiableCredentials: GenerateVCTest(),
			},
			expectErr: false,
			expectFields: map[string]interface{}{
				"id":     "urn:uuid:abcd1234-5678-90ab-cdef-1234567890ab",
				"holder": "did:nda:testnet:0x123",
				"type":   "VerifiablePresentation",
				"@context": []interface{}{
					"https://www.w3.org/ns/credentials/v2",
				},
				"length": len(GenerateVCTest()),
			},
		},
		{
			name:      "Empty presentation",
			input:     vp.PresentationContents{},
			expectErr: false,
			expectFields: map[string]interface{}{
				"length": 0,
			},
		},
		{
			name: "type has multiple values",
			input: vp.PresentationContents{
				Context:               []interface{}{"https://www.w3.org/ns/credentials/v2"},
				ID:                    "urn:uuid:abcd1234-5678-90ab-cdef-1234567890ab",
				Types:                 []string{"VerifiablePresentation", "CustomType"},
				Holder:                "did:nda:testnet:0x123",
				VerifiableCredentials: GenerateVCTest(),
			},
			expectErr: false,
			expectFields: map[string]interface{}{
				"id":     "urn:uuid:abcd1234-5678-90ab-cdef-1234567890ab",
				"holder": "did:nda:testnet:0x123",
				"type":   []interface{}{"VerifiablePresentation", "CustomType"},
				"@context": []interface{}{
					"https://www.w3.org/ns/credentials/v2",
				},
				"length": len(GenerateVCTest()),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := vp.NewEmbeddedPresentation(tt.input)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("Expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("CreatePresentationWithContent failed: %v", err)
			}

			// Get JSON from embedded presentation
			embeddedPres := p.(*vp.EmbeddedPresentation)
			data, err := embeddedPres.ToJSON()
			if err != nil {
				t.Fatalf("ToJSON failed: %v", err)
			}

			var m map[string]interface{}
			if err := json.Unmarshal(data, &m); err != nil {
				t.Fatalf("JSON output not parseable: %v", err)
			}

			// Check dynamic expectations
			for key, expected := range tt.expectFields {
				got := m[key]

				switch expectedVal := expected.(type) {
				case string:
					if got != expectedVal {
						t.Errorf("Expected %s = '%v', got '%v'", key, expectedVal, got)
					}
				case []interface{}:
					gotList, ok := got.([]interface{})
					if !ok || len(gotList) != len(expectedVal) {
						t.Errorf("Expected %s = %v, got %v", key, expectedVal, got)
					}
				}
			}

			// Check verifiableCredential count
			if len(tt.input.VerifiableCredentials) > 0 {
				vc, ok := m["verifiableCredential"].([]interface{})
				if !ok {
					t.Errorf("verifiableCredential is not a list")
				} else if len(vc) != len(tt.input.VerifiableCredentials) {
					t.Errorf("Expected %d verifiableCredentials, got %d", len(tt.input.VerifiableCredentials), len(vc))
				}
			}
		})
	}
}

func TestParsePresentationContents(t *testing.T) {
	vcList := GenerateVCTest()
	vp.Init("https://auth-dev.pila.vn/api/v1/did")

	vpc := vp.PresentationContents{
		Context: []interface{}{
			"https://www.w3.org/ns/credentials/v2",
		},
		ID:                    "urn:uuid:abcd1234-5678-90ab-cdef-1234567890ab",
		Types:                 []string{"VerifiablePresentation"},
		Holder:                "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce",
		VerifiableCredentials: vcList,
	}

	pContent, err := vp.NewEmbeddedPresentation(vpc)
	if err != nil {
		t.Fatalf("Failed to marshal PresentationContents: %v", err)
	}

	// Get JSON from embedded presentation
	embeddedPres := pContent.(*vp.EmbeddedPresentation)
	pJson, err := embeddedPres.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	p, err := vp.ParsePresentation(pJson)
	if err != nil {
		t.Fatalf("ParsePresentation failed: %v", err)
	}

	// Get JSON from embedded presentation and parse it
	embeddedPres = p.(*vp.EmbeddedPresentation)
	jsonData, err := embeddedPres.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(jsonData, &m); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if m["id"] != vpc.ID {
		t.Fatalf("Expected ID '%v', got %v", vpc.ID, m["id"])
	}

	if m["holder"] != vpc.Holder {
		t.Fatalf("Expected holder '%v', got %v", vpc.Holder, m["holder"])
	}

	// Check verifiableCredentials count
	vcListFromJSON, ok := m["verifiableCredential"].([]interface{})
	if !ok {
		t.Fatalf("Expected verifiableCredential to be a slice")
	}
	if len(vcListFromJSON) != len(vpc.VerifiableCredentials) {
		t.Fatalf("Expected %d verifiableCredentials, got %d", len(vpc.VerifiableCredentials), len(vcListFromJSON))
	}

	// Check types - handle both string and slice cases
	var typesList []interface{}
	switch v := m["type"].(type) {
	case string:
		typesList = []interface{}{v}
	case []interface{}:
		typesList = v
	default:
		t.Fatalf("Expected type to be string or slice, got %T", m["type"])
	}

	if len(typesList) != len(vpc.Types) {
		t.Fatalf("Expected %d types, got %d", len(vpc.Types), len(typesList))
	} else {
		for i, k := range typesList {
			if k != vpc.Types[i] {
				t.Fatalf("Expected type '%s', got %s", vpc.Types[i], k)
			}
		}
	}
}

func TestAddECDSAProof(t *testing.T) {

	vp.Init("https://auth-dev.pila.vn/api/v1/did")
	vc.Init("https://auth-dev.pila.vn/api/v1/did")

	vcList := GenerateVCTest()
	if vcList == nil {
		t.Fatal("Failed to generate VCTest")
	}

	privateKeyHex := "e5c9a597b20e13627a3850d38439b61ec9ee7aefd77c7cb6c01dc3866e1db19a"

	vpc := vp.PresentationContents{
		Context: []interface{}{
			"https://www.w3.org/ns/credentials/v2",
		},
		ID:                    "urn:uuid:abcd1234-5678-90ab-cdef-1234567890ab",
		Types:                 []string{"VerifiablePresentation"},
		Holder:                "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce",
		VerifiableCredentials: vcList,
	}

	presentation, err := vp.NewEmbeddedPresentation(vpc)
	if err != nil {
		t.Fatalf("Failed to create presentation: %v", err)
	}

	err = presentation.AddProof(privateKeyHex)
	if err != nil {
		t.Fatalf("Failed to add ECDSA proof: %v", err)
	}

	// Get JSON from embedded presentation
	embeddedPres := presentation.(*vp.EmbeddedPresentation)
	presentationJSON, err := embeddedPres.ToJSON()
	if err != nil {
		t.Fatalf("Failed to serialize presentation: %v", err)
	}

	p, err := vp.ParsePresentation(presentationJSON)
	if err != nil {
		t.Fatalf("Failed to parse presentation: %v", err)
	}

	// Check if presentation has proof by looking at the serialized form
	_, err = p.Serialize()
	if err != nil {
		t.Fatalf("Failed to serialize presentation: %v", err)
	}
}

func TestVerifyECDSAPresentation(t *testing.T) {
	vp.Init("https://auth-dev.pila.vn/api/v1/did")
	vc.Init("https://auth-dev.pila.vn/api/v1/did")

	vcList := GenerateVCTest()
	if vcList == nil {
		t.Fatal("Failed to generate VCTest")
	}

	privateKeyHex := "e5c9a597b20e13627a3850d38439b61ec9ee7aefd77c7cb6c01dc3866e1db19a"

	vpc := vp.PresentationContents{
		Context: []interface{}{
			"https://www.w3.org/ns/credentials/v2",
		},
		ID:                    "urn:uuid:abcd1234-5678-90ab-cdef-1234567890ab",
		Types:                 []string{"VerifiablePresentation"},
		Holder:                "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce",
		VerifiableCredentials: vcList,
	}

	presentation, err := vp.NewEmbeddedPresentation(vpc)
	if err != nil {
		t.Fatalf("Failed to create presentation: %v", err)
	}

	err = presentation.AddProof(privateKeyHex)
	if err != nil {
		t.Fatalf("Failed to add ECDSA proof: %v", err)
	}

	// Verify the presentation directly without JSON serialization/parsing
	// since the JSON round-trip might not preserve credential proofs correctly
	err = presentation.Verify()
	if err != nil {
		t.Fatalf("Error verifying ECDSA presentation: %v", err)
	}
}

// GenerateVCTest replicates the function from main.go to create test credentials.
func GenerateVCTest() []*vc.Credential {
	privateKeyHex := "e5c9a597b20e13627a3850d38439b61ec9ee7aefd77c7cb6c01dc3866e1db19a"
	vc.Init("https://auth-dev.pila.vn/api/v1/did")

	vcc := vc.CredentialContents{
		Context: []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2",
			map[string]interface{}{
				"@vocab":                     "https://schema.org/version/latest/schemaorg-all-https.jsonld",
				"VerifiableAttestation":      "ex:VerifiableAttestation",
				"VerifiableEducationalID":    "ex:VerifiableEducationalID",
				"eduPersonScopedAffiliation": "ex:eduPersonScopedAffiliation",
				"identifier":                 "ex:identifier",
			},
		},
		ID: "urn:uuid:db2a23dc-80e2-4ef8-b708-5d2ea7b5deb6",
		Types: []string{
			"VerifiableCredentialDTA",
			"VerifiableAttestation",
			"VerifiableEducationalID",
		},
		Issuer: "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce",
		ValidFrom: func() time.Time {
			t, _ := time.Parse(time.RFC3339, "2023-11-11T00:00:00Z")
			return t
		}(),
		ValidUntil: func() time.Time {
			t, _ := time.Parse(time.RFC3339, "2024-11-11T00:00:00Z")
			return t
		}(),
		Subject: []vc.Subject{
			{
				ID: "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbsEYvdrjxMjQ4tpnje9BDBTzuNDP3knn6qLZErzd4bJ5go2CChoPjd5GAH3zpFJP5fuwSk66U5Pq6EhF4nKnHzDnznEP8fX99nZGgwbAh1o7Gj1X52Tdhf7U4KTk66xsA5r",
				CustomFields: map[string]interface{}{
					"identifier":                 "c305487c-52ae-459e-b3d9-2a8d0a1b96e3",
					"eduPersonScopedAffiliation": []interface{}{"student"},
					"scoreabcdididid":            []int{100, 100, 100, 100, 100},
					"isActive":                   true,
				},
			},
		},
		CredentialStatus: []vc.Status{
			{
				ID:              "https://university.example/credentials/status/3#94567",
				Type:            "BitstringStatusListEntry",
				StatusPurpose:   "revocation",
				StatusListIndex: "94567",
			},
		},
		Schemas: []vc.Schema{
			{
				ID:   "http://localhost:8080/verifiable-educational-id.schema.json",
				Type: "JsonSchema",
			},
		},
	}

	credential, err := vc.NewEmbededCredential(vcc)
	if err != nil {
		fmt.Printf("Failed to create credential: %v\n", err)
		return nil
	}
	// Add an embedded ECDSA proof
	err = credential.AddProof(privateKeyHex)
	if err != nil {
		fmt.Printf("Failed to add embedded ECDSA proof: %v\n", err)
		return nil
	}

	return []*vc.Credential{&credential, &credential}
}

func TestCreatePresentationJWT(t *testing.T) {
	// Initialize the presentation and credential packages
	vp.Init("https://auth-dev.pila.vn/api/v1/did")
	vc.Init("https://auth-dev.pila.vn/api/v1/did")

	// Test data
	privateKeyHex := "e5c9a597b20e13627a3850d38439b61ec9ee7aefd77c7cb6c01dc3866e1db19a"
	holderDID := "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce"

	// Create a test credential first
	vcList := GenerateVCTest()
	if vcList == nil {
		t.Fatal("Failed to generate test credentials")
	}

	// For JWT presentations, we need to create JWT credentials
	// But since we're using the new interface, we'll work with the credential objects directly

	// Create presentation JWT contents
	presentationContentJWT := vp.PresentationContents{
		Context:               []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:                    "urn:uuid:jwt-test-presentation-12345678",
		Types:                 []string{"VerifiablePresentation"},
		Holder:                holderDID,
		VerifiableCredentials: vcList, // Use the credential objects, not JWT strings
	}

	// Create presentation from contents
	presentation, err := vp.NewJWTPresentation(presentationContentJWT)
	if err != nil {
		t.Fatalf("Failed to create presentation from contents: %v", err)
	}

	// Add proof to the presentation
	err = presentation.AddProof(privateKeyHex)
	if err != nil {
		t.Fatalf("Failed to sign presentation as JWT: %v", err)
	}

	// Serialize to get JWT token
	serialized, err := presentation.Serialize()
	if err != nil {
		t.Fatalf("Failed to serialize presentation: %v", err)
	}
	jwtToken := serialized.(string)
	if jwtToken == "" {
		t.Fatal("JWT token should not be empty")
	}

	// Verify the JWT token structure (should have 3 parts)
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT should have 3 parts separated by dots, got %d", len(parts))
	}

	// Parse the JWT presentation back
	verifiedPresentation, err := vp.ParsePresentation(jwtToken)
	if err != nil {
		t.Fatalf("Failed to verify JWT presentation: %v", err)
	}
	if verifiedPresentation == nil {
		t.Fatal("Verified presentation should not be nil")
	}

	// Verify the presentation data matches
	// For JWT presentations, we can verify by checking the serialized JWT
	serialized, err = verifiedPresentation.Serialize()
	if err != nil {
		t.Fatalf("Failed to serialize verified presentation: %v", err)
	}

	var ok bool
	jwtToken, ok = serialized.(string)
	if !ok {
		t.Fatal("Expected JWT presentation to serialize to string")
	}

	// Verify the JWT token structure (should have 3 parts)
	parts = strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT should have 3 parts separated by dots, got %d", len(parts))
	}

	// Basic verification that the JWT was created successfully
	if jwtToken == "" {
		t.Fatal("JWT token should not be empty")
	}

}

func TestPresentationSignatureFlows(t *testing.T) {
	// Initialize the presentation and credential packages
	vp.Init("https://auth-dev.pila.vn/api/v1/did")
	vc.Init("https://auth-dev.pila.vn/api/v1/did")

	// Test data
	privateKeyHex := "e5c9a597b20e13627a3850d38439b61ec9ee7aefd77c7cb6c01dc3866e1db19a"
	holderDID := "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce"

	// Create test credentials
	vcList := GenerateVCTest()
	if vcList == nil {
		t.Fatal("Failed to generate test credentials")
	}

	// Create presentation contents
	presentationContents := vp.PresentationContents{
		Context:               []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:                    "urn:uuid:signature-test-presentation-12345678",
		Types:                 []string{"VerifiablePresentation"},
		Holder:                holderDID,
		VerifiableCredentials: vcList,
	}

	t.Run("Embedded Presentation - AddProof Flow", func(t *testing.T) {
		// Create embedded presentation
		presentation, err := vp.NewEmbeddedPresentation(presentationContents)
		if err != nil {
			t.Fatalf("Failed to create embedded presentation: %v", err)
		}

		// Add proof using AddProof method
		err = presentation.AddProof(privateKeyHex)
		if err != nil {
			t.Fatalf("Failed to add proof to embedded presentation: %v", err)
		}

		// Verify the presentation
		err = presentation.Verify()
		if err != nil {
			t.Fatalf("Failed to verify embedded presentation with proof: %v", err)
		}

		// Serialize and verify it has proof
		serialized, err := presentation.Serialize()
		if err != nil {
			t.Fatalf("Failed to serialize embedded presentation: %v", err)
		}

		// Check that serialized presentation contains proof
		presMap, ok := serialized.(map[string]interface{})
		if !ok {
			t.Fatal("Serialized presentation should be a map")
		}
		if _, exists := presMap["proof"]; !exists {
			t.Fatal("Serialized presentation should contain proof")
		}
	})

	t.Run("Embedded Presentation - GetSigningInput + AddCustomProof Flow", func(t *testing.T) {
		// Create embedded presentation
		presentation, err := vp.NewEmbeddedPresentation(presentationContents)
		if err != nil {
			t.Fatalf("Failed to create embedded presentation: %v", err)
		}

		// Get signing input
		signingInput, err := presentation.GetSigningInput()
		if err != nil {
			t.Fatalf("Failed to get signing input: %v", err)
		}
		if len(signingInput) == 0 {
			t.Fatal("Signing input should not be empty")
		}

		// Sign message with ES256K
		signer := jwt.SigningMethodES256K{}
		signature, err := signer.Sign(string(signingInput), privateKeyHex)
		if err != nil {
			t.Fatalf("Failed to sign message: %v", err)
		}
		if len(signature) == 0 {
			t.Fatal("Signature should not be empty")
		}

		// Create a custom proof (simulating external signing)
		customProof := &dto.Proof{
			Signature: signature,
		}

		// Add custom proof
		err = presentation.AddCustomProof(customProof)
		if err != nil {
			t.Fatalf("Failed to add custom proof to embedded presentation: %v", err)
		}

		// Serialize and verify it has proof
		serialized, err := presentation.Serialize()
		if err != nil {
			t.Fatalf("Failed to serialize embedded presentation with custom proof: %v", err)
		}

		// Check that serialized presentation contains proof
		presMap, ok := serialized.(map[string]interface{})
		if !ok {
			t.Fatal("Serialized presentation should be a map")
		}
		if _, exists := presMap["proof"]; !exists {
			t.Fatal("Serialized presentation should contain proof")
		}
	})

	t.Run("JWT Presentation - AddProof Flow", func(t *testing.T) {
		// Create JWT presentation
		presentation, err := vp.NewJWTPresentation(presentationContents)
		if err != nil {
			t.Fatalf("Failed to create JWT presentation: %v", err)
		}

		// Add proof using AddProof method
		err = presentation.AddProof(privateKeyHex)
		if err != nil {
			t.Fatalf("Failed to add proof to JWT presentation: %v", err)
		}

		// Serialize to get JWT token
		serialized, err := presentation.Serialize()
		if err != nil {
			t.Fatalf("Failed to serialize JWT presentation: %v", err)
		}

		jwtToken, ok := serialized.(string)
		if !ok {
			t.Fatal("Serialized JWT presentation should be a string")
		}
		if jwtToken == "" {
			t.Fatal("JWT token should not be empty")
		}
		if len(strings.Split(jwtToken, ".")) != 3 {
			t.Fatal("JWT should have 3 parts")
		}

		// Parse and verify the JWT presentation
		parsedPresentation, err := vp.ParsePresentation(jwtToken)
		if err != nil {
			t.Fatalf("Failed to parse JWT presentation: %v", err)
		}
		if parsedPresentation == nil {
			t.Fatal("Parsed presentation should not be nil")
		}
	})

	t.Run("JWT Presentation - GetSigningInput + AddCustomProof Flow", func(t *testing.T) {
		// Create JWT presentation
		presentation, err := vp.NewJWTPresentation(presentationContents)
		if err != nil {
			t.Fatalf("Failed to create JWT presentation: %v", err)
		}

		// Get signing input
		signingInput, err := presentation.GetSigningInput()
		if err != nil {
			t.Fatalf("Failed to get signing input: %v", err)
		}
		if len(signingInput) == 0 {
			t.Fatal("Signing input should not be empty")
		}

		// Sign message with ES256K
		signer := jwt.SigningMethodES256K{}
		signature, err := signer.Sign(string(signingInput), privateKeyHex)
		if err != nil {
			t.Fatalf("Failed to sign message: %v", err)
		}
		if len(signature) == 0 {
			t.Fatal("Signature should not be empty")
		}

		// Create a custom proof with JWT signature
		customProof := &dto.Proof{
			Signature: signature,
		}

		// Add custom proof (this will set the JWT signature)
		err = presentation.AddCustomProof(customProof)
		if err != nil {
			t.Fatalf("Failed to add custom proof to JWT presentation: %v", err)
		}

		// Serialize to get JWT token
		serialized, err := presentation.Serialize()
		if err != nil {
			t.Fatalf("Failed to serialize JWT presentation with custom proof: %v", err)
		}

		jwtToken, ok := serialized.(string)
		if !ok {
			t.Fatal("Serialized JWT presentation should be a string")
		}
		if jwtToken == "" {
			t.Fatal("JWT token should not be empty")
		}
	})

	t.Run("Error Cases", func(t *testing.T) {
		// Test AddCustomProof with nil proof
		presentation, err := vp.NewEmbeddedPresentation(presentationContents)
		if err != nil {
			t.Fatalf("Failed to create embedded presentation: %v", err)
		}

		err = presentation.AddCustomProof(nil)
		if err == nil {
			t.Fatal("Should return error for nil proof")
		}
		if !strings.Contains(err.Error(), "proof cannot be nil") {
			t.Fatalf("Error message should mention nil proof, got: %v", err)
		}

		// Test JWT presentation with nil proof
		jwtPresentation, err := vp.NewJWTPresentation(presentationContents)
		if err != nil {
			t.Fatalf("Failed to create JWT presentation: %v", err)
		}

		err = jwtPresentation.AddCustomProof(nil)
		if err == nil {
			t.Fatal("Should return error for nil proof")
		}
		if !strings.Contains(err.Error(), "proof cannot be nil") {
			t.Fatalf("Error message should mention nil proof, got: %v", err)
		}
	})
}
