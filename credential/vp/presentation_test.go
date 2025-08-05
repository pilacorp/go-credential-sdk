package vp_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

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

	vpByte, err := pParsed.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
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
			name:      "Missing required fields",
			input:     vp.PresentationContents{},
			expectErr: true,
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
			p, err := vp.CreatePresentationWithContent(tt.input)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("Expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("CreatePresentationWithContent failed: %v", err)
			}

			data, err := p.ToJSON()
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

	pContent, err := vp.CreatePresentationWithContent(vpc)
	if err != nil {
		t.Fatalf("Failed to marshal PresentationContents: %v", err)
	}

	pJson, err := pContent.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	p, err := vp.ParsePresentation(pJson)
	if err != nil {
		t.Fatalf("ParsePresentation failed: %v", err)
	}

	contents, err := p.ParsePresentationContents()
	if err != nil {
		t.Fatalf("ParsePresentationContents failed: %v", err)
	}

	if contents.ID != vpc.ID {
		t.Fatalf("Expected ID '%v', got %v", vpc.ID, contents.ID)
	}

	if contents.Holder != vpc.Holder {
		t.Fatalf("Expected holder '%v', got %v", vpc.Holder, contents.Holder)
	}

	if len(contents.VerifiableCredentials) != len(vpc.VerifiableCredentials) {
		t.Fatalf("Expected %d verifiableCredentials, got %d", len(vpc.VerifiableCredentials), len(contents.VerifiableCredentials))
	}

	if len(contents.Types) != len(vpc.Types) {
		t.Fatalf("Expected %d types, got %d", len(vpc.Types), len(contents.Types))
	} else {
		for i, k := range contents.Types {
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
	vmID := "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce#key-1"

	vpc := vp.PresentationContents{
		Context: []interface{}{
			"https://www.w3.org/ns/credentials/v2",
		},
		ID:                    "urn:uuid:abcd1234-5678-90ab-cdef-1234567890ab",
		Types:                 []string{"VerifiablePresentation"},
		Holder:                "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce",
		VerifiableCredentials: vcList,
	}

	presentation, err := vp.CreatePresentationWithContent(vpc)
	if err != nil {
		t.Fatalf("Failed to create presentation: %v", err)
	}

	err = presentation.AddECDSAProof(privateKeyHex, vmID)
	if err != nil {
		t.Fatalf("Failed to add ECDSA proof: %v", err)
	}

	presentationJSON, err := presentation.ToJSON()
	if err != nil {
		t.Fatalf("Failed to serialize presentation: %v", err)
	}

	p, err := vp.ParsePresentation(presentationJSON)
	if err != nil {
		t.Fatalf("Failed to parse presentation: %v", err)
	}

	pContents, err := p.ParsePresentationContents()
	if err != nil {
		t.Fatalf("Failed to parse presentation contents: %v", err)
	}

	if len(pContents.Proofs) == 0 {
		t.Fatal("Expected at least one proof in the presentation contents")
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
	vmID := "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce#key-1"

	vpc := vp.PresentationContents{
		Context: []interface{}{
			"https://www.w3.org/ns/credentials/v2",
		},
		ID:                    "urn:uuid:abcd1234-5678-90ab-cdef-1234567890ab",
		Types:                 []string{"VerifiablePresentation"},
		Holder:                "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce",
		VerifiableCredentials: vcList,
	}

	presentation, err := vp.CreatePresentationWithContent(vpc)
	if err != nil {
		t.Fatalf("Failed to create presentation: %v", err)
	}

	err = presentation.AddECDSAProof(privateKeyHex, vmID)
	if err != nil {
		t.Fatalf("Failed to add ECDSA proof: %v", err)
	}

	presentationJSON, err := presentation.ToJSON()
	if err != nil {
		t.Fatalf("Failed to serialize presentation: %v", err)
	}

	p, err := vp.ParsePresentation(presentationJSON)
	if err != nil {
		t.Fatalf("Failed to parse presentation: %v", err)
	}

	isValid, err := vp.VerifyECDSAPresentation(p)
	if err != nil {
		t.Fatalf("Error verifying ECDSA presentation: %v", err)
	}
	if !isValid {
		t.Fatal("ECDSA proof verification failed in the presentation")
	}
	t.Log("ECDSA proof verified successfully in the presentation")
}

// GenerateVCTest replicates the function from main.go to create test credentials.
func GenerateVCTest() []*vc.Credential {
	privateKeyHex := "e5c9a597b20e13627a3850d38439b61ec9ee7aefd77c7cb6c01dc3866e1db19a"
	method := "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce#key-1"
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

	credential, err := vc.CreateCredentialWithContent(vcc)
	if err != nil {
		fmt.Printf("Failed to create credential: %v\n", err)
		return nil
	}
	// Add an embedded ECDSA proof
	err = credential.AddECDSAProof(privateKeyHex, method)
	if err != nil {
		fmt.Printf("Failed to add embedded ECDSA proof: %v\n", err)
		return nil
	}

	return []*vc.Credential{credential, credential}
}
