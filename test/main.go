package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// Example: Create credential from test patterns
// This mirrors the test cases in credential_test.go

const (
	testIssuerPrivateKey = "5a369512f8f8a0e6973abd6241ce38103c232966c6153bf8377ac85582812aa4"
	testIssuerDID        = "did:nda:testnet:0x084ce14ef7c6e76a5ff3d58c160de7e1d385d9ee"
)

func main() {
	vc.Init("https://auth-dev.pila.vn/api/v1/did")
	fmt.Println("=== Example: Create Credential from Test Patterns ===\n")

	// Example 1: Create JSON Credential
	fmt.Println("-- Example 1: Create JSON Credential --")
	createJSONCredentialExample()

	// Example 2: Create JWT Credential
	fmt.Println("\n-- Example 2: Create JWT Credential --")
	createJWTCredentialExample()

	// Example 3: Create Credential without validFrom/validUntil (null)
	fmt.Println("\n-- Example 3: Create Credential without dates (null) --")
	createCredentialWithoutDatesExample()
}

// Example 1: Create JSON Credential (similar to TestCreateCredentialWithContents)
func createJSONCredentialExample() {
	credentialContents := createBaseCredentialContents(testIssuerDID, createValidCustomFields())

	// Create JSON credential
	jsonCredential, err := vc.NewJSONCredential(credentialContents)
	if err != nil {
		log.Fatalf("Failed to create JSON credential: %v", err)
	}

	if err := jsonCredential.AddProof(testIssuerPrivateKey); err != nil {
		log.Fatalf("Failed to add proof: %v", err)
	}

	// Get contents
	contents, err := jsonCredential.GetContents()
	if err != nil {
		log.Fatalf("Failed to get contents: %v", err)
	}

	// Pretty print JSON
	var prettyJSON map[string]interface{}
	if err := json.Unmarshal(contents, &prettyJSON); err != nil {
		log.Fatalf("Failed to unmarshal: %v", err)
	}
	prettyBytes, _ := json.MarshalIndent(prettyJSON, "", "  ")
	fmt.Println("JSON Credential created successfully:")
	fmt.Println(string(prettyBytes))

	// Serialize
	serialized, err := jsonCredential.Serialize()
	if err != nil {
		log.Fatalf("Failed to serialize: %v", err)
	}
	fmt.Printf("\nCredential type: %s\n", jsonCredential.GetType())
	fmt.Printf("Serialized (first 100 chars): %s...\n", fmt.Sprintf("%v", serialized)[:min(100, len(fmt.Sprintf("%v", serialized)))])
}

// Example 2: Create JWT Credential (similar to TestCreateJWTCredentialWithValidateSchema)
func createJWTCredentialExample() {
	credentialContents := createBaseCredentialContents(testIssuerDID, createValidCustomFields())

	// Create JWT credential (without schema validation to avoid DID resolver 403)
	jwtCredential, err := vc.NewJWTCredential(credentialContents)
	if err != nil {
		log.Fatalf("Failed to create JWT credential: %v", err)
	}

	// Note: AddProof requires DID resolver (may fail with 403 if offline)
	// Uncomment to add proof (requires working DID resolver):
	if err := jwtCredential.AddProof(testIssuerPrivateKey); err != nil {
		log.Fatalf("Failed to add proof: %v", err)
	}

	// Get contents
	contents, err := jwtCredential.GetContents()
	if err != nil {
		log.Fatalf("Failed to get contents: %v", err)
	}

	// Pretty print JSON
	var prettyJSON map[string]interface{}
	if err := json.Unmarshal(contents, &prettyJSON); err != nil {
		log.Fatalf("Failed to unmarshal: %v", err)
	}
	prettyBytes, _ := json.MarshalIndent(prettyJSON, "", "  ")
	fmt.Println("JWT Credential created successfully:")
	fmt.Println(string(prettyBytes))

	// Serialize to JWT string
	serialized, err := jwtCredential.Serialize()
	if err != nil {
		log.Fatalf("Failed to serialize: %v", err)
	}
	jwtToken, ok := serialized.(string)
	if !ok {
		log.Fatalf("Serialized result is not a string")
	}
	fmt.Printf("\nCredential type: %s\n", jwtCredential.GetType())
	fmt.Printf("JWT Token (first 100 chars): %s...\n", jwtToken[:min(100, len(jwtToken))])
}

// Example 3: Create Credential without validFrom/validUntil (null/empty)
func createCredentialWithoutDatesExample() {
	credentialContents := vc.CredentialContents{
		Context: []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:      "did:nda:testnet:example-123",
		Issuer:  testIssuerDID,
		Types:   []string{"VerifiableCredential"},
		Subject: []vc.Subject{
			{
				ID: "did:nda:testnet:0x78e43d3bd308b0522c8f6fcfb4785d9b841556c8",
				CustomFields: map[string]interface{}{
					"name": "Test User",
					"age":  25,
				},
			},
		},
		Schemas: []vc.Schema{
			{
				ID:   "https://auth-dev.pila.vn/api/v1/schemas/7250251f-141e-47a2-aa5f-a5d3499d30da",
				Type: "JsonSchema",
			},
		},
		ValidFrom:  time.Time{},
		ValidUntil: time.Unix(0, 0),
	}

	// Create JSON credential
	jsonCredential, err := vc.NewJSONCredential(credentialContents)
	if err != nil {
		log.Fatalf("Failed to create JSON credential: %v", err)
	}

	// Get contents to verify dates are not included
	contents, err := jsonCredential.GetContents()
	if err != nil {
		log.Fatalf("Failed to get contents: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(contents, &result); err != nil {
		log.Fatalf("Failed to unmarshal: %v", err)
	}

	// Check that validFrom and validUntil are NOT present
	if _, hasValidFrom := result["validFrom"]; hasValidFrom {
		fmt.Println("⚠️  Warning: validFrom should not be present (it's null/empty)")
	} else {
		fmt.Println("✅ validFrom is correctly omitted (null/empty)")
	}

	if _, hasValidUntil := result["validUntil"]; hasValidUntil {
		fmt.Println("⚠️  Warning: validUntil should not be present (it's null/empty)")
	} else {
		fmt.Println("✅ validUntil is correctly omitted (null/empty)")
	}

	prettyBytes, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println("\nCredential without dates:")
	fmt.Println(string(prettyBytes))
}

// Helper: Create base credential contents (from credential_test.go)
func createBaseCredentialContents(issuerDID string, customFields map[string]interface{}) vc.CredentialContents {
	schema := vc.Schema{
		ID:   "https://auth-dev.pila.vn/api/v1/schemas/7250251f-141e-47a2-aa5f-a5d3499d30da",
		Type: "JsonSchema",
	}

	return vc.CredentialContents{
		Context: []interface{}{"https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"},
		Schemas: []vc.Schema{schema},
		Subject: []vc.Subject{
			{
				ID:           "did:nda:testnet:0x78e43d3bd308b0522c8f6fcfb4785d9b841556c8",
				CustomFields: customFields,
			},
		},
		ID:         "did:nda:testnet:f5dd72fe-75d3-4a3b-b679-8b9fb5df5177",
		Issuer:     issuerDID,
		Types:      []string{"VerifiableCredential"},
		ValidFrom:  time.Now(),
		ValidUntil: time.Now().Add(time.Hour * 24 * 30),
		CredentialStatus: []vc.Status{
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

// Helper: Create valid custom fields (from credential_test.go)
func createValidCustomFields() map[string]interface{} {
	return map[string]interface{}{
		"age":        10,
		"name":       "Test Create",
		"salary":     50000,
		"department": "Engineering",
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
