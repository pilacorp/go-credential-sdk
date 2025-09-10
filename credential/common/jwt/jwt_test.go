package jwt

import (
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
)

// TestJWTSelfIssued tests JWT signing where the issuer is also the subject
func TestJWTSelfIssued(t *testing.T) {
	// Provided private key and DID
	privateKeyHex := "c6f8cf675b77523c3d3157d322b3c7c4cc14874f290407398361be1a4c1ed7d0"
	issuerDID := "did:nda:testnet:0xb64b2b1168047d1745492c7025c5edba69e4f4f0"

	// For self-issued credentials, the subject is the same as the issuer
	subjectDID := issuerDID

	// Create a self-issued verifiable credential as JSONMap
	vcData := jsonmap.JSONMap{
		"@context":     []string{"https://www.w3.org/2018/credentials/v1"},
		"id":           "urn:uuid:self-issued-credential-12345678",
		"type":         []string{"VerifiableCredential", "SelfIssuedCredential"},
		"issuer":       issuerDID,
		"issuanceDate": "2024-01-18T08:13:09Z",
		"credentialSubject": map[string]interface{}{
			"id":             subjectDID,
			"name":           "NDA Testnet Issuer",
			"organization":   "NDA Testnet",
			"role":           "Issuer",
			"credentialType": "SelfIssuedCredential",
		},
	}

	// Create JWT signer
	signer := NewJWTSigner(privateKeyHex, issuerDID)

	// Sign the self-issued verifiable credential
	signedJWT, err := signer.SignDocument(vcData, "vc", nil)
	if err != nil {
		t.Fatalf("Failed to sign self-issued VC: %v", err)
	}

	// Verify the JWT is not empty
	if signedJWT == "" {
		t.Fatal("Signed JWT should not be empty")
	}

	// Verify the JWT has the expected structure (3 parts separated by dots)
	parts := strings.Split(signedJWT, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT should have 3 parts, got %d", len(parts))
	}

	// Verify the JWT
	verifier := NewJWTVerifier("https://auth-dev.pila.vn/api/v1/did")
	err = verifier.VerifyDocument(signedJWT, "vc")
	if err != nil {
		t.Fatalf("Failed to verify JWT: %v", err)
	}
}

// TestJWTPresentation tests JWT signing for Verifiable Presentation
func TestJWTPresentation(t *testing.T) {
	// Provided private key and DID
	privateKeyHex := "c6f8cf675b77523c3d3157d322b3c7c4cc14874f290407398361be1a4c1ed7d0"
	holderDID := "did:nda:testnet:0xb64b2b1168047d1745492c7025c5edba69e4f4f0"

	// Create a verifiable presentation as JSONMap
	vpData := jsonmap.JSONMap{
		"@context": []string{"https://www.w3.org/2018/credentials/v1"},
		"id":       "urn:did:123456",
		"type":     []string{"VerifiablePresentation"},
		"holder":   holderDID,
		"verifiableCredential": []string{
			"eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QiLCJraWQiOiJkaWQ6ZWJzaTp6eGFZYVV0Yjhwdm9BdFlOV2JLY3ZlZyNDSHhZek9xdDM4U3g2WUJmUFloaUVkZ2N3eldrOXR5N2swTEJhNmg3MG5jIn0.eyJqdGkiOiJ1cm46dXVpZDowMDNhMWRkOC1hNWQyLTQyZWYtODE4Mi1lOTIxYzBhOWYyY2QiLCJzdWIiOiJkaWQ6a2V5OnpCaEJMbVlteWlodG9tUmRKSk5FS3piUGo1MW80YTNHWUZlWm9SSFNBQktVd3FkamlRUFkyY3EzTFRHUnEzNlJob1pScWl4MWVxNHVBNDMzUUpheUhkVGk4c3htOHFkYkFiblR5Zzlkc1hDakQ4Tk43RXRjcjRmNTVtUmhuOVQxZDNkNkVjNkhndHBjVWZlbWI0WlZLU0NEYUJyQnlkc3JLQUIzVEtXTlhBa2duejFoc2VlcWY4WSIsImlzcyI6ImRpZDplYnNpOnp4YVlhVXRiOHB2b0F0WU5XYktjdmVnIiwibmJmIjoxNjM1NzI0ODAwLCJleHAiOjE5NTM3NjMyMDAsImlhdCI6MTU5MjgzNTEwNCwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwiaWQiOiJ1cm46dXVpZDowMDNhMWRkOC1hNWQyLTQyZWYtODE4Mi1lOTIxYzBhOWYyY2QiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVmVyaWZpYWJsZUF0dGVzdGF0aW9uIl0sImlzc3VlciI6ImRpZDplYnNpOnp4YVlhVXRiOHB2b0F0WU5XYktjdmVnIiwiaXNzdWFuY2VEYXRlIjoiMjAyMS0xMS0wMVQwMDowMDowMFoiLCJ2YWxpZEZyb20iOiIyMDIxLTExLTAxVDAwOjAwOjAwWiIsInZhbGlkVW50aWwiOiIyMDUwLTExLTAxVDAwOjAwOjAwWiIsImV4cGlyYXRpb25EYXRlIjoiMjAzMS0xMS0zMFQwMDowMDowMFoiLCJpc3N1ZWQiOiIyMDIwLTA2LTIyVDE0OjExOjQ0WiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6QmhCTG1ZbXlpaHRvbVJkSkpORUt6YlBqNTFvNGEzR1lGZVpvUkhTQUJLVXdxZGppUVBZMmNxM0xUR1JxMzZSaG9aUnFpeDFlcTR1QTQzM1FKYXlIZFRpOHN4bThxZGJBYm5UeWc5ZHNYQ2pEOE5ON0V0Y3I0ZjU1bVJobjlUMWQzZDZFYzZIZ3RwY1VmZW1iNFpWS1NDRGFCckJ5ZHNyS0FCM1RLV05YQWtnbnoxaHNlZXFmOFkifSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vYXBpLXBpbG90LmVic2kuZXUvdHJ1c3RlZC1zY2hlbWFzLXJlZ2lzdHJ5L3YzL3NjaGVtYXMvejNNZ1VGVWtiNzIydXE0eDNkdjV5QUptbk5tekRGZUs1VUM4eDgzUW9lTEpNIiwidHlwZSI6IkZ1bGxKc29uU2NoZW1hVmFsaWRhdG9yMjAyMSJ9LCJ0ZXJtc09mVXNlIjp7ImlkIjoiaHR0cHM6Ly9hcGktcGlsb3QuZWJzaS5ldS90cnVzdGVkLWlzc3VlcnMtcmVnaXN0cnkvdjUvaXNzdWVycy9kaWQ6ZWJzaTp6eGFZYVV0Yjhwdm9BdFlOV2JLY3ZlZy9hdHRyaWJ1dGVzL2I0MGZkOWI0MDQ0MThhNDRkMmQ5OTExMzc3YTAzMTMwZGRlNDUwZWI1NDZjNzU1YjViODBhY2Q3ODI5MDJlNmQiLCJ0eXBlIjoiSXNzdWFuY2VDZXJ0aWZpY2F0ZSJ9fX0.fKCREswG43_862Vr8L3lJORgFNzvMZ2hR7p93gfEkhM-qhIIlSlP0AcAgy0c6qu2_2uAIC7mOGnj9AZ3Au2nLw",
		},
	}

	// Create JWT signer
	signer := NewJWTSigner(privateKeyHex, holderDID)

	// Sign the verifiable presentation
	signedJWT, err := signer.SignDocument(vpData, "vp", map[string]interface{}{
		"aud": "did:ebsi:zwNAE5xThBpmGJUWAY23kgx",
	})
	if err != nil {
		t.Fatalf("Failed to sign VP: %v", err)
	}

	// Verify the JWT is not empty
	if signedJWT == "" {
		t.Fatal("Signed JWT should not be empty")
	}

	// Verify the JWT has the expected structure (3 parts separated by dots)
	parts := strings.Split(signedJWT, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT should have 3 parts, got %d", len(parts))
	}

	// Verify the JWT
	verifier := NewJWTVerifier("https://auth-dev.pila.vn/api/v1/did")
	err = verifier.VerifyDocument(signedJWT, "vp")
	if err != nil {
		t.Fatalf("Failed to verify VP JWT: %v", err)
	}
}
