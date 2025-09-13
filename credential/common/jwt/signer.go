package jwt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
)

// JWTSigner handles JWT signing operations for verifiable documents
type JWTSigner struct {
	privKeyHex string
	issuerDID  string
}

// NewJWTSigner creates a new JWT signer instance
func NewJWTSigner(privKeyHex, issuerDID string) *JWTSigner {
	return &JWTSigner{
		privKeyHex: privKeyHex,
		issuerDID:  issuerDID,
	}
}

func (s *JWTSigner) SigningInput(docJSONMap jsonmap.JSONMap, docType string) ([]byte, error) {
	// Register the ES256K signing method
	jwt.RegisterSigningMethod(ES256K.Alg(), func() jwt.SigningMethod {
		return ES256K
	})

	// Get document ID from JSONMap or generate one
	docID, ok := docJSONMap["id"].(string)
	if !ok || docID == "" {
		docID = "urn:uuid:" + generateUUID()
	}

	// Determine the claim key based on document type
	claimKey := docType

	claims := map[string]interface{}{
		claimKey: docJSONMap,
	}

	// Create the token
	token := jwt.NewWithClaims(ES256K, jwt.MapClaims(claims))
	token.Header["typ"] = "JWT"
	token.Header["kid"] = s.GetKeyID()

	signingInput, err := token.SigningString()
	if err != nil {
		return nil, fmt.Errorf("failed to get signing input: %w", err)
	}

	return []byte(signingInput), nil
}

// SignDocument signs a verifiable document (VC or VP) as JWT from JSONMap
func (s *JWTSigner) SignDocument(docJSONMap jsonmap.JSONMap, docType string, additionalClaims ...map[string]interface{}) (string, error) {
	// Register the ES256K signing method
	jwt.RegisterSigningMethod(ES256K.Alg(), func() jwt.SigningMethod {
		return ES256K
	})

	// Get document ID from JSONMap or generate one
	docID, ok := docJSONMap["id"].(string)
	if !ok || docID == "" {
		docID = "urn:uuid:" + generateUUID()
	}

	// Determine the claim key based on document type
	claimKey := docType

	claims := map[string]interface{}{
		claimKey: docJSONMap,
	}

	// Add any additional claims (if provided)
	if len(additionalClaims) > 0 && additionalClaims[0] != nil {
		for key, value := range additionalClaims[0] {
			claims[key] = value
		}
	}

	// Create and sign the token
	token := jwt.NewWithClaims(ES256K, jwt.MapClaims(claims))
	token.Header["typ"] = "JWT"
	token.Header["kid"] = s.GetKeyID()

	signedString, err := token.SignedString(s.privKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedString, nil
}

// GetPublicKey returns the public key associated with this signer
func (s *JWTSigner) GetPublicKey() (*ecdsa.PublicKey, error) {
	privKeyBytes, err := hex.DecodeString(s.privKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}

	privKey, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	return &privKey.PublicKey, nil
}

// GetKeyID returns the Key ID for this signer
func (s *JWTSigner) GetKeyID() string {
	return fmt.Sprintf("%s#%s", s.issuerDID, "key-1")
}

// generateUUID generates a simple UUID-like string
func generateUUID() string {
	// Simple UUID generation using crypto/rand
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback to time-based ID if crypto.Read fails
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
