package jwt

import (
	"encoding/base64"
	"fmt"
)

// JWTSigner handles JWT signing operations
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

// SignString signs a string (header.payload) and returns the signature
func (s *JWTSigner) SignString(signingString string) (string, error) {
	// Sign the string using ES256K
	signature, err := ES256K.Sign(signingString, s.privKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to sign string: %w", err)
	}

	// Encode signature as base64url
	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)
	return signatureEncoded, nil
}

// GetKeyID returns the Key ID for this signer
func (s *JWTSigner) GetKeyID() string {
	return fmt.Sprintf("%s#%s", s.issuerDID, "key-1")
}
