package jwt

import (
	"encoding/base64"
	"fmt"
)

// JWTSigner handles JWT signing operations
type JWTSigner struct {
	privKeyHex string
}

// NewJWTSigner creates a new JWT signer instance
func NewJWTSigner(privKeyHex string) *JWTSigner {
	return &JWTSigner{
		privKeyHex: privKeyHex,
	}
}

// SignString signs a string and returns the signature
func (s *JWTSigner) SignString(signingString string) (string, error) {
	signature, err := ES256K.Sign(signingString, s.privKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(signature), nil
}
