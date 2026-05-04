package jwt

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
)

// JWTSigner handles JWT signing operations
type JWTSigner struct {
	signer signer.SignerProvider
}

// NewJWTSigner creates a new JWT signer instance
func NewJWTSigner(signer signer.SignerProvider) *JWTSigner {
	return &JWTSigner{
		signer: signer,
	}
}

// SignString signs a string and returns the signature
func (s *JWTSigner) SignString(signingString string) (string, error) {
	if s.signer == nil {
		return "", fmt.Errorf("signer cannot be nil")
	}

	hash := sha256.Sum256([]byte(signingString))
	signature, err := s.signer.Sign(hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}
	if err := signer.ValidateSignatureLength(signature); err != nil {
		return "", err
	}
	if len(signature) == 65 {
		signature = signature[:64]
	}

	return base64.RawURLEncoding.EncodeToString(signature), nil
}
