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
		return "", fmt.Errorf("jwt signer: signer cannot be nil")
	}

	hash := sha256.Sum256([]byte(signingString))
	signature, err := s.signer.Sign(hash[:])
	if err != nil {
		return "", fmt.Errorf("jwt signer: failed to sign digest: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(TrimRecoveryByte(signature)), nil
}

// TrimRecoveryByte drops the recovery id some secp256k1 signers append.
//
// RFC 7518 §3.4 defines the JWS ECDSA signature as the raw r||s pair — 64
// octets on both P-256 and secp256k1. A 65th octet is a convention of the
// signing library, not part of the signature, and a verifier reading the value
// as r||s rejects it. Signing paths inside the SDK and the external-signing
// entry points must agree on this, or the same key produces a token that
// verifies one way and not the other.
func TrimRecoveryByte(sig []byte) []byte {
	if len(sig) == 65 {
		return sig[:64]
	}
	return sig
}
