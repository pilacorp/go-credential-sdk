package jwt

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
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
