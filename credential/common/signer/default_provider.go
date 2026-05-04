package signer

import (
	"crypto/ecdsa"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// DefaultProvider signs using an in-memory ECDSA private key.
//
// This is intended for development/testing. Production integrations should
// implement SignerProvider using Vault/HSM/remote signing services.
type DefaultProvider struct {
	priv *ecdsa.PrivateKey
}

// NewDefaultProvider creates a DefaultProvider from a hex-encoded private key.
//
// The privHex parameter can include or omit the "0x" prefix.
func NewDefaultProvider(privHex string) (*DefaultProvider, error) {
	priv, err := crypto.HexToECDSA(strings.TrimPrefix(privHex, "0x"))
	if err != nil {
		return nil, err
	}
	return &DefaultProvider{priv: priv}, nil
}

func (s *DefaultProvider) Sign(hashPayload []byte) ([]byte, error) {
	if len(hashPayload) != 32 {
		return nil, fmt.Errorf("hash payload must be 32 bytes, got %d", len(hashPayload))
	}

	signature, err := crypto.Sign(hashPayload, s.priv)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	if err := ValidateSignatureLength(signature); err != nil {
		return nil, err
	}

	return signature, nil
}

