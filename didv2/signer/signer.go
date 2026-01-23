package signer

import (
	"crypto/ecdsa"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// SignerProvider is the interface for the signer provider.
type SignerProvider interface {
	Sign(payload []byte) ([]byte, error)
	GetAddress() string
}

// DefaultProvider is the default signer provider.
type DefaultProvider struct {
	priv *ecdsa.PrivateKey
}

// NewDefaultProvider creates a new default signer provider.
//
// privHex is the private key in hex format.
// Returns the signer provider or an error if the private key is invalid.
func NewDefaultProvider(privHex string) (SignerProvider, error) {
	priv, err := crypto.HexToECDSA(strings.TrimPrefix(privHex, "0x"))
	if err != nil {
		return nil, err
	}
	return &DefaultProvider{priv: priv}, nil
}

// Sign signs the payload.
//
// hashPayload is the hash of the payload to sign.
// Returns the signature or an error if the signature is invalid.
func (s *DefaultProvider) Sign(hashPayload []byte) ([]byte, error) {
	signature, err := crypto.Sign(hashPayload, s.priv)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	if len(signature) != 65 {
		return nil, fmt.Errorf("invalid signature length: expected 65 bytes, got %d", len(signature))
	}

	return signature, nil
}

// GetAddress returns the address of the signer.
//
// Returns the address of the signer.
func (s *DefaultProvider) GetAddress() string {
	return strings.ToLower(crypto.PubkeyToAddress(s.priv.PublicKey).Hex())
}
