package signer

import (
	"crypto/ecdsa"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

type SignerProvider interface {
	Sign(payload []byte) ([]byte, error)
	GetAddress() string
}

type DefaultProvider struct {
	priv *ecdsa.PrivateKey
}

func NewDefaultProvider(privHex string) (SignerProvider, error) {
	priv, err := crypto.HexToECDSA(strings.TrimPrefix(privHex, "0x"))
	if err != nil {
		return nil, err
	}
	return &DefaultProvider{priv: priv}, nil
}

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

func (s *DefaultProvider) GetAddress() string {
	return crypto.PubkeyToAddress(s.priv.PublicKey).Hex()
}
