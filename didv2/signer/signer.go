package signer

import (
	"crypto/ecdsa"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

type SignOptions map[string]interface{}
type SignerProvider interface {
	Sign(payload []byte, opts ...SignOptions) ([]byte, error)
	GetAddress() string
}

type DefaultProvider struct {
	priv *ecdsa.PrivateKey
	addr string
}

func NewDefaultProvider(privHex string) (SignerProvider, error) {
	if strings.TrimSpace(privHex) == "" {
		return nil, fmt.Errorf("private key cannot be empty")
	}

	priv, err := crypto.HexToECDSA(strings.TrimPrefix(privHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	return &DefaultProvider{
		priv: priv,
		addr: crypto.PubkeyToAddress(priv.PublicKey).Hex(),
	}, nil
}

func (s *DefaultProvider) Sign(hashPayload []byte, opts ...SignOptions) ([]byte, error) {
	// Process optional parameters if provided
	var options SignOptions
	if len(opts) > 0 {
		options = opts[0]
	}

	// You can use options here for customization
	// Example: if options != nil {
	//     if customValue, ok := options["someKey"]; ok {
	//         // Use customValue for custom behavior
	//     }
	// }
	_ = options // Placeholder to avoid unused variable error

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
	return s.addr
}
