package signer

import (
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-credential-sdk/didv2/blockchain"
)

type Signer interface {
	Sign(payload []byte) ([]byte, error)
}

type DefaultSigner struct {
	priv *ecdsa.PrivateKey
}

func NewDefaultSigner(privHex string) (Signer, error) {
	priv, err := crypto.HexToECDSA(privHex)
	if err != nil {
		return nil, err
	}
	return &DefaultSigner{priv: priv}, nil
}

func (s *DefaultSigner) Sign(payload []byte) ([]byte, error) {
	return blockchain.SignPayload(s.priv, payload)
}
