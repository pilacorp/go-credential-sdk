package signer

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
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

// TxSignerFn creates a bind.SignerFn-compatible function using a generic SignerProvider.
// It hashes the transaction with EIP-155 and signs it via the provided SignerProvider.
func TxSignerFn(chainID *big.Int, s SignerProvider) func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
	return func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
		eip155Signer := types.NewEIP155Signer(chainID)
		h := eip155Signer.Hash(tx)
		sig, err := s.Sign(h.Bytes())
		if err != nil {
			return nil, err
		}

		return tx.WithSignature(eip155Signer, sig)
	}
}
