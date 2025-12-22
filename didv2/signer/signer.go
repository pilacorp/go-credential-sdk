package signer

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
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
	hash := crypto.Keccak256Hash(payload)

	signature, err := crypto.Sign(hash.Bytes(), s.priv)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	if len(signature) != 65 {
		return nil, fmt.Errorf("invalid signature length: expected 65 bytes, got %d", len(signature))
	}

	// Normalize recovery ID to Ethereum format: 27 or 28
	v := signature[64]
	if v < 27 {
		v += 27
	}
	signature[64] = v

	return signature, nil
}

// TxSignerFn creates a bind.SignerFn-compatible function using a generic Signer.
// It hashes the transaction with EIP-155 and signs it via the provided Signer.
func TxSignerFn(chainID *big.Int, s Signer) func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
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
