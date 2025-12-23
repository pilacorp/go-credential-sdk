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

type TxSigner struct {
	priv *ecdsa.PrivateKey
}

func NewTxSigner(privHex string) (Signer, error) {
	priv, err := crypto.HexToECDSA(privHex)
	if err != nil {
		return nil, err
	}
	return &TxSigner{priv: priv}, nil
}

func (s *TxSigner) Sign(hashPayload []byte) ([]byte, error) {
	signature, err := crypto.Sign(hashPayload, s.priv)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	if len(signature) != 65 {
		return nil, fmt.Errorf("invalid signature length: expected 65 bytes, got %d", len(signature))
	}

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
