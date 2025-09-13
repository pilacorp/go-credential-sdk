package jwt

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
)

// SigningMethodES256K implements JWT signing using ES256K algorithm
type SigningMethodES256K struct{}

func (m *SigningMethodES256K) Alg() string {
	return "ES256K"
}

func (m *SigningMethodES256K) Verify(signingString string, signature []byte, key interface{}) error {
	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid key type: expected *ecdsa.PublicKey")
	}

	hasher := sha256.New()
	hasher.Write([]byte(signingString))
	digest := hasher.Sum(nil)

	if len(signature) != 64 {
		return fmt.Errorf("invalid signature length")
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	if !ecdsa.Verify(ecdsaKey, digest, r, s) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

func (m *SigningMethodES256K) Sign(signingString string, key interface{}) ([]byte, error) {
	privKeyHex, ok := key.(string)
	if !ok {
		return nil, fmt.Errorf("invalid key type: expected string")
	}

	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key hex: %w", err)
	}

	privKey, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	hasher := sha256.New()
	hasher.Write([]byte(signingString))
	digest := hasher.Sum(nil)

	sig, err := crypto.Sign(digest, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create ecdsa signature: %w", err)
	}

	return sig[:64], nil // Return R and S, excluding the recovery ID (V)
}

var ES256K = &SigningMethodES256K{}
