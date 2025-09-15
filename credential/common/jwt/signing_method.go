package jwt

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
)

// SigningMethodES256K implements ES256K signing
type SigningMethodES256K struct{}

// Alg returns the algorithm name
func (m *SigningMethodES256K) Alg() string {
	return "ES256K"
}

// Sign signs a string with private key
func (m *SigningMethodES256K) Sign(signingString string, key interface{}) ([]byte, error) {
	privKeyHex, ok := key.(string)
	if !ok {
		return nil, fmt.Errorf("invalid key type")
	}

	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	privKey, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	hash := sha256.Sum256([]byte(signingString))
	sig, err := crypto.Sign(hash[:], privKey)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return sig[:64], nil // Return R and S, excluding recovery ID
}

// Verify verifies a signature
func (m *SigningMethodES256K) Verify(signingString string, signature []byte, key interface{}) error {
	publicKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid key type")
	}

	if len(signature) != 64 {
		return fmt.Errorf("invalid signature length")
	}

	hash := sha256.Sum256([]byte(signingString))
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	if !ecdsa.Verify(publicKey, hash[:], r, s) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// ES256K is the ES256K signing method instance
var ES256K = &SigningMethodES256K{}
