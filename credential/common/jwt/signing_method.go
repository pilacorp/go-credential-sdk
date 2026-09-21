package jwt

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// JOSE algorithms this package signs and verifies.
const (
	AlgES256K = "ES256K" // secp256k1
	AlgES256  = "ES256"  // P-256
)

// AlgForKeyKind returns the JOSE algorithm for the key a verification method
// holds. RSA is rejected: the JWT path signs a 64-byte R||S signature.
func AlgForKeyKind(kind verificationmethod.KeyKind) (string, error) {
	switch kind {
	case verificationmethod.KeySecp256k1:
		return AlgES256K, nil
	case verificationmethod.KeyP256:
		return AlgES256, nil
	}
	return "", fmt.Errorf("key kind %v is not supported for JWT", kind)
}

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

// Verify verifies an ES256K signature. The check is plain ECDSA on the key's
// curve (see VerifyECDSA).
func (m *SigningMethodES256K) Verify(signingString string, signature []byte, key interface{}) error {
	publicKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid key type")
	}
	return VerifyECDSA(signingString, signature, publicKey)
}

// VerifyECDSA verifies a 64-byte r||s signature over SHA-256(signingString)
// with publicKey, on whatever curve the key is on. ES256K (secp256k1) and
// ES256 (P-256) differ only in that curve, so one check serves both.
func VerifyECDSA(signingString string, signature []byte, publicKey *ecdsa.PublicKey) error {
	if publicKey == nil {
		return fmt.Errorf("public key is nil")
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
