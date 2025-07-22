package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
)

const secp256k1KeySize = 32

// ECDSASigner makes ECDSA based signatures.
type ECDSASigner struct {
	privateKey *ecdsa.PrivateKey
	hash       crypto.Hash
}

func newECDSASigner(privKey *ecdsa.PrivateKey, hash crypto.Hash) *ECDSASigner {
	return &ECDSASigner{
		privateKey: privKey,
		hash:       hash,
	}
}

// Sign signs a message using ECDSA with secp256k1.
func (es *ECDSASigner) Sign(msg []byte) ([]byte, error) {
	hasher := es.hash.New()
	if _, err := hasher.Write(msg); err != nil {
		return nil, fmt.Errorf("ecdsa: hash error: %w", err)
	}
	hashed := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, es.privateKey, hashed)
	if err != nil {
		return nil, fmt.Errorf("ecdsa: sign error: %w", err)
	}

	keyBytes := es.privateKey.Curve.Params().BitSize / 8
	if es.privateKey.Curve.Params().BitSize%8 > 0 {
		keyBytes++
	}

	// Pad r and s to fixed length
	signature := make([]byte, 2*keyBytes)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(signature[keyBytes-len(rBytes):], rBytes)
	copy(signature[2*keyBytes-len(sBytes):], sBytes)

	return signature, nil
}

// NewECDSASecp256k1Signer creates a new ECDSA secp256k1 signer.
func NewECDSASecp256k1Signer(privateKey *ecdsa.PrivateKey) *ECDSASigner {
	return newECDSASigner(privateKey, crypto.SHA256)
}

// Verifier verifies ECDSA secp256k1 signatures.
type Verifier struct {
	curve   elliptic.Curve
	keySize int
	hash    crypto.Hash
}

// NewSecp256k1 creates a new signature verifier for ECDSA secp256k1.
func NewSecp256k1() *Verifier {
	return &Verifier{
		curve:   btcec.S256(),
		keySize: secp256k1KeySize,
		hash:    crypto.SHA256,
	}
}

// Verify verifies the signature for the given message and public key bytes.
func (v *Verifier) Verify(signature, msg, pubKeyBytes []byte) error {
	// Create ECDSA public key from bytes
	x, y := elliptic.Unmarshal(v.curve, pubKeyBytes)
	if x == nil {
		return errors.New("ecdsa: invalid public key bytes")
	}
	pubKey := &ecdsa.PublicKey{Curve: v.curve, X: x, Y: y}

	// Check signature size for IEEE P1363 format
	if len(signature) < 2*v.keySize {
		return errors.New("ecdsa: invalid signature size")
	}

	// Hash the message
	hasher := v.hash.New()
	if _, err := hasher.Write(msg); err != nil {
		return errors.New("ecdsa: hash error")
	}
	hash := hasher.Sum(nil)

	// Extract r and s
	r := big.NewInt(0).SetBytes(signature[:v.keySize])
	s := big.NewInt(0).SetBytes(signature[v.keySize:])

	// Try ASN.1 DER format if signature is longer
	if len(signature) > 2*v.keySize {
		var esig struct {
			R, S *big.Int
		}
		if _, err := asn1.Unmarshal(signature, &esig); err == nil {
			r = esig.R
			s = esig.S
		}
	}

	if r.Sign() == 0 || s.Sign() == 0 {
		return errors.New("ecdsa: invalid signature format")
	}

	// Verify signature
	if !ecdsa.Verify(pubKey, hash, r, s) {
		return errors.New("ecdsa: invalid signature")
	}

	return nil
}
