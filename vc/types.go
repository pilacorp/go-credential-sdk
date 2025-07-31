package vc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"math/big"
	"strings"
)

// TypedID represents an ID with an optional type, used in credential schemas or other typed references.
type TypedID struct {
	ID   string
	Type string
}

// TypedResource represents a related resource with additional fields for media and digest information.
type TypedResource struct {
	ID              string
	Type            string
	MediaType       string
	DigestSRI       string
	DigestMultibase string
}

// ECDSADescriptor is an implementation of ProofDescriptor for ECDSA-based proofs.
type ECDSADescriptor struct{}

// ProofType returns the proof type for ECDSA.
func (d *ECDSADescriptor) ProofType() string {
	return "DataIntegrityProof"
}

// SupportedKeyTypes returns the supported key types for ECDSA.
func (d *ECDSADescriptor) SupportedKeyTypes() []KeyType {
	return []KeyType{KeyTypeECDSAP256}
}

// ECDSASigner is an implementation of CryptographicSigner for ECDSA.
type ECDSASigner struct {
	PrivateKey *ecdsa.PrivateKey
}

// Sign performs an ECDSA signature, returning raw or Base64-encoded signature based on encode flag.
func (s *ECDSASigner) Sign(data []byte, encode bool) ([]byte, error) {
	if s.PrivateKey == nil {
		return nil, fmt.Errorf("failed to sign: private key is nil")
	}
	r, sVal, err := ecdsa.Sign(rand.Reader, s.PrivateKey, data)
	if err != nil {
		return nil, fmt.Errorf("failed to perform ECDSA sign: %w", err)
	}
	rBytes, sBytes := padSignatureComponent(r, sVal)
	sig := append(rBytes, sBytes...)
	if len(sig) != 64 {
		return nil, fmt.Errorf("failed to sign: invalid signature length: expected 64 bytes, got %d", len(sig))
	}
	if encode {
		encoded := base64.RawURLEncoding.EncodeToString(sig)
		log.Printf("Encoded signature: %s", encoded)
		return []byte(encoded), nil
	}
	log.Printf("Raw signature length: %d", len(sig))
	return sig, nil
}

// padSignatureComponent pads ECDSA signature components to 32 bytes each.
func padSignatureComponent(r, s *big.Int) ([]byte, []byte) {
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)
	copy(rPadded[32-len(rBytes):], rBytes)
	copy(sPadded[32-len(sBytes):], sBytes)
	return rPadded, sPadded
}

// Algorithm returns the ECDSA algorithm.
func (s *ECDSASigner) Algorithm() Algorithm {
	return AlgorithmECDSAP256
}

// KeyType returns the ECDSA key type.
func (s *ECDSASigner) KeyType() KeyType {
	return KeyTypeECDSAP256
}

// ECDSAVerifier is an implementation of CryptographicVerifier for ECDSA.
type ECDSAVerifier struct {
	PublicKey *ecdsa.PublicKey
}

// Verify performs an ECDSA verification.
func (v *ECDSAVerifier) Verify(data, signature []byte, publicKey interface{}) error {
	pubKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("failed to verify: public key must be *ecdsa.PublicKey, got %T", publicKey)
	}
	if v.PublicKey == nil || pubKey == nil {
		return fmt.Errorf("failed to verify: public key is nil")
	}
	sig := signature
	if strings.Contains(string(signature), ".") || strings.Contains(string(signature), "=") || len(signature) > 64 {
		var err error
		sig, err = base64.RawURLEncoding.DecodeString(string(signature))
		if err != nil {
			return fmt.Errorf("failed to decode Base64 signature: %w", err)
		}
		log.Printf("Decoded Base64 signature length: %d", len(sig))
	}
	if strings.Contains(string(sig), "~") {
		parts := strings.Split(string(sig), "~")
		sig = []byte(parts[0])
	}
	log.Printf("Verifying signature (length: %d)", len(sig))
	if len(sig) != 64 {
		return fmt.Errorf("failed to verify: invalid signature length: expected 64 bytes, got %d", len(sig))
	}
	r := big.NewInt(0).SetBytes(sig[:32])
	s := big.NewInt(0).SetBytes(sig[32:])
	if !ecdsa.Verify(pubKey, data, r, s) {
		return fmt.Errorf("failed to verify: ECDSA verification failed")
	}
	return nil
}

// KeyType returns the ECDSA key type.
func (v *ECDSAVerifier) KeyType() KeyType {
	return KeyTypeECDSAP256
}
