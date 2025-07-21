package vc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
)

// TypedID represents an ID with an optional type.
type TypedID struct {
	ID   string
	Type string
}

// TypedResource represents a related resource with additional fields.
type TypedResource struct {
	ID              string
	Type            string
	MediaType       string
	DigestSRI       string
	DigestMultibase string
}

// ECDSADescriptor is an implementation of ProofDescriptor for ECDSA.
type ECDSADescriptor struct{}

// ProofType returns the proof type.
func (d *ECDSADescriptor) ProofType() string {
	return "DataIntegrityProof"
}

// SupportedKeyTypes returns the supported key types.
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
		return nil, fmt.Errorf("private key is nil")
	}

	// Perform ECDSA signature
	r, sVal, err := ecdsa.Sign(rand.Reader, s.PrivateKey, data)
	if err != nil {
		return nil, fmt.Errorf("ecdsa sign: %w", err)
	}

	// Ensure r and s are 32 bytes each
	rBytes := r.Bytes()
	sBytes := sVal.Bytes()
	if len(rBytes) > 32 || len(sBytes) > 32 {
		return nil, fmt.Errorf("invalid ECDSA signature component length: r=%d, s=%d", len(rBytes), len(sBytes))
	}

	// Pad r and s to 32 bytes if necessary
	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)
	copy(rPadded[32-len(rBytes):], rBytes)
	copy(sPadded[32-len(sBytes):], sBytes)

	// Concatenate r and s (64 bytes total)
	sig := append(rPadded, sPadded...)
	if len(sig) != 64 {
		return nil, fmt.Errorf("invalid signature length: expected 64 bytes, got %d", len(sig))
	}

	if encode {
		// Encode in Base64 URL-safe format for JWT or JWS
		encoded := base64.RawURLEncoding.EncodeToString(sig)
		fmt.Printf("Encoded signature: %s\n", encoded)
		return []byte(encoded), nil
	}
	// Return raw signature for proofValue
	fmt.Printf("Raw signature length: %d\n", len(sig))
	return sig, nil
}

// Algorithm returns the algorithm.
func (s *ECDSASigner) Algorithm() Algorithm {
	return AlgorithmECDSAP256
}

// KeyType returns the key type.
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
		return fmt.Errorf("public key must be *ecdsa.PublicKey, got %T", publicKey)
	}
	if v.PublicKey == nil || pubKey == nil {
		return fmt.Errorf("public key is nil")
	}

	sig := signature
	// Check if signature is Base64-encoded (for JWS/JWT)
	if strings.Contains(string(signature), ".") || strings.Contains(string(signature), "=") || len(signature) > 64 {
		var err error
		sig, err = base64.RawURLEncoding.DecodeString(string(signature))
		if err != nil {
			return fmt.Errorf("decode Base64 signature: %w", err)
		}
		fmt.Printf("Decoded Base64 signature length: %d\n", len(sig))
	}

	// Remove disclosures if present (for JWS)
	sigStr := string(sig)
	if strings.Contains(sigStr, "~") {
		parts := strings.Split(sigStr, "~")
		sig = []byte(parts[0])
	}

	fmt.Printf("Verifying signature (length: %d)\n", len(sig))
	if len(sig) != 64 {
		return fmt.Errorf("invalid signature length: expected 64 bytes, got %d", len(sig))
	}

	// Extract r and s (32 bytes each)
	r := big.NewInt(0).SetBytes(sig[:32])
	s := big.NewInt(0).SetBytes(sig[32:])

	// Verify signature
	if !ecdsa.Verify(pubKey, data, r, s) {
		return fmt.Errorf("ecdsa verification failed")
	}
	return nil
}

// KeyType returns the key type.
func (v *ECDSAVerifier) KeyType() KeyType {
	return KeyTypeECDSAP256
}
