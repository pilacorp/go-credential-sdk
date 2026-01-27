// Package signer provides an abstraction layer for cryptographic signing operations.
//
// The SignerProvider interface allows different signing implementations:
//   - DefaultProvider: Local ECDSA signing with private key
//   - Custom implementations: HSM, hardware wallets, remote signing services, Vault
//
// This abstraction enables flexible key management while maintaining a consistent
// API for signing operations across the SDK.
package signer

import (
	"crypto/ecdsa"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// SignerProvider is the interface for signing operations in the DID V2 SDK.
//
// There are two types of signers in the SDK:
//   - Issuer Signer: Uses Issuer's private key to create issuer signatures
//   - DID/Tx Signer: Uses DID's private key to sign transactions
//
// Implementations can use local keys, HSMs, hardware wallets, or remote signing services.
type SignerProvider interface {
	// Sign signs the provided payload and returns a 65-byte signature.
	// The signature format is: [R (32 bytes)][S (32 bytes)][V (1 byte)]
	// where V is the recovery ID (27 or 28 for Ethereum).
	Sign(payload []byte) ([]byte, error)
	// GetAddress returns the Ethereum address of the signer.
	// This is used to derive DID identifiers and identify the signer.
	GetAddress() string
}

// DefaultProvider is the default implementation of SignerProvider using local ECDSA keys.
//
// This implementation uses go-ethereum's crypto package for signing with a private key
// stored in memory. For production use, consider implementing custom signers that use
// secure key storage (HSM, Vault, hardware wallets).
type DefaultProvider struct {
	priv *ecdsa.PrivateKey
}

// NewDefaultProvider creates a new DefaultProvider from a hex-encoded private key.
//
// The privHex parameter can include or omit the "0x" prefix.
// This is suitable for development and testing. For production, use custom
// SignerProvider implementations with secure key storage.
//
// Returns a SignerProvider or an error if the private key is invalid.
func NewDefaultProvider(privHex string) (SignerProvider, error) {
	priv, err := crypto.HexToECDSA(strings.TrimPrefix(privHex, "0x"))
	if err != nil {
		return nil, err
	}
	return &DefaultProvider{priv: priv}, nil
}

// Sign signs the provided payload using the ECDSA private key.
//
// The payload should be the hash of the data to sign (e.g., Keccak256 hash).
// Returns a 65-byte signature: [R (32 bytes)][S (32 bytes)][V (1 byte)].
// The V component is the recovery ID (27 or 28 for Ethereum).
//
// Returns an error if signing fails or if the signature format is invalid.
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

// GetAddress returns the Ethereum address derived from the signer's public key.
//
// The address is computed using standard Ethereum address derivation and returned
// as a lowercase hex string (with "0x" prefix).
func (s *DefaultProvider) GetAddress() string {
	return strings.ToLower(crypto.PubkeyToAddress(s.priv.PublicKey).Hex())
}
