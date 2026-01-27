// Package did provides core DID domain logic including key pair generation,
// DID Document creation, and address derivation.
//
// This package is the foundation module used by both Wallet/App and Backend
// services in all deployment models.
package did

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"maps"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// GenerateECDSAKeyPair generates a new ECDSA key pair for DID creation.
//
// This is the foundational function for key pair generation used across all
// deployment models. In Model 2, Wallet/App calls this first before requesting
// an issuer signature from Backend.
//
// Returns a KeyPair containing both public and private keys. The private key
// should be stored securely as it proves ownership of the DID.
func GenerateECDSAKeyPair() (*KeyPair, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	return &KeyPair{
		PublicKey:  privateKey.Public().(*ecdsa.PublicKey),
		PrivateKey: privateKey,
	}, nil
}

// GenerateDIDDocument creates a W3C-compliant DID Document from the provided parameters.
//
// The DID Document is the core identity document that:
//   - Declares the DID identifier
//   - Publishes the public key for verification
//   - Specifies the controller (Issuer)
//   - Includes metadata and verification methods
//
// The didPublicKey parameter is the hex-encoded public key (compressed or uncompressed).
// The did parameter is the full DID identifier (e.g., "did:nda:0x1234...").
// The hash parameter is an optional hash value to include in document metadata.
// The issuerDID parameter is the DID identifier of the Issuer (controller).
// The didType parameter specifies the type of DID (People, Item, Location, Activity).
// The metadata parameter contains additional key-value pairs for the document.
//
// Returns a DIDDocument that can be hashed and included in blockchain transactions.
func GenerateDIDDocument(didPublicKey, did, hash, issuerDID string, didType DIDType, metadata map[string]any) *DIDDocument {
	docMetadata := make(map[string]any)
	maps.Copy(docMetadata, metadata)

	if didType.String() != "" {
		docMetadata["type"] = didType.String()
	}

	if hash != "" {
		docMetadata["hash"] = hash
	}

	return &DIDDocument{
		Context: []string{
			"https://w3id.org/security/v1",
			"https://www.w3.org/ns/did/v1",
		},
		Id:         did,
		Controller: issuerDID,
		VerificationMethod: []VerificationMethod{{
			Id:           did + "#key-1",
			Type:         "EcdsaSecp256k1VerificationKey2019",
			Controller:   did,
			PublicKeyHex: didPublicKey,
		}},
		Authentication:   []string{did + "#key-1"},
		AssertionMethod:  []string{did + "#key-1"},
		DocumentMetadata: docMetadata,
	}
}

// AddressFromPublicKeyHex converts a hex-encoded public key to an Ethereum address.
//
// Supports both compressed (33 bytes) and uncompressed (65 bytes) public key formats.
// The publicKeyHex parameter can include or omit the "0x" prefix.
//
// Returns the Ethereum address in lowercase hex format (with "0x" prefix).
// This address is used to derive the DID identifier and for on-chain operations.
func AddressFromPublicKeyHex(publicKeyHex string) (string, error) {
	// Decode hex-encoded public key
	publicKeyBytes, err := hex.DecodeString(strings.TrimPrefix(publicKeyHex, "0x"))
	if err != nil {
		return "", fmt.Errorf("failed to decode public key hex: %w", err)
	}

	var publicKey *ecdsa.PublicKey

	// Handle compressed public key (33 bytes)
	if len(publicKeyBytes) == 33 && (publicKeyBytes[0] == 0x02 || publicKeyBytes[0] == 0x03) {
		publicKey, err = crypto.DecompressPubkey(publicKeyBytes)
		if err != nil {
			return "", fmt.Errorf("failed to decompress public key: %w", err)
		}
	} else if len(publicKeyBytes) == 65 && publicKeyBytes[0] == 0x04 {
		// Handle uncompressed public key (65 bytes)
		publicKey, err = crypto.UnmarshalPubkey(publicKeyBytes)
		if err != nil {
			return "", fmt.Errorf("failed to unmarshal public key: %w", err)
		}
	} else {
		return "", fmt.Errorf("unsupported public key format: expected 33 bytes (compressed) or 65 bytes (uncompressed), got %d bytes", len(publicKeyBytes))
	}

	return strings.ToLower(crypto.PubkeyToAddress(*publicKey).Hex()), nil
}
