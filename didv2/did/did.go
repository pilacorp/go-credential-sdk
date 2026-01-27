package did

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"maps"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// GenerateECDSAKeyPair generates a new ECDSA key pair and creates a KeyPair struct.
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

// GenerateDIDDocument creates a DID document from a key pair and request metadata.
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

// AddressFromPublicKeyHex converts a public key hex to an address.
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
