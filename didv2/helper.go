package didv2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-credential-sdk/didv2/blockchain"
)

// GenerateECDSADID generates a new ECDSA key pair and creates a KeyPair
func GenerateECDSADID(method string) (*KeyPair, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	publicKeyECDSA, ok := privateKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("-----error casting public key to ECDSA")
	}
	address := strings.ToLower(crypto.PubkeyToAddress(*publicKeyECDSA).Hex())
	privateKeyHex := strings.ToLower("0x" + fmt.Sprintf("%x", crypto.FromECDSA(privateKey)))
	publicKeyHex := strings.ToLower("0x" + fmt.Sprintf("%x", crypto.CompressPubkey(publicKeyECDSA)))

	// Create DID identifier: ${method}:${address}
	identifier := strings.ToLower(fmt.Sprintf("%s:%s", method, address))

	// Create KeyPair
	keyPair := &KeyPair{
		Address:    address,
		PublicKey:  publicKeyHex,
		PrivateKey: privateKeyHex,
		Identifier: identifier,
	}

	return keyPair, nil
}

// GenerateDIDDocument creates a DID document from a key pair and request metadata
func GenerateDIDDocument(keyPair *KeyPair, didType blockchain.DIDType, hash string, metadata map[string]interface{}, signerDID string) *DIDDocument {
	docMetadata := make(map[string]interface{})

	// Copy existing metadata if present
	for k, v := range metadata {
		docMetadata[k] = v
	}

	// Always set type and hash
	if didType.ToString() != "" {
		docMetadata["type"] = didType.ToString()
	}
	if hash != "" {
		docMetadata["hash"] = hash
	}

	document := &DIDDocument{
		Context: []string{
			"https://w3id.org/security/v1",
			"https://www.w3.org/ns/did/v1",
		},
		Id:         keyPair.Identifier,
		Controller: signerDID,
		VerificationMethod: []VerificationMethod{{
			Id:           keyPair.Identifier + "#key-1",
			Type:         "EcdsaSecp256k1VerificationKey2019",
			Controller:   keyPair.Identifier,
			PublicKeyHex: keyPair.PublicKey,
		}},
		Authentication:   []string{keyPair.Identifier + "#key-1"},
		AssertionMethod:  []string{keyPair.Identifier + "#key-1"},
		DocumentMetadata: docMetadata,
	}

	return document
}

// RandomHex returns a random bytes as 0x-prefixed hex string.
func RandomHex(length int) (string, error) {
	var b = make([]byte, length)

	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("rand.Read failed: %w", err)
	}

	return hex.EncodeToString(b[:]), nil
}
