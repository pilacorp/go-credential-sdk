package did

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-credential-sdk/didv2/did/jsoncanonicalizer"
)

// DIDType is the type of DID.
type DIDType uint8

// DIDType constants.
const (
	DIDTypePeople   DIDType = 0
	DIDTypeItem     DIDType = 1
	DIDTypeActivity DIDType = 2
	DIDTypeLocation DIDType = 3
)

// DIDDocument is the DID document.
type DIDDocument struct {
	Context            []string             `json:"@context"`
	Id                 string               `json:"id"`
	Controller         string               `json:"controller"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	Authentication     []string             `json:"authentication"`
	AssertionMethod    []string             `json:"assertionMethod"`
	DocumentMetadata   map[string]any       `json:"didDocumentMetadata"`
}

// VerificationMethod is the verification method for the DID document.
type VerificationMethod struct {
	Id           string `json:"id"`
	Type         string `json:"type"`
	Controller   string `json:"controller"`
	PublicKeyHex string `json:"publicKeyHex,omitempty"`
}

// KeyPair represents the generated wallet and DID identifier.
type KeyPair struct {
	PublicKey  *ecdsa.PublicKey  `json:"publicKey"`
	PrivateKey *ecdsa.PrivateKey `json:"privateKey"`
}

// Hash calculates the Keccak256 hash of a DID document.
//
// Each DID document is hashed to get a unique hash.
func (doc *DIDDocument) Hash() (string, error) {
	docJSON, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("failed to marshal DID document: %w", err)
	}

	docToHash, err := jsoncanonicalizer.Transform(docJSON)
	if err != nil {
		return "", fmt.Errorf("failed to transform DID document: %w", err)
	}

	hash := crypto.Keccak256Hash(docToHash)

	return strings.ToLower(hash.Hex()), nil
}

// GetAddress returns the address of the key pair.
func (k *KeyPair) GetAddress() string {
	if k.PublicKey == nil {
		fmt.Println("invalid public key")

		return ""
	}

	return strings.ToLower(crypto.PubkeyToAddress(*k.PublicKey).Hex())
}

// GetDID returns the DID of the key pair.
func (k *KeyPair) GetDID(method string) string {
	if k.PublicKey == nil || method == "" {
		fmt.Println("invalid public key or method: public key is nil or method is empty")

		return ""
	}

	return strings.ToLower(fmt.Sprintf("%s:%s", method, k.GetAddress()))
}

// GetPublicKeyHex returns the public key in hex format.
func (k *KeyPair) GetPublicKeyHex() string {
	if k.PublicKey == nil {
		fmt.Println("invalid public key")

		return ""
	}

	return strings.ToLower("0x" + fmt.Sprintf("%x", crypto.CompressPubkey(k.PublicKey)))
}

// GetPrivateKeyHex returns the private key in hex format.
func (k *KeyPair) GetPrivateKeyHex() string {
	if k.PrivateKey == nil {
		fmt.Println("invalid private key")

		return ""
	}

	return strings.ToLower("0x" + fmt.Sprintf("%x", crypto.FromECDSA(k.PrivateKey)))
}

// String returns the string representation of the DIDType.
func (d DIDType) String() string {
	switch d {
	case DIDTypeItem:
		return "item"
	case DIDTypePeople:
		return "people"
	case DIDTypeLocation:
		return "location"
	case DIDTypeActivity:
		return "activity"
	default:
		return "unknown"
	}
}

// ToDID converts a method and address to a DID.
func ToDID(method, address string) string {
	return strings.ToLower(fmt.Sprintf("%s:%s", method, address))
}
