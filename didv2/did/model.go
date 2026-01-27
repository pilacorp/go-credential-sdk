package did

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-credential-sdk/didv2/did/jsoncanonicalizer"
)

// DIDType represents the type of DID being issued.
//
// Different DID types serve different purposes in the system:
//   - People: For individuals/persons
//   - Item: For products/items
//   - Location: For physical locations
//   - Activity: For activities/events
type DIDType uint8

// DID type constants.
const (
	// DIDTypePeople represents a DID for a person or individual.
	DIDTypePeople DIDType = 0
	// DIDTypeItem represents a DID for an item or product.
	DIDTypeItem DIDType = 1
	// DIDTypeActivity represents a DID for an activity or event.
	DIDTypeActivity DIDType = 2
	// DIDTypeLocation represents a DID for a location.
	DIDTypeLocation DIDType = 3
)

// DIDDocument represents a W3C-compliant DID Document.
//
// A DID Document is the core identity document that:
//   - Declares the DID identifier
//   - Publishes verification methods (public keys)
//   - Specifies the controller (Issuer)
//   - Includes authentication and assertion methods
//   - Contains metadata about the DID
//
// The document is canonicalized and hashed to create an immutable DocHash
// that binds the document content to signatures and on-chain records.
type DIDDocument struct {
	// Context contains the JSON-LD context URIs for the DID Document.
	Context []string `json:"@context"`
	// Id is the full DID identifier (e.g., "did:nda:0x1234...").
	Id string `json:"id"`
	// Controller is the DID identifier of the Issuer who controls this DID.
	Controller string `json:"controller"`
	// VerificationMethod contains the public keys and verification methods
	// that can be used to verify signatures related to this DID.
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	// Authentication lists the verification methods that can be used for authentication.
	Authentication []string `json:"authentication"`
	// AssertionMethod lists the verification methods that can be used for assertions.
	AssertionMethod []string `json:"assertionMethod"`
	// DocumentMetadata contains additional metadata about the DID Document,
	// such as type, hash, and custom key-value pairs.
	DocumentMetadata map[string]any `json:"didDocumentMetadata"`
}

// VerificationMethod represents a public key verification method in a DID Document.
//
// It specifies how signatures related to this DID can be verified using the
// published public key.
type VerificationMethod struct {
	// Id is the unique identifier of this verification method (e.g., "did:nda:0x...#key-1").
	Id string `json:"id"`
	// Type specifies the cryptographic suite (e.g., "EcdsaSecp256k1VerificationKey2019").
	Type string `json:"type"`
	// Controller is the DID that controls this verification method.
	Controller string `json:"controller"`
	// PublicKeyHex is the hex-encoded public key (compressed format).
	PublicKeyHex string `json:"publicKeyHex,omitempty"`
}

// KeyPair represents an ECDSA key pair for a DID.
//
// The key pair consists of a public key (used in DID Documents) and a private key
// (used for signing and proving ownership). The private key must be stored securely.
type KeyPair struct {
	// PublicKey is the ECDSA public key used in DID Documents and for verification.
	PublicKey *ecdsa.PublicKey `json:"publicKey"`
	// PrivateKey is the ECDSA private key used for signing and proving DID ownership.
	// This must be stored securely and never exposed.
	PrivateKey *ecdsa.PrivateKey `json:"privateKey"`
}

// Hash calculates the Keccak256 hash of the canonicalized DID Document.
//
// The document is first canonicalized using JSON canonicalization to ensure
// consistent hashing regardless of formatting. This hash (DocHash) is used to:
//   - Bind the document content to issuer signatures
//   - Create an immutable reference in on-chain transactions
//   - Verify document integrity
//
// Returns the hash as a lowercase hex string (with "0x" prefix).
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

// GetAddress returns the Ethereum address derived from the public key.
//
// The address is computed using the standard Ethereum address derivation:
// Keccak256 hash of the public key, taking the last 20 bytes.
//
// Returns the address as a lowercase hex string (with "0x" prefix).
// Returns empty string if the public key is invalid.
func (k *KeyPair) GetAddress() string {
	if k.PublicKey == nil {
		fmt.Println("invalid public key")

		return ""
	}

	return strings.ToLower(crypto.PubkeyToAddress(*k.PublicKey).Hex())
}

// GetDID returns the full DID identifier for this key pair.
//
// The DID is constructed as: "{method}:{address}" (e.g., "did:nda:0x1234...").
//
// The method parameter is the DID method identifier (e.g., "did:nda").
// Returns the DID as a lowercase string.
// Returns empty string if the public key is invalid or method is empty.
func (k *KeyPair) GetDID(method string) string {
	if k.PublicKey == nil || method == "" {
		fmt.Println("invalid public key or method: public key is nil or method is empty")

		return ""
	}

	return strings.ToLower(fmt.Sprintf("%s:%s", method, k.GetAddress()))
}

// GetPublicKeyHex returns the public key in compressed hex format.
//
// The public key is compressed to 33 bytes (0x02 or 0x03 prefix + 32 bytes).
// This format is used in DID Documents and for address derivation.
//
// Returns the public key as a lowercase hex string (with "0x" prefix).
// Returns empty string if the public key is invalid.
func (k *KeyPair) GetPublicKeyHex() string {
	if k.PublicKey == nil {
		fmt.Println("invalid public key")

		return ""
	}

	return strings.ToLower("0x" + fmt.Sprintf("%x", crypto.CompressPubkey(k.PublicKey)))
}

// GetPrivateKeyHex returns the private key in hex format.
//
// WARNING: The private key is sensitive information that proves ownership of the DID.
// Store this securely and never expose it in logs, error messages, or public APIs.
//
// Returns the private key as a lowercase hex string (with "0x" prefix).
// Returns empty string if the private key is invalid.
func (k *KeyPair) GetPrivateKeyHex() string {
	if k.PrivateKey == nil {
		fmt.Println("invalid private key")

		return ""
	}

	return strings.ToLower("0x" + fmt.Sprintf("%x", crypto.FromECDSA(k.PrivateKey)))
}

// String returns the string representation of the DIDType.
//
// Returns "people", "item", "activity", "location", or "unknown" for invalid types.
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

// ToDID constructs a full DID identifier from a method and Ethereum address.
//
// The DID format is: "{method}:{address}" (e.g., "did:nda:0x1234...").
//
// The method parameter is the DID method identifier (e.g., "did:nda").
// The address parameter is the Ethereum address (with or without "0x" prefix).
//
// Returns the DID as a lowercase string.
func ToDID(method, address string) string {
	return strings.ToLower(fmt.Sprintf("%s:%s", method, address))
}
