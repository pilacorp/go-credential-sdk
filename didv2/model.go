package didv2

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-credential-sdk/didv2/blockchain"
)

// KeyPair represents the generated wallet and DID identifier
type KeyPair struct {
	Address    string `json:"address"`
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
	Identifier string `json:"identifier"`
}

type ReGenerateDIDRxRequest struct {
	IssuerAddress string                 `json:"issuerAddress"`
	IssuerPkHex   string                 `json:"issuerPrivateKeyHex"`
	DIDPkHex      string                 `json:"didPkHex"`
	Type          blockchain.DIDType     `json:"type"`
	Metadata      map[string]interface{} `json:"metadata"`
	Hash          string                 `json:"hash"`
	Deadline      uint                   `json:"deadline"`
}

type CreateDID struct {
	IssuerAddress string                 `json:"issuerAddress"`
	Type          blockchain.DIDType     `json:"type"`
	Metadata      map[string]interface{} `json:"metadata"`
	Hash          string                 `json:"hash"`
	Deadline      uint                   `json:"deadline"`
}

type DIDDocument struct {
	Context            []string               `json:"@context"`
	Id                 string                 `json:"id"`
	Controller         string                 `json:"controller"`
	VerificationMethod []VerificationMethod   `json:"verificationMethod"`
	Authentication     []string               `json:"authentication"` //=id
	AssertionMethod    []string               `json:"assertionMethod"`
	DocumentMetadata   map[string]interface{} `json:"didDocumentMetadata"`
}

// Hash calculates the Keccak256 hash of a DID document
func (doc *DIDDocument) Hash() (string, error) {
	// Marshal document to JSON
	docJSON, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("failed to marshal DID document: %w", err)
	}

	// Calculate Keccak256 hash
	hash := crypto.Keccak256Hash(docJSON)

	// Convert to hex string with 0x prefix
	return strings.ToLower(hash.Hex()), nil
}

type VerificationMethod struct {
	Id           string `json:"id"`
	Type         string `json:"type"`                   //
	Controller   string `json:"controller"`             //key
	PublicKeyHex string `json:"publicKeyHex,omitempty"` // Return real public key
}

type DID struct {
	DID         string                     `json:"did"`
	Secret      Secret                     `json:"secret"`
	Document    *DIDDocument               `json:"document"`
	Transaction *blockchain.SubmitTxResult `json:"transaction"`
}

type Secret struct {
	PrivateKeyHex string `json:"privateKeyHex"`
}
