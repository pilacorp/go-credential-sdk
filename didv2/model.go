package didv2

import "github.com/pilacorp/go-credential-sdk/didv2/blockchain"

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
	IssuerPkHex   string                 `json:"issuerPrivateKeyHex"`
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
