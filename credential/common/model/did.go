package model

type DIDDocument struct {
	Context             []string                  `json:"@context"`
	ID                  string                    `json:"id"`
	VerificationMethod  []VerificationMethodEntry `json:"verificationMethod"`
	Authentication      []string                  `json:"authentication"`
	AssertionMethod     []string                  `json:"assertionMethod"`
	Controller          interface{}               `json:"controller"` // Can be string or []string
	DIDDocumentMetadata map[string]interface{}    `json:"didDocumentMetadata"`
}

// VerificationMethodEntry represents a single verification method in a DID Document.
type VerificationMethodEntry struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Controller   string `json:"controller"`
	PublicKeyHex string `json:"publicKeyHex,omitempty"`
	PublicKeyJwk *JWK   `json:"publicKeyJwk,omitempty"`
}

// JWK represents a JSON Web Key structure
type JWK struct {
	Kty string `json:"kty"` // Key type
	Crv string `json:"crv"` // Curve
	X   string `json:"x"`   // X coordinate
	Y   string `json:"y"`   // Y coordinate
}
