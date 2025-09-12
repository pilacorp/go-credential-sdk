package vc

import (
	"fmt"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
)

// Config holds package configuration.
var config = struct {
	BaseURL string
}{
	BaseURL: "https://api.ndadid.vn/api/v1/did",
}

// Init initializes the package with a base URL.
func Init(baseURL string) {
	if baseURL != "" {
		config.BaseURL = baseURL
	}
}

type Credential interface {
	AddProof(priv string, opts ...CredentialOpt) error

	GetSigningInput() ([]byte, error)
	AddCustomProof(proof *dto.Proof) error

	// Verify verifies the credential
	Verify(opts ...CredentialOpt) error

	// Serialize returns the credential in its native format
	// - For JWT credentials: returns the JWT string
	// - For embedded credentials: returns the JSON object with proof
	Serialize() (interface{}, error)

	ToJSON() ([]byte, error)
}

// Credential represents a W3C Credential as a JSON object.
type JSONCredential jsonmap.JSONMap

// CredentialContents represents the structured contents of a Credential.
type CredentialContents struct {
	Context          []interface{} // JSON-LD contexts
	ID               string        // Credential identifier
	Types            []string      // Credential types
	Issuer           string        // Issuer identifier
	ValidFrom        time.Time     // Issuance date
	ValidUntil       time.Time     // Expiration date
	CredentialStatus []Status      // Credential status entries
	Subject          []Subject     // Credential subjects
	Schemas          []Schema      // Credential schemas
}

// Status represents the credentialStatus field as per W3C Verifiable Credentials.
type Status struct {
	ID                   string `json:"id,omitempty"`
	Type                 string `json:"type"`
	StatusPurpose        string `json:"statusPurpose,omitempty"`
	StatusListIndex      string `json:"statusListIndex,omitempty"`
	StatusListCredential string `json:"statusListCredential,omitempty"`
}

// Subject represents the credentialSubject field.
type Subject struct {
	ID           string                 // Subject identifier
	CustomFields map[string]interface{} // Additional subject data
}

// Schema represents a credential schema with an ID and type.
type Schema struct {
	ID   string // Schema identifier
	Type string // Schema type
}

// CredentialOpt configures credential processing options.
type CredentialOpt func(*credentialOptions)

// credentialOptions holds configuration for credential processing.
type credentialOptions struct {
	validate   bool
	didBaseURL string
}

// WithBaseURL sets the DID base URL for credential processing.
func WithBaseURL(baseURL string) CredentialOpt {
	return func(c *credentialOptions) {
		c.didBaseURL = baseURL
	}
}

// WithEnableValidation enables schema validation during credential parsing.
func WithEnableValidation() CredentialOpt {
	return func(c *credentialOptions) {
		c.validate = true
	}
}

// ParseCredential parses a credential from various formats into a Credential.
func ParseCredential(rawCredential []byte, opts ...CredentialOpt) (Credential, error) {
	if len(rawCredential) == 0 {
		return nil, fmt.Errorf("JSON string is empty")
	}

	// try to parse as JWT
	rawCredentialStr := string(rawCredential)
	credential, err := ParseCredentialJWT(rawCredentialStr, opts...)
	if err == nil {
		return credential, nil
	}

	// try to parse as embedded
	credential, err = ParseCredentialEmbedded(rawCredential, opts...)
	if err == nil {
		return credential, nil
	}

	return nil, fmt.Errorf("failed to parse credential: not a valid JWT or embedded credential")
}
