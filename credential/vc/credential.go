package vc

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
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

	GetType() string
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
	proc       *processor.ProcessorOptions
	validate   bool
	didBaseURL string
}

// WithProcessorOptions sets processor options for credential processing.
func WithProcessorOptions(options ...processor.ProcessorOpt) CredentialOpt {
	return func(c *credentialOptions) {
		c.proc = &processor.ProcessorOptions{}
		for _, opt := range options {
			opt(c.proc)
		}
	}
}

// WithBaseURL sets the DID base URL for credential processing.
func WithBaseURL(baseURL string) CredentialOpt {
	return func(c *credentialOptions) {
		c.didBaseURL = baseURL
	}
}

func WithDisableValidation() CredentialOpt {
	return func(c *credentialOptions) {
		c.validate = false
	}
}

// WithEnableValidation enables schema validation during credential parsing.
func WithEnableValidation() CredentialOpt {
	return func(c *credentialOptions) {
		c.validate = true
	}
}

// WithCredentialSchemaLoader sets a custom schema loader for validation.
func WithCredentialSchemaLoader(id, schema string) CredentialOpt {
	return func(c *credentialOptions) {
		if c.proc == nil {
			c.proc = &processor.ProcessorOptions{}
		}
		c.proc.SchemaLoader = &processor.CredentialSchemaLoader{Schema: schema}
	}
}

// ParseCredential parses a credential from various formats into a Credential.
func ParseCredential(rawCredential interface{}, opts ...CredentialOpt) (Credential, error) {
	switch v := rawCredential.(type) {
	case []byte:
		return ParseCredentialEmbedded(v, opts...)
	case string:
		return ParseCredentialJWT(v, opts...)
	case map[string]interface{}:
		// Convert map to JSON bytes for embedded parsing
		vcBytes, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal credential data: %w", err)
		}
		return ParseCredentialEmbedded(vcBytes, opts...)
	default:
		return nil, fmt.Errorf("invalid credential type: %T", rawCredential)
	}
}
