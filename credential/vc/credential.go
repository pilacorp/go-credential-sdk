package vc

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
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
	AddCustomProof(proof *dto.Proof, opts ...CredentialOpt) error

	// Verify verifies the credential
	Verify(opts ...CredentialOpt) error

	// Serialize returns the credential in its native format
	// - For JWT credentials: returns the JWT string
	// - For embedded credentials: returns the JSON object with proof
	Serialize() (interface{}, error)

	GetContents() ([]byte, error)

	GetType() string

	executeOptions(opts ...CredentialOpt) error
}

// CredentialData represents credential data in JSON format (suitable for both JWT and JSON credentials).
type CredentialData jsonmap.JSONMap

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
	isValidateSchema      bool
	isVerifyProof         bool
	isCheckExpiration     bool
	isCheckRevocation     bool
	didBaseURL            string
	verificationMethodKey string
}

// WithBaseURL sets the DID base URL for credential processing.
func WithBaseURL(baseURL string) CredentialOpt {
	return func(c *credentialOptions) {
		c.didBaseURL = baseURL
	}
}

// WithVerificationMethodKey sets the verification method key (default: "key-1").
func WithVerificationMethodKey(key string) CredentialOpt {
	return func(c *credentialOptions) {
		c.verificationMethodKey = key
	}
}

// WithSchemaValidation enables schema validation during credential parsing.
func WithSchemaValidation() CredentialOpt {
	return func(c *credentialOptions) {
		c.isValidateSchema = true
	}
}

// WithVerifyProof enables proof verification during credential parsing.
func WithVerifyProof() CredentialOpt {
	return func(c *credentialOptions) {
		c.isVerifyProof = true
	}
}

// WithCheckExpiration enables expiration check during credential parsing.
func WithCheckExpiration() CredentialOpt {
	return func(c *credentialOptions) {
		c.isCheckExpiration = true
// WithCheckRevocation enables revocation check during credential parsing.
func WithCheckRevocation() CredentialOpt {
	return func(c *credentialOptions) {
		c.isCheckRevocation = true
	}
}

// getOptions returns the credential options.
func getOptions(opts ...CredentialOpt) *credentialOptions {
	options := &credentialOptions{
		isValidateSchema:      false,
		isVerifyProof:         false,
		isCheckExpiration:     false,
		isCheckRevocation:     false,
		didBaseURL:            config.BaseURL,
		verificationMethodKey: "key-1",
	}

	for _, opt := range opts {
		opt(options)
	}

	return options
}

// ParseCredential parses a credential from various formats into a Credential.
func ParseCredential(rawCredential []byte, opts ...CredentialOpt) (Credential, error) {
	if len(rawCredential) == 0 {

		return nil, fmt.Errorf("JSON string is empty")
	}

	if isJSONCredential(rawCredential) {

		return ParseJSONCredential(rawCredential, opts...)
	}

	valStr := string(rawCredential)
	if isJWTCredential(valStr) {

		return ParseJWTCredential(valStr, opts...)
	}

	return nil, fmt.Errorf("failed to parse credential: not a valid JWT or embedded credential")
}

// ParseCredentialWithValidation parses a credential from various formats into a Credential with validation.
func ParseCredentialWithValidation(rawCredential []byte) (Credential, error) {
	return ParseCredential(rawCredential, WithSchemaValidation(), WithVerifyProof())
}

func isJSONCredential(rawCredential []byte) bool {
	if len(rawCredential) == 0 {
		return false
	}

	if !json.Valid(rawCredential) {
		return false
	}

	var jsonMap map[string]interface{}
	err := json.Unmarshal(rawCredential, &jsonMap)
	if err != nil {
		return false
	}

	return true
}

func isJWTCredential(valStr string) bool {
	valStr = strings.Trim(valStr, "\"")
	regex := `^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$`
	match, _ := regexp.MatchString(regex, valStr)
	return match
}
