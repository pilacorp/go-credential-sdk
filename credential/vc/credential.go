package vc

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/sdjwt"
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

	// AddSelectiveDisclosures adds selective disclosures to the credential.
	// For JWT credentials: adds SD-JWT disclosures to the credential.
	// For JSON credentials: returns an error (unsupported).
	AddSelectiveDisclosures(selectivePaths []string) (Credential, error)

	// ExtractField extracts a field value from the credential by dot-notation path.
	// Returns nil if the field does not exist.
	// Example paths: "name", "credentialSubject.name", "credentialSubject.address.city"
	ExtractField(path string) interface{}

	executeOptions(opts ...CredentialOpt) error
}

// CredentialData represents credential data in JSON format (suitable for both JWT and JSON credentials).
type CredentialData jsonmap.JSONMap

// CredentialContents represents the structured contents of a Credential.
type CredentialContents struct {
	Context          []interface{} `json:"context,omitempty"`          // JSON-LD contexts
	ID               string        `json:"id,omitempty"`               // Credential identifier
	Types            []string      `json:"type,omitempty"`             // Credential types
	Issuer           string        `json:"issuer,omitempty"`           // Issuer identifier
	ValidFrom        time.Time     `json:"validFrom,omitempty"`        // Issuance date
	ValidUntil       time.Time     `json:"validUntil,omitempty"`       // Expiration date
	CredentialStatus []Status      `json:"credentialStatus,omitempty"` // Credential status entries
	Subject          []Subject     `json:"subject,omitempty"`          // Credential subjects
	Schemas          []Schema      `json:"schemas,omitempty"`          // Credential schemas
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
	ID           string                 `json:"id,omitempty"`           // Subject identifier
	CustomFields map[string]interface{} `json:"customFields,omitempty"` // Additional subject data
}

// Schema represents a credential schema with an ID and type.
type Schema struct {
	ID   string `json:"id,omitempty"`   // Schema identifier
	Type string `json:"type,omitempty"` // Schema type
}

// Decoy specifies where and how many decoy digests to add for SD-JWT privacy.
type Decoy = sdjwt.DecoyConfig

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
	sdDisclosures         []string
	sdSelectivePaths      []string
	sdAlg                 string
	sdShuffle             bool
	sdDecoys              []sdjwt.DecoyConfig
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
	}
}

// WithCheckRevocation enables revocation check during credential parsing.
func WithCheckRevocation() CredentialOpt {
	return func(c *credentialOptions) {
		c.isCheckRevocation = true
	}
}

// WithSDDisclosures sets pre-built SD-JWT disclosures to be used when issuing credentials.
// If provided, JWTCredential.Serialize will output an SD-JWT instead of a plain JWT.
func WithSDDisclosures(disclosures []string) CredentialOpt {
	return func(c *credentialOptions) {
		c.sdDisclosures = disclosures
	}
}

// WithSDSelectivePaths declares which claims should be selectively disclosable.
// When provided, the SDK will use sdjwt.BuildDisclosures to construct SD-JWT structures
// during credential issuance.
func WithSDSelectivePaths(paths []string) CredentialOpt {
	return func(c *credentialOptions) {
		c.sdSelectivePaths = paths
	}
}

// WithSDHashAlgorithm sets the hash algorithm for SD-JWT.
// Supported: sha-256, sha-384, sha-512. Empty string defaults to sha-256.
func WithSDHashAlgorithm(alg string) CredentialOpt {
	return func(c *credentialOptions) {
		c.sdAlg = alg
	}
}

// WithSDShuffle enables shuffling of the _sd array to prevent disclosure order leakage.
func WithSDShuffle(enabled bool) CredentialOpt {
	return func(c *credentialOptions) {
		c.sdShuffle = enabled
	}
}

// WithSDDecoyDigests adds decoy digests at specified parent paths to obscure the number of disclosed claims.
// Each Decoy specifies the path where decoy digests should be added and the count of decoys.
// Example: WithSDDecoyDigests([]vc.Decoy{{Path: "", Count: 2}, {Path: "credentialSubject", Count: 3}})
func WithSDDecoyDigests(decoys []Decoy) CredentialOpt {
	return func(c *credentialOptions) {
		c.sdDecoys = decoys
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
	if sdjwt.IsSDJWT(valStr) || isJWTCredential(valStr) {

		return ParseJWTCredential(valStr, opts...)
	}

	return nil, fmt.Errorf("failed to parse credential: not a valid JSON, SD-JWT, or JWT credential")
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
