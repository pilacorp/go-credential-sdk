package vc

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/xeipuuv/gojsonschema"

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

// Credential represents a W3C Verifiable Credential as a JSON object.
type Credential jsonmap.JSONMap

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
	Proofs           []dto.Proof   // Proofs attached to the credential
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

// WithDisableValidation disables schema validation during credential parsing.
func WithDisableValidation() CredentialOpt {
	return func(c *credentialOptions) {
		c.validate = false
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

// ParseCredential parses a JSON string into a Credential.
func ParseCredential(rawJSON []byte, opts ...CredentialOpt) (*Credential, error) {
	if len(rawJSON) == 0 {
		return nil, fmt.Errorf("JSON string is empty")
	}

	var m jsonmap.JSONMap
	if err := json.Unmarshal(rawJSON, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential: %w", err)
	}

	options := &credentialOptions{
		proc:       &processor.ProcessorOptions{},
		validate:   true,
		didBaseURL: config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	if options.validate {
		if err := validateCredential(m, options.proc); err != nil {
			return nil, fmt.Errorf("failed to validate credential: %w", err)
		}
	}

	c := Credential(m)
	return &c, nil
}

// CreateCredentialWithContent creates a Credential from CredentialContents.
func CreateCredentialWithContent(vcc CredentialContents) (*Credential, error) {
	if len(vcc.Context) == 0 && vcc.ID == "" && vcc.Issuer == "" {
		return nil, fmt.Errorf("contents must have context, ID, or issuer")
	}

	m, err := serializeCredentialContents(&vcc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize credential contents: %w", err)
	}
	c := Credential(m)
	return &c, nil
}

// ToJSON serializes the Credential to JSON.
func (c *Credential) ToJSON() ([]byte, error) {
	return (*jsonmap.JSONMap)(c).ToJSON()
}

// AddECDSAProof adds an ECDSA proof to the Credential.
func (c *Credential) AddECDSAProof(priv, verificationMethod string, opts ...CredentialOpt) error {
	options := &credentialOptions{
		proc:       &processor.ProcessorOptions{},
		validate:   true,
		didBaseURL: config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	return (*jsonmap.JSONMap)(c).AddECDSAProof(priv, verificationMethod, "assertionMethod", options.didBaseURL)
}

// AddCustomProof adds a custom proof to the Presentation.
func (c *Credential) AddCustomProof(priv, proof *dto.Proof) error {

	return (*jsonmap.JSONMap)(c).AddCustomProof(proof)
}

// CanonicalizeCredential canonicalizes the Credential for signing or verification.
func (c *Credential) CanonicalizeCredential() ([]byte, error) {
	return (*jsonmap.JSONMap)(c).Canonicalize()
}

// VerifyECDSACredential verifies an ECDSA-signed Credential.
func VerifyECDSACredential(c *Credential, opts ...CredentialOpt) (bool, error) {
	options := &credentialOptions{
		proc:       &processor.ProcessorOptions{},
		validate:   true,
		didBaseURL: config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	return (*jsonmap.JSONMap)(c).VerifyProof(options.didBaseURL)
}

// ParseCredentialContents parses the Credential into structured contents.
func (c *Credential) ParseCredentialContents() (CredentialContents, error) {
	var contents CredentialContents
	parsers := []func(*Credential, *CredentialContents) error{
		parseContext,
		parseID,
		parseTypes,
		parseIssuer,
		parseDates,
		parseSubject,
		parseSchema,
		parseStatus,
		parseProofs,
	}

	for _, parser := range parsers {
		if err := parser(c, &contents); err != nil {
			return contents, fmt.Errorf("failed to parse credential contents: %w", err)
		}
	}
	return contents, nil
}

// validateCredential validates the Credential against its schema.
func validateCredential(m jsonmap.JSONMap, processor *processor.ProcessorOptions) error {
	if processor == nil {
		return fmt.Errorf("processor options are required")
	}

	requiredKeys := []string{"type", "credentialSchema", "credentialSubject", "credentialStatus", "proof"}
	for _, key := range requiredKeys {
		if _, exists := m[key]; !exists {
			return fmt.Errorf("%s is required", key)
		}
		m[key] = convertToArray(m[key])
	}

	for _, schema := range m["credentialSchema"].([]interface{}) {
		schemaMap, ok := schema.(map[string]interface{})
		if !ok || schemaMap["id"] == nil {
			return fmt.Errorf("credentialSchema.id is required")
		}

		schemaID, ok := schemaMap["id"].(string)
		if !ok || schemaID == "" {
			return fmt.Errorf("credentialSchema.id must be a non-empty string")
		}

		schemaLoader := gojsonschema.NewReferenceLoader(schemaID)
		credentialLoader := gojsonschema.NewGoLoader(m)

		result, err := gojsonschema.Validate(schemaLoader, credentialLoader)
		if err != nil {
			return fmt.Errorf("failed to validate schema: %w", err)
		}
		if !result.Valid() {
			return fmt.Errorf("credential validation failed: %v", result.Errors())
		}
	}
	return nil
}

// convertToArray ensures a value is represented as an array.
func convertToArray(value interface{}) []interface{} {
	if value == nil {
		return nil
	}
	if arr, ok := value.([]interface{}); ok {
		return arr
	}
	return []interface{}{value}
}
