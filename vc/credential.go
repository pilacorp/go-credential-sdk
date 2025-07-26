package vc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"log"
	"time"

	"github.com/xeipuuv/gojsonschema"

	"credential-sdk/vc/crypto"
)

// Credential represents a W3C Verifiable Credential as a JSON object.
type Credential map[string]interface{}

// CredentialOpt represents an option for configuring credential processing.
type CredentialOpt func(*credentialOptions)

// credentialOptions holds configuration for credential processing.
type credentialOptions struct {
	processor *ProcessorOptions
	validate  bool
}

// WithProcessorOptions sets the processor options for credential processing.
func WithProcessorOptions(options ...ProcessorOpt) CredentialOpt {
	return func(c *credentialOptions) {
		c.processor = &ProcessorOptions{}
		for _, opt := range options {
			opt(c.processor)
		}
	}
}

// WithDisableValidation disables schema validation during credential parsing.
func WithDisableValidation() CredentialOpt {
	return func(c *credentialOptions) {
		c.validate = false
	}
}

// ParseCredential parses a JSON string into a Credential.
func ParseCredential(jsonStr string, opts ...CredentialOpt) (*Credential, error) {
	if jsonStr == "" {
		return nil, fmt.Errorf("failed to parse credential: JSON string is empty")
	}
	var c Credential
	if err := json.Unmarshal([]byte(jsonStr), &c); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential: %w", err)
	}

	options := &credentialOptions{
		processor: &ProcessorOptions{},
		validate:  true,
	}
	for _, opt := range opts {
		opt(options)
	}

	if options.validate {
		if err := validateCredential(c, options.processor); err != nil {
			return nil, fmt.Errorf("failed to validate credential: %w", err)
		}
	}

	return &c, nil
}

// CreateCredentialWithContent creates a Credential from CredentialContents.
func CreateCredentialWithContent(vcc CredentialContents) (*Credential, error) {
	if vcc.Context == nil && vcc.ID == "" && vcc.Issuer == "" {
		return nil, fmt.Errorf("failed to create credential: contents must have context, ID, or issuer")
	}
	credential, err := serializeCredentialContents(&vcc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize credential contents: %w", err)
	}
	return &credential, nil
}

// ToJSON serializes the Credential to JSON.
func (c *Credential) ToJSON() ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("failed to serialize to JSON: credential is nil")
	}
	data, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential: %w", err)
	}
	var temp Credential
	if err := json.Unmarshal(data, &temp); err != nil {
		return nil, fmt.Errorf("failed to validate serialization: %w", err)
	}
	return data, nil
}

// AddECDSAProofs adds an ECDSA proof to the Credential.
func (c *Credential) AddECDSAProofs(priv *ecdsa.PrivateKey, verificationMethod string) error {
	if c == nil {
		return fmt.Errorf("failed to add ECDSA proof: credential is nil")
	}
	if priv == nil {
		return fmt.Errorf("failed to add ECDSA proof: private key is nil")
	}
	if verificationMethod == "" {
		return fmt.Errorf("failed to add ECDSA proof: verification method is required")
	}
	proofType := "DataIntegrityProof"
	proof := &Proof{
		Type:               proofType,
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: verificationMethod,
		ProofPurpose:       "assertionMethod",
	}
	vcCopy := make(Credential)
	for k, v := range *c {
		if k != "proof" {
			vcCopy[k] = v
		}
	}
	canonicalDoc, err := CanonicalizeDocument(vcCopy)
	if err != nil {
		return fmt.Errorf("failed to canonicalize document: %w", err)
	}
	digest, err := ComputeDigest(canonicalDoc)
	if err != nil {
		return fmt.Errorf("failed to compute digest: %w", err)
	}
	signer := crypto.NewECDSASecp256k1Signer(priv)
	signature, err := signer.Sign(digest)
	if err != nil {
		log.Printf("Failed to sign ECDSA proof: %v", err)
		return fmt.Errorf("failed to sign ECDSA proof: %w", err)
	}
	proof.ProofValue = hex.EncodeToString(signature)
	rawProof := serializeProofs([]Proof{*proof})
	(*c)["proof"] = rawProof
	return nil
}

// VerifyECDSACredential verifies an ECDSA-signed Credential.
func VerifyECDSACredential(vc *Credential, publicKey *ecdsa.PublicKey) error {
	if vc == nil {
		return fmt.Errorf("failed to verify ECDSA credential: credential is nil")
	}
	if publicKey == nil {
		return fmt.Errorf("failed to verify ECDSA credential: public key is nil")
	}
	proofs, ok := (*vc)["proof"].([]interface{})
	if !ok {
		if proof, exists := (*vc)["proof"]; exists {
			proofs = []interface{}{proof}
		} else {
			return fmt.Errorf("failed to verify ECDSA credential: credential has no proof")
		}
	}
	if len(proofs) == 0 {
		return fmt.Errorf("failed to verify ECDSA credential: no proofs found")
	}
	vcCopy := make(Credential)
	for k, v := range *vc {
		if k != "proof" {
			vcCopy[k] = v
		}
	}
	canonicalDoc, err := CanonicalizeDocument(vcCopy)
	if err != nil {
		return fmt.Errorf("failed to canonicalize document: %w", err)
	}
	digest, err := ComputeDigest(canonicalDoc)
	if err != nil {
		return fmt.Errorf("failed to compute digest: %w", err)
	}
	proof, err := parseRawToProof(proofs[0])
	if err != nil {
		return fmt.Errorf("failed to verify ECDSA credential: invalid proof format at index 0: %w", err)
	}
	proofBytes, err := hex.DecodeString(proof.ProofValue)
	if err != nil {
		return fmt.Errorf("failed to decode proofValue: %w", err)
	}
	verifier := crypto.NewSecp256k1()
	pubKeyBytes := elliptic.Marshal(btcec.S256(), publicKey.X, publicKey.Y)
	if err := verifier.Verify(proofBytes, digest, pubKeyBytes); err != nil {
		return fmt.Errorf("failed to verify ECDSA signature: %w", err)
	}
	return nil
}

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
	Proofs           []Proof       // Proofs attached to the credential
}

// Status represents the credentialStatus field as per W3C Verifiable Credentials and EBSI specifications.
type Status struct {
	ID                   string `json:"id,omitempty"`                   // Unique identifier for the status entry
	Type                 string `json:"type"`                           // Status type
	StatusPurpose        string `json:"statusPurpose,omitempty"`        // Purpose of the status
	StatusListIndex      string `json:"statusListIndex,omitempty"`      // Index in the status list
	StatusListCredential string `json:"statusListCredential,omitempty"` // Reference to the status list credential
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

// validateCredential validates the Credential against its schema.
func validateCredential(c Credential, processor *ProcessorOptions) error {
	if processor == nil {
		return fmt.Errorf("failed to validate credential: processor options are required")
	}
	schema, ok := c["credentialSchema"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("failed to validate credential: credentialSchema is required")
	}
	schemaID, ok := schema["id"].(string)
	if !ok {
		return fmt.Errorf("failed to validate credential: credentialSchema.id is required")
	}
	schemaLoader := gojsonschema.NewReferenceLoader(schemaID)
	credentialLoader := gojsonschema.NewGoLoader(c)
	result, err := gojsonschema.Validate(schemaLoader, credentialLoader)
	if err != nil {
		return fmt.Errorf("failed to validate schema: %w", err)
	}
	if !result.Valid() {
		return fmt.Errorf("failed to validate credential: %v", result.Errors())
	}
	return nil
}

// parseCredentialContents parses the Credential into structured contents.
func (c *Credential) ParseCredentialContents() (CredentialContents, error) {
	var contents CredentialContents
	if err := parseContext(c, &contents); err != nil {
		return contents, fmt.Errorf("failed to parse credential contents: %w", err)
	}
	if err := parseID(c, &contents); err != nil {
		return contents, fmt.Errorf("failed to parse credential contents: %w", err)
	}
	if err := parseTypes(c, &contents); err != nil {
		return contents, fmt.Errorf("failed to parse credential contents: %w", err)
	}
	if err := parseIssuer(c, &contents); err != nil {
		return contents, fmt.Errorf("failed to parse credential contents: %w", err)
	}
	if err := parseDates(c, &contents); err != nil {
		return contents, fmt.Errorf("failed to parse credential contents: %w", err)
	}
	if err := parseSubject(c, &contents); err != nil {
		return contents, fmt.Errorf("failed to parse credential contents: %w", err)
	}
	if err := parseSchema(c, &contents); err != nil {
		return contents, fmt.Errorf("failed to parse credential contents: %w", err)
	}
	if err := parseStatus(c, &contents); err != nil {
		return contents, fmt.Errorf("failed to parse credential contents: %w", err)
	}
	if err := parseProofs(c, &contents); err != nil {
		return contents, fmt.Errorf("failed to parse credential contents: %w", err)
	}

	return contents, nil
}
