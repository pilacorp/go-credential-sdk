package vc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/xeipuuv/gojsonschema"
)

// Credential represents a W3C Verifiable Credential.
type Credential map[string]interface{}

// CredentialOpt represents an option for credential processing.
type CredentialOpt func(*credentialOptions)

type credentialOptions struct {
	processor *ProcessorOptions
	validate  bool
}

// WithProcessorOptions sets the processor options.
func WithProcessorOptions(options ...ProcessorOpt) CredentialOpt {
	return func(c *credentialOptions) {
		c.processor = &ProcessorOptions{}
		for _, opt := range options {
			opt(c.processor)
		}
	}
}

// WithDisableValidation disables schema validation.
func WithDisableValidation() CredentialOpt {
	return func(c *credentialOptions) {
		c.validate = false
	}
}

// ParseCredential parses a JSON string into a Credential.
func ParseCredential(jsonStr string, opts ...CredentialOpt) (*Credential, error) {
	var c Credential
	err := json.Unmarshal([]byte(jsonStr), &c)
	if err != nil {
		return nil, fmt.Errorf("unmarshal credential: %w", err)
	}

	// Validate proofValue after deserialization
	if proof, ok := c["proof"]; ok {
		var proofs []interface{}
		switch v := proof.(type) {
		case []interface{}:
			proofs = v
		case map[string]interface{}:
			proofs = []interface{}{v}
		default:
			return nil, fmt.Errorf("invalid proof format: %T", proof)
		}
		for i, p := range proofs {
			if pr, ok := p.(map[string]interface{}); ok {
				if pv, ok := pr["proofValue"].(string); ok && pv != "" {
					fmt.Printf("Parsed proofValue at index %d: %s\n", i, pv)
					encodedProof := pv
					if len(pv) > 0 && pv[0] == 'u' {
						encodedProof = pv[1:]
					}
					if len(encodedProof) < 80 {
						return nil, fmt.Errorf("proofValue at index %d too short: %d characters, expected ~86", i, len(encodedProof))
					}
					decoded, err := base64.RawURLEncoding.DecodeString(encodedProof)
					if err != nil {
						return nil, fmt.Errorf("decode proofValue at index %d: %w", i, err)
					}
					if len(decoded) != 64 {
						return nil, fmt.Errorf("decoded proofValue length at index %d: expected 64 bytes, got %d", i, len(decoded))
					}
				}
			}
		}
	}

	options := &credentialOptions{
		processor: &ProcessorOptions{},
		validate:  true,
	}
	for _, opt := range opts {
		opt(options)
	}

	if options.validate {
		err = validateCredential(c, options.processor)
		if err != nil {
			return nil, fmt.Errorf("validate credential: %w", err)
		}
	}

	return &c, nil
}

// NewCredential creates a new Credential with required fields.
func NewCredential(id, issuer, subjectID string, subjectData map[string]interface{}) (*Credential, error) {
	c := Credential{
		"@context":     []string{"https://www.w3.org/ns/credentials/v2"},
		"id":           id,
		"issuer":       issuer,
		"issuanceDate": time.Now().UTC().Format(time.RFC3339),
		"credentialSubject": map[string]interface{}{
			"id": subjectID,
		},
	}

	for k, v := range subjectData {
		c["credentialSubject"].(map[string]interface{})[k] = v
	}

	return &c, nil
}

// CreateCredentialWithProofs creates vc from CredentialContents, with provided proofs.
func CreateCredentialWithContent(vcc CredentialContents) (*Credential, error) {
	credential, err := serializeCredentialContents(&vcc)
	if err != nil {
		return nil, fmt.Errorf("converting credential contents: %w", err)
	}

	//jsonutil.AddCustomFields(vcJSON, customFields)

	return &credential, nil
}

// Contents returns the structured contents of the Credential.
func (c *Credential) Contents() (CredentialContents, error) {
	var contents CredentialContents
	parsed, err := parseCredentialContents(*c)
	if err != nil {
		return contents, fmt.Errorf("parse credential contents: %w", err)
	}
	return parsed, nil
}

// ToJSON serializes the Credential to JSON.
func (c *Credential) ToJSON() ([]byte, error) {
	if proof, ok := (*c)["proof"]; ok {
		fmt.Printf("Proof before serialization: %v\n", proof)
	}
	data, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshal credential: %w", err)
	}
	// Validate proofValue after serialization
	var temp Credential
	if err := json.Unmarshal(data, &temp); err != nil {
		return nil, fmt.Errorf("validate serialization: %w", err)
	}
	if proof, ok := temp["proof"]; ok {
		fmt.Printf("Proof after serialization: %v\n", proof)
		var proofs []interface{}
		switch v := proof.(type) {
		case []interface{}:
			proofs = v
		case map[string]interface{}:
			proofs = []interface{}{v}
		default:
			return nil, fmt.Errorf("invalid proof format after serialization: %T", proof)
		}
		for i, p := range proofs {
			if pr, ok := p.(map[string]interface{}); ok {
				if pv, ok := pr["proofValue"].(string); ok && pv != "" {
					encodedProof := pv
					if len(pv) > 0 && pv[0] == 'u' {
						encodedProof = pv[1:]
					}
					if len(encodedProof) < 80 {
						return nil, fmt.Errorf("serialized proofValue at index %d too short: %d characters, expected ~86", i, len(encodedProof))
					}
					decoded, err := base64.RawURLEncoding.DecodeString(encodedProof)
					if err != nil {
						return nil, fmt.Errorf("decode serialized proofValue at index %d: %w", i, err)
					}
					if len(decoded) != 64 {
						return nil, fmt.Errorf("decoded serialized proofValue length at index %d: expected 64 bytes, got %d", i, len(decoded))
					}
				}
			}
		}
	}
	return data, nil
}

// ToJWT serializes the Credential to a JWT string.
func (c *Credential) ToJWT(creator *ProofCreator, keyType KeyType) (string, error) {
	// Create a copy of the credential without the proof
	vcCopy := make(Credential)
	for k, v := range *c {
		if k != "proof" {
			vcCopy[k] = v
		}
	}

	// Serialize the credential to JSON for the JWT payload
	payload, err := json.Marshal(vcCopy)
	if err != nil {
		return "", fmt.Errorf("marshal credential for JWT: %w", err)
	}

	// Create W3C-compliant JWT header
	header := map[string]interface{}{
		"kid": "ExHkBMW9fmbkvV266mRpuP2sUY_N_EWIN1lapUzO8ro",
		"alg": "ES256",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal JWT header: %w", err)
	}

	// Encode header and payload in Base64 URL-safe format
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	dataToSign := []byte(headerB64 + "." + payloadB64)

	// Create a temporary proof to pass to the signer
	proof := &Proof{
		Type: "DataIntegrityProof",
	}

	// Sign the header.payload
	signature, err := creator.Sign(proof, keyType, dataToSign, true)
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}

	// Construct JWT string
	return headerB64 + "." + payloadB64 + "." + string(signature), nil
}

// AddProof adds a proof to the Credential.
func (c *Credential) AddProof(creator *ProofCreator, proofType, verificationMethod string, keyType KeyType, useJWS bool, opts ...ProcessorOpt) error {
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

	canonicalDoc, err := CanonicalizeDocument(vcCopy, opts...)
	if err != nil {
		return fmt.Errorf("canonicalize document: %w", err)
	}

	digest, err := ComputeDigest(canonicalDoc)
	if err != nil {
		return fmt.Errorf("compute digest: %w", err)
	}

	signature, err := creator.Sign(proof, keyType, digest, false)
	if err != nil {
		return fmt.Errorf("sign proof: %w", err)
	}

	if useJWS {
		parts := strings.Split(string(signature), "~")
		if len(parts) < 1 {
			return fmt.Errorf("invalid JWS format")
		}
		proof.JWS = parts[0]
		if len(parts) > 1 {
			proof.Disclosures = parts[1:]
		}
	} else {
		// Ensure signature is exactly 64 bytes for proofValue
		if len(signature) != 64 {
			return fmt.Errorf("invalid signature length for proofValue: expected 64 bytes, got %d", len(signature))
		}
		// Encode signature as multibase (base64url) for proofValue
		encoded := base64.RawURLEncoding.EncodeToString(signature)
		fmt.Printf("Generated proofValue: u%s\n", encoded)
		// Validate that encoded signature decodes back to 64 bytes
		decoded, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return fmt.Errorf("failed to decode proofValue: %w", err)
		}
		if len(decoded) != 64 {
			return fmt.Errorf("decoded proofValue length invalid: expected 64 bytes, got %d", len(decoded))
		}
		// Validate encoded length (~86 characters)
		if len(encoded) < 80 {
			return fmt.Errorf("encoded proofValue too short: %d characters, expected ~86", len(encoded))
		}
		proof.ProofValue = "u" + encoded
	}

	var proofs []interface{}
	if p, ok := (*c)["proof"]; ok {
		switch v := p.(type) {
		case []interface{}:
			proofs = v
		case interface{}:
			proofs = []interface{}{v}
		default:
			return fmt.Errorf("invalid proof format: %T", p)
		}
	}

	proofs = append(proofs, proof)
	(*c)["proof"] = proofs
	return nil
}

// CredentialContents represents the structured contents of a Credential.
type CredentialContents struct {
	Context    []string
	ID         string
	Types      []string
	Issuer     string
	ValidFrom  time.Time
	ValidUntil time.Time
	Subject    []Subject
	Schemas    []TypedID
	Proofs     []Proof
}

// Subject represents the credentialSubject field.
type Subject struct {
	ID           string
	CustomFields map[string]interface{}
}

// validateCredential validates the Credential against its schema.
func validateCredential(c Credential, processor *ProcessorOptions) error {
	if processor == nil {
		return fmt.Errorf("processor options are required")
	}

	schema, ok := c["credentialSchema"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("credentialSchema is required")
	}

	schemaID, ok := schema["id"].(string)
	if !ok {
		return fmt.Errorf("credentialSchema.id is required")
	}

	schemaLoader := gojsonschema.NewReferenceLoader(schemaID)
	credentialLoader := gojsonschema.NewGoLoader(c)
	result, err := gojsonschema.Validate(schemaLoader, credentialLoader)
	if err != nil {
		return fmt.Errorf("schema validation: %w", err)
	}

	if !result.Valid() {
		return fmt.Errorf("credential is invalid: %v", result.Errors())
	}

	return nil
}

// parseCredentialContents parses the Credential into structured contents.
func parseCredentialContents(c Credential) (CredentialContents, error) {
	var contents CredentialContents

	// Parse @context
	if context, ok := c["@context"].([]interface{}); ok {
		for _, ctx := range context {
			if ctxStr, ok := ctx.(string); ok {
				contents.Context = append(contents.Context, ctxStr)
			}
		}
	}

	// Parse ID
	if id, ok := c["id"].(string); ok {
		contents.ID = id
	}

	// Parse types
	if types, ok := c["type"].([]interface{}); ok {
		for _, t := range types {
			if typeStr, ok := t.(string); ok {
				contents.Types = append(contents.Types, typeStr)
			}
		}
	}

	// Parse issuer
	contents.Issuer, _ = c["issuer"].(string)

	// Parse validFrom and validUntil
	if validFrom, ok := c["validFrom"].(string); ok {
		t, err := time.Parse(time.RFC3339, validFrom)
		if err == nil {
			contents.ValidFrom = t
		}
	}
	if validUntil, ok := c["validUntil"].(string); ok {
		t, err := time.Parse(time.RFC3339, validUntil)
		if err == nil {
			contents.ValidUntil = t
		}
	}

	// Parse credentialSubject
	if subject, ok := c["credentialSubject"].(map[string]interface{}); ok {
		s := Subject{
			CustomFields: make(map[string]interface{}),
		}
		if id, ok := subject["id"].(string); ok {
			s.ID = id
		}
		for k, v := range subject {
			if k != "id" {
				s.CustomFields[k] = v
			}
		}
		contents.Subject = append(contents.Subject, s)
	}

	// Parse credentialSchema
	if schema, ok := c["credentialSchema"].(map[string]interface{}); ok {
		schemaID, _ := parseTypedID(schema)
		contents.Schemas = append(contents.Schemas, schemaID)
	}

	// Parse relatedResource
	if resources, ok := c["relatedResource"].([]interface{}); ok {
		for _, r := range resources {
			if resource, ok := r.(map[string]interface{}); ok {
				tr := TypedResource{}
				if id, ok := resource["id"].(string); ok {
					tr.ID = id
				}
				if t, ok := resource["type"].(string); ok {
					tr.Type = t
				}
				if mt, ok := resource["mediaType"].(string); ok {
					tr.MediaType = mt
				}
				if sri, ok := resource["digestSRI"].(string); ok {
					tr.DigestSRI = sri
				}
				if mb, ok := resource["digestMultibase"].(string); ok {
					tr.DigestMultibase = mb
				}
			}
		}
	}

	// Parse proof
	proofs, err := parseLDProof(c["proof"])
	if err != nil {
		return contents, fmt.Errorf("parse proof: %w", err)
	}
	contents.Proofs = proofs

	return contents, nil
}

// parseTypedID parses a TypedID from a value.
func parseTypedID(value interface{}) (TypedID, error) {
	var tid TypedID
	switch v := value.(type) {
	case string:
		tid.ID = v
	case map[string]interface{}:
		if id, ok := v["id"].(string); ok {
			tid.ID = id
		}
		if t, ok := v["type"].(string); ok {
			tid.Type = t
		}
	default:
		return tid, fmt.Errorf("invalid typed ID format: %T", value)
	}
	return tid, nil
}

func serializeCredentialContents(vcc *CredentialContents) (Credential, error) {
	vcJSON := map[string]interface{}{}

	// Serialize @context
	if len(vcc.Context) > 0 {
		vcJSON["@context"] = vcc.Context
	}

	// Serialize ID
	if vcc.ID != "" {
		vcJSON["id"] = vcc.ID
	}

	// Serialize types
	if len(vcc.Types) > 0 {
		vcJSON["type"] = vcc.Types
	}

	// Serialize issuer
	if vcc.Issuer != "" {
		vcJSON["issuer"] = vcc.Issuer
	}

	// Serialize validFrom and validUntil
	if !vcc.ValidFrom.IsZero() {
		vcJSON["validFrom"] = vcc.ValidFrom.Format(time.RFC3339)
	}
	if !vcc.ValidUntil.IsZero() {
		vcJSON["validUntil"] = vcc.ValidUntil.Format(time.RFC3339)
	}

	// Serialize credentialSubject
	if len(vcc.Subject) > 0 {
		subjects := make([]map[string]interface{}, len(vcc.Subject))
		for i, subject := range vcc.Subject {
			subjectJSON := make(map[string]interface{})
			if subject.ID != "" {
				subjectJSON["id"] = subject.ID
			}
			for k, v := range subject.CustomFields {
				subjectJSON[k] = v
			}
			subjects[i] = subjectJSON
		}
		if len(subjects) == 1 {
			vcJSON["credentialSubject"] = subjects[0]
		} else {
			vcJSON["credentialSubject"] = subjects
		}
	}

	// Serialize schemas
	if len(vcc.Schemas) > 0 {
		schemas := make([]map[string]interface{}, len(vcc.Schemas))
		for i, schema := range vcc.Schemas {
			schemaJSON := make(map[string]interface{})
			if schema.ID != "" {
				schemaJSON["id"] = schema.ID
			}
			if schema.Type != "" {
				schemaJSON["type"] = schema.Type
			}
			schemas[i] = schemaJSON
		}
		vcJSON["credentialSchema"] = schemas
	}

	return vcJSON, nil
}
