package vc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/xeipuuv/gojsonschema"

	"github.com/pilacorp/go-credential-sdk/vc/crypto"
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

// Status represents the credentialStatus field as per W3C Verifiable Credentials and EBSI specifications.
type Status struct {
	ID                   string `json:"id,omitempty"`                   // Unique identifier for the status entry (e.g., revocation list URL)
	Type                 string `json:"type"`                           // Status type (e.g., StatusList2021Entry, RevocationList2021)
	StatusPurpose        string `json:"statusPurpose,omitempty"`        // Purpose of the status (e.g., "revocation", "suspension")
	StatusListIndex      string `json:"statusListIndex,omitempty"`      // Index in the status list (e.g., bit position in StatusList2021)
	StatusListCredential string `json:"statusListCredential,omitempty"` // Reference to the status list credential
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

// NewCredential creates a new Credential with required fields.
func NewCredential(id, issuer, subjectID string, subjectData map[string]interface{}) (*Credential, error) {
	if id == "" || issuer == "" {
		return nil, fmt.Errorf("failed to create credential: id and issuer are required")
	}
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
		if k == "id" {
			continue // Skip overwriting the subject ID
		}
		c["credentialSubject"].(map[string]interface{})[k] = v
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

// Contents returns the structured contents of the Credential.
func (c *Credential) Contents() (CredentialContents, error) {
	if c == nil {
		return CredentialContents{}, fmt.Errorf("failed to get contents: credential is nil")
	}
	contents, err := parseCredentialContents(*c)
	if err != nil {
		return contents, fmt.Errorf("failed to parse credential contents: %w", err)
	}
	return contents, nil
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

// ToJWT serializes the Credential to a JWT string.
func (c *Credential) ToJWT(creator *ProofCreator, keyType KeyType) (string, error) {
	if c == nil {
		return "", fmt.Errorf("failed to serialize to JWT: credential is nil")
	}
	if creator == nil {
		return "", fmt.Errorf("failed to serialize to JWT: proof creator is nil")
	}
	vcCopy := make(Credential)
	for k, v := range *c {
		if k != "proof" {
			vcCopy[k] = v
		}
	}
	payload, err := json.Marshal(vcCopy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal credential for JWT: %w", err)
	}
	header := map[string]interface{}{
		"kid": "ExHkBMW9fmbkvV266mRpuP2sUY_N_EWIN1lapUzO8ro",
		"alg": string(keyTypeToAlgorithm(keyType)),
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWT header: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	dataToSign := []byte(headerB64 + "." + payloadB64)
	proof := &Proof{Type: "DataIntegrityProof"}
	signature, err := creator.Sign(proof, keyType, dataToSign, true)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}
	log.Printf("Generated JWT signature: %s", signature)
	return headerB64 + "." + payloadB64 + "." + string(signature), nil
}

// AddProof adds a proof to the Credential using the specified proof type and key type.
func (c *Credential) AddProof(creator *ProofCreator, proofType, verificationMethod string, keyType KeyType, useJWS bool, opts ...ProcessorOpt) error {
	if c == nil {
		return fmt.Errorf("failed to add proof: credential is nil")
	}
	if creator == nil {
		return fmt.Errorf("failed to add proof: proof creator is nil")
	}
	if proofType == "" || verificationMethod == "" {
		return fmt.Errorf("failed to add proof: proof type and verification method are required")
	}
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
	signature, err := creator.Sign(proof, keyType, digest, false)
	if err != nil {
		return fmt.Errorf("failed to sign proof: %w", err)
	}
	if useJWS {
		parts := strings.Split(string(signature), "~")
		if len(parts) < 1 {
			return fmt.Errorf("failed to add proof: invalid JWS format")
		}
		proof.JWS = parts[0]
		if len(parts) > 1 {
			proof.Disclosures = parts[1:]
		}
	} else {
		if len(signature) != 64 {
			return fmt.Errorf("failed to add proof: invalid signature length for proofValue: expected 64 bytes, got %d", len(signature))
		}
		encoded := base64.RawURLEncoding.EncodeToString(signature)
		log.Printf("Generated proofValue: u%s", encoded)
		decoded, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return fmt.Errorf("failed to decode proofValue: %w", err)
		}
		if len(decoded) != 64 {
			return fmt.Errorf("failed to add proof: decoded proofValue length invalid: expected 64 bytes, got %d", len(decoded))
		}
		if len(encoded) < 80 {
			return fmt.Errorf("failed to add proof: encoded proofValue too short: %d characters, expected ~86", len(encoded))
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
			return fmt.Errorf("failed to add proof: invalid proof format %T", p)
		}
	}
	proofs = append(proofs, proof)
	(*c)["proof"] = proofs
	return nil
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
	rawProof := proofsToRaw([]Proof{*proof})
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
		return fmt.Errorf("failed to verify ECDSA credential: invalid proof format at index 0", err)
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
	Schemas          []TypedID     // Credential schemas
	Proofs           []Proof       // Proofs attached to the credential
}

// Subject represents the credentialSubject field.
type Subject struct {
	ID           string                 // Subject identifier
	CustomFields map[string]interface{} // Additional subject data
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
func parseCredentialContents(c Credential) (CredentialContents, error) {
	var contents CredentialContents
	if err := parseContext(&c, &contents); err != nil {
		return contents, fmt.Errorf("failed to parse credential contents: %w", err)
	}
	if err := parseID(&c, &contents); err != nil {
		return contents, fmt.Errorf("failed to parse credential contents: %w", err)
	}
	if err := parseTypes(&c, &contents); err != nil {
		return contents, fmt.Errorf("failed to parse credential contents: %w", err)
	}
	if err := parseIssuer(&c, &contents); err != nil {
		return contents, fmt.Errorf("failed to parse credential contents: %w", err)
	}
	if err := parseDates(&c, &contents); err != nil {
		return contents, fmt.Errorf("failed to parse credential contents: %w", err)
	}
	if err := parseSubject(&c, &contents); err != nil {
		return contents, fmt.Errorf("failed to parse credential contents: %w", err)
	}
	if err := parseSchema(&c, &contents); err != nil {
		return contents, fmt.Errorf("failed to parse credential contents: %w", err)
	}
	if err := parseStatus(&c, &contents); err != nil {
		return contents, fmt.Errorf("failed to parse credential contents: %w", err)
	}
	proofs, err := parseLDProof(c["proof"])
	if err != nil {
		return contents, fmt.Errorf("failed to parse credential contents: %w", err)
	}
	contents.Proofs = proofs
	return contents, nil
}

// serializeCredentialContents serializes CredentialContents into a Credential.
func serializeCredentialContents(vcc *CredentialContents) (Credential, error) {
	if vcc == nil {
		return nil, fmt.Errorf("failed to serialize credential contents: contents is nil")
	}
	vcJSON := make(Credential)
	if len(vcc.Context) > 0 {
		validatedContext, err := validateContext(vcc.Context)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize credential contents: invalid @context: %w", err)
		}
		vcJSON["@context"] = validatedContext
	}
	if vcc.ID != "" {
		vcJSON["id"] = vcc.ID
	}
	if len(vcc.Types) > 0 {
		vcJSON["type"] = serializeTypes(vcc.Types)
	}
	if len(vcc.Subject) > 0 {
		vcJSON["credentialSubject"] = SerializeSubject(vcc.Subject)
	}
	if len(vcc.Proofs) > 0 {
		vcJSON["proof"] = proofsToRaw(vcc.Proofs)
	}
	if vcc.Issuer != "" {
		vcJSON["issuer"] = vcc.Issuer
	}
	if len(vcc.Schemas) > 0 {
		vcJSON["credentialSchema"] = typedIDsToRaw(vcc.Schemas)
	}
	if len(vcc.CredentialStatus) > 0 {
		vcJSON["credentialStatus"] = statusToRaw(vcc.CredentialStatus)
	}
	if !vcc.ValidFrom.IsZero() {
		vcJSON["validFrom"] = vcc.ValidFrom.Format(time.RFC3339)
	}
	if !vcc.ValidUntil.IsZero() {
		vcJSON["validUntil"] = vcc.ValidUntil.Format(time.RFC3339)
	}
	if len(vcc.Proofs) > 0 {
		vcJSON["proof"] = proofsToRaw(vcc.Proofs)
	}

	return vcJSON, nil
}

// keyTypeToAlgorithm maps a KeyType to its corresponding Algorithm.
func keyTypeToAlgorithm(keyType KeyType) Algorithm {
	switch keyType {
	case KeyTypeECDSAP256:
		return AlgorithmECDSAP256
	case KeyTypeECDSASecp256k1:
		return AlgorithmECDSASecp256k1
	case KeyTypeEd25519:
		return AlgorithmEd25519
	default:
		return ""
	}
}
