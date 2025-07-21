package vc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// KeyType represents a cryptographic key type.
type KeyType string

const (
	KeyTypeECDSAP256      KeyType = "ECDSAP256"
	KeyTypeECDSASecp256k1 KeyType = "ECDSASecp256k1"
	KeyTypeEd25519        KeyType = "Ed25519"
)

// Algorithm represents a cryptographic algorithm.
type Algorithm string

const (
	AlgorithmECDSAP256      Algorithm = "ES256"
	AlgorithmECDSASecp256k1 Algorithm = "ES256K"
	AlgorithmEd25519        Algorithm = "EdDSA"
)

// Proof represents a Linked Data Proof.
type Proof struct {
	Type               string   `json:"type"`
	Created            string   `json:"created"`
	VerificationMethod string   `json:"verificationMethod"`
	ProofPurpose       string   `json:"proofPurpose"`
	ProofValue         string   `json:"proofValue,omitempty"`
	JWS                string   `json:"jws,omitempty"`
	Disclosures        []string `json:"disclosures,omitempty"`
}

// CryptographicSigner defines the interface for signing data.
type CryptographicSigner interface {
	Sign(data []byte, encode bool) ([]byte, error)
	Algorithm() Algorithm
	KeyType() KeyType
}

// ProofDescriptor defines the interface for proof-specific behavior.
type ProofDescriptor interface {
	ProofType() string
	SupportedKeyTypes() []KeyType
}

// ProofCreator manages proof creation for multiple algorithms.
type ProofCreator struct {
	signers map[string]proofEntry
}

type proofEntry struct {
	descriptor ProofDescriptor
	signer     CryptographicSigner
}

// NewProofCreator creates a new ProofCreator.
func NewProofCreator() *ProofCreator {
	return &ProofCreator{
		signers: make(map[string]proofEntry),
	}
}

// AddProofType adds support for a proof type with its descriptor and signer.
func (c *ProofCreator) AddProofType(descriptor ProofDescriptor, signer CryptographicSigner) {
	c.signers[descriptor.ProofType()] = proofEntry{
		descriptor: descriptor,
		signer:     signer,
	}
}

// Sign signs a document using the specified proof type and key type.
func (c *ProofCreator) Sign(proof *Proof, keyType KeyType, data []byte, encode bool) ([]byte, error) {
	entry, ok := c.signers[proof.Type]
	if !ok {
		return nil, fmt.Errorf("unsupported proof type: %s", proof.Type)
	}

	supported := false
	for _, kt := range entry.descriptor.SupportedKeyTypes() {
		if kt == keyType {
			supported = true
			break
		}
	}
	if !supported {
		return nil, fmt.Errorf("proof type %s does not support key type %s", proof.Type, keyType)
	}

	if entry.signer.KeyType() != keyType {
		return nil, fmt.Errorf("signer key type %s does not match requested %s", entry.signer.KeyType(), keyType)
	}

	return entry.signer.Sign(data, encode)
}

// ProofVerifier verifies proofs on Verifiable Credentials.
type ProofVerifier struct {
	verifiers map[KeyType]CryptographicVerifier
}

// CryptographicVerifier defines the interface for verifying signatures.
type CryptographicVerifier interface {
	Verify(data, signature []byte, publicKey interface{}) error
	KeyType() KeyType
}

// NewProofVerifier creates a new ProofVerifier.
func NewProofVerifier() *ProofVerifier {
	return &ProofVerifier{
		verifiers: make(map[KeyType]CryptographicVerifier),
	}
}

// AddVerifier adds a verifier for a specific key type.
func (v *ProofVerifier) AddVerifier(verifier CryptographicVerifier) {
	v.verifiers[verifier.KeyType()] = verifier
}

// Verify verifies the proof on a Credential.
func (v *ProofVerifier) Verify(vc *Credential, publicKey interface{}, keyType KeyType, opts ...ProcessorOpt) error {
	proofs, ok := (*vc)["proof"].([]interface{})
	if !ok {
		if proof, exists := (*vc)["proof"]; exists {
			proofs = []interface{}{proof}
		} else {
			return fmt.Errorf("credential has no proof")
		}
	}

	verifier, ok := v.verifiers[keyType]
	if !ok {
		return fmt.Errorf("no verifier for key type %s", keyType)
	}

	vcCopy := make(Credential)
	for k, v := range *vc {
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

	for i, p := range proofs {
		var proofValue, jws string
		var disclosures []string
		switch pr := p.(type) {
		case *Proof:
			if pr == nil {
				return fmt.Errorf("nil proof at index %d", i)
			}
			proofValue = pr.ProofValue
			jws = pr.JWS
			disclosures = pr.Disclosures
		case map[string]interface{}:
			parsedProof, err := parseProof(pr)
			if err != nil {
				return fmt.Errorf("parse proof at index %d: %w", i, err)
			}
			proofValue = parsedProof.ProofValue
			jws = parsedProof.JWS
			disclosures = parsedProof.Disclosures
		default:
			return fmt.Errorf("invalid proof format at index %d: %T", i, p)
		}

		if jws == "" && proofValue == "" {
			return fmt.Errorf("proof at index %d has no jws or proofValue", i)
		}

		var signature []byte
		if jws != "" {
			// Handle JWS (Base64-encoded signature)
			signature = []byte(jws)
		} else {
			// Handle proofValue (multibase base64url)
			if proofValue == "" {
				return fmt.Errorf("proofValue is empty at index %d", i)
			}
			fmt.Printf("Verifying proofValue at index %d: %s (length: %d)\n", i, proofValue, len(proofValue))
			// Decode proofValue
			encodedProof := proofValue
			if len(proofValue) > 0 && proofValue[0] == 'u' {
				encodedProof = proofValue[1:] // Remove 'u' prefix
			}
			if len(encodedProof) < 80 {
				return fmt.Errorf("proofValue at index %d too short: %d characters, expected ~86", i, len(encodedProof))
			}
			signature, err = base64.RawURLEncoding.DecodeString(encodedProof)
			if err != nil {
				return fmt.Errorf("decode proofValue at index %d: %w", i, err)
			}
			fmt.Printf("Decoded proofValue length at index %d: %d\n", i, len(signature))
			if len(signature) != 64 {
				return fmt.Errorf("decoded proofValue length at index %d: expected 64 bytes, got %d", i, len(signature))
			}
		}

		// Include disclosures if present (for JWS)
		signatureWithDisclosures := string(signature)
		if len(disclosures) > 0 {
			signatureWithDisclosures += "~" + strings.Join(disclosures, "~")
		}

		if err := verifier.Verify(digest, []byte(signatureWithDisclosures), publicKey); err != nil {
			return fmt.Errorf("verify proof at index %d: %w", i, err)
		}
	}

	return nil
}

// VerifyJWT verifies a JWT string and returns the reconstructed Credential.
func (v *ProofVerifier) VerifyJWT(jwtString string, publicKey interface{}, keyType KeyType, opts ...CredentialOpt) (*Credential, error) {
	verifier, ok := v.verifiers[keyType]
	if !ok {
		return nil, fmt.Errorf("no verifier for key type %s", keyType)
	}

	// Parse JWT
	parts := strings.Split(jwtString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected header.payload.signature")
	}
	headerB64, payloadB64, signatureB64 := parts[0], parts[1], parts[2]

	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}

	// Reconstruct Credential
	var credential Credential
	if err := json.Unmarshal(payloadJSON, &credential); err != nil {
		return nil, fmt.Errorf("unmarshal JWT payload: %w", err)
	}

	// Verify signature
	data := []byte(headerB64 + "." + payloadB64)
	if err := verifier.Verify(data, []byte(signatureB64), publicKey); err != nil {
		return nil, fmt.Errorf("verify JWT: %w", err)
	}

	// Apply credential options (e.g., validation)
	options := &credentialOptions{
		processor: &ProcessorOptions{},
		validate:  true,
	}
	for _, opt := range opts {
		opt(options)
	}

	if options.validate {
		if err := validateCredential(credential, options.processor); err != nil {
			return nil, fmt.Errorf("validate credential: %w", err)
		}
	}

	return &credential, nil
}

// parseLDProof parses the proof field into a slice of Proof structs.
func parseLDProof(proofRaw interface{}) ([]Proof, error) {
	if proofRaw == nil {
		return nil, nil
	}

	switch proof := proofRaw.(type) {
	case *Proof:
		if proof == nil {
			return nil, fmt.Errorf("nil proof")
		}
		return []Proof{*proof}, nil
	case map[string]interface{}:
		parsedProof, err := parseProof(proof)
		if err != nil {
			return nil, fmt.Errorf("parse proof: %w", err)
		}
		return []Proof{parsedProof}, nil
	case []interface{}:
		var proofs []Proof
		for i, p := range proof {
			switch pr := p.(type) {
			case *Proof:
				if pr == nil {
					return nil, fmt.Errorf("nil proof at index %d", i)
				}
				proofs = append(proofs, *pr)
			case map[string]interface{}:
				parsedProof, err := parseProof(pr)
				if err != nil {
					return nil, fmt.Errorf("parse proof at index %d: %w", i, err)
				}
				proofs = append(proofs, parsedProof)
			default:
				return nil, fmt.Errorf("invalid proof format at index %d: %T", i, p)
			}
		}
		return proofs, nil
	default:
		return nil, fmt.Errorf("unsupported proof format: %T", proofRaw)
	}
}

// parseProof converts a single proof map into a Proof struct.
func parseProof(proof map[string]interface{}) (Proof, error) {
	var result Proof

	// Safely extract fields with type assertions
	if t, ok := proof["type"].(string); ok {
		result.Type = t
	} else {
		return Proof{}, fmt.Errorf("invalid or missing type field")
	}

	if created, ok := proof["created"].(string); ok {
		result.Created = created
	} else {
		return Proof{}, fmt.Errorf("invalid or missing created field")
	}

	if vm, ok := proof["verificationMethod"].(string); ok {
		result.VerificationMethod = vm
	} else {
		return Proof{}, fmt.Errorf("invalid or missing verificationMethod field")
	}

	if pp, ok := proof["proofPurpose"].(string); ok {
		result.ProofPurpose = pp
	} else {
		return Proof{}, fmt.Errorf("invalid or missing proofPurpose field")
	}

	if pv, ok := proof["proofValue"].(string); ok {
		result.ProofValue = pv
	} // proofValue is optional

	if jws, ok := proof["jws"].(string); ok {
		result.JWS = jws
	} // jws is optional

	if disclosures, ok := proof["disclosures"].([]interface{}); ok {
		for _, d := range disclosures {
			if ds, ok := d.(string); ok {
				result.Disclosures = append(result.Disclosures, ds)
			}
		}
	} // disclosures is optional

	return result, nil
}
