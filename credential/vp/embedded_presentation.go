package vp

import (
	"encoding/json"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
)

type EmbeddedPresentation struct {
	jsonPresentation JSONPresentation
	proof            *dto.Proof
}

func NewEmbeddedPresentation(vpc PresentationContents) (Presentation, error) {
	m, err := serializePresentationContents(&vpc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize presentation contents: %w", err)
	}

	return &EmbeddedPresentation{jsonPresentation: JSONPresentation(m)}, nil
}

func ParsePresentationEmbedded(rawJSON []byte, opts ...PresentationOpt) (Presentation, error) {
	if len(rawJSON) == 0 {
		return nil, fmt.Errorf("JSON string is empty")
	}

	var m jsonmap.JSONMap
	if err := json.Unmarshal(rawJSON, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal presentation: %w", err)
	}

	options := &presentationOptions{
		validate:   false,
		didBaseURL: config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	if options.validate {
		if err := verifyCredentials(JSONPresentation(m)); err != nil {
			return nil, fmt.Errorf("failed to validate presentation: %w", err)
		}
	}

	return &EmbeddedPresentation{jsonPresentation: JSONPresentation(m)}, nil
}

func (e *EmbeddedPresentation) AddProof(priv string, opts ...PresentationOpt) error {
	options := &presentationOptions{
		validate:   false,
		didBaseURL: config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	return (*jsonmap.JSONMap)(&e.jsonPresentation).AddECDSAProof(priv, e.getVerificationMethod(), "authentication", options.didBaseURL)
}

func (e *EmbeddedPresentation) getVerificationMethod() string {
	return fmt.Sprintf("%s#%s", e.jsonPresentation["holder"].(string), "key-1")
}

func (e *EmbeddedPresentation) GetSigningInput() ([]byte, error) {
	return (*jsonmap.JSONMap)(&e.jsonPresentation).Canonicalize()
}

func (e *EmbeddedPresentation) AddCustomProof(proof *dto.Proof) error {
	if proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}

	e.proof = proof

	return (*jsonmap.JSONMap)(&e.jsonPresentation).AddCustomProof(e.proof)
}

func (e *EmbeddedPresentation) Verify(opts ...PresentationOpt) error {
	options := &presentationOptions{
		validate:   false,
		didBaseURL: config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	isValid, err := (*jsonmap.JSONMap)(&e.jsonPresentation).VerifyProof(config.BaseURL)
	if err != nil {
		return err
	}
	if !isValid {
		return fmt.Errorf("invalid proof")
	}

	// Verify embedded credentials
	if options.validate {
		if err := verifyCredentials(e.jsonPresentation); err != nil {
			return fmt.Errorf("failed to verify credentials: %w", err)
		}
	}

	return nil
}

func (e *EmbeddedPresentation) Serialize() (interface{}, error) {
	// Check if presentation has proof
	if e.jsonPresentation["proof"] == nil {
		return nil, fmt.Errorf("presentation must have proof before serialization")
	}

	// Return the JSON presentation object directly
	return map[string]interface{}(e.jsonPresentation), nil
}

func (e *EmbeddedPresentation) GetContents() ([]byte, error) {
	return (*jsonmap.JSONMap)(&e.jsonPresentation).ToJSON()
}

// CreatePresentationEmbedded creates an embedded presentation from PresentationContents.
func CreatePresentationEmbedded(vpc PresentationContents, opts ...PresentationOpt) (Presentation, error) {
	if len(vpc.Context) == 0 && vpc.ID == "" && vpc.Holder == "" {
		return nil, fmt.Errorf("contents must have context, ID, or holder")
	}

	return NewEmbeddedPresentation(vpc)
}

func (e *EmbeddedPresentation) GetType() string {
	return "Embedded"
}
