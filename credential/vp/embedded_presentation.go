package vp

import (
	"encoding/json"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
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
		proc:       &processor.ProcessorOptions{},
		didBaseURL: config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	return &EmbeddedPresentation{jsonPresentation: JSONPresentation(m)}, nil
}

func (e *EmbeddedPresentation) AddProof(priv string, opts ...PresentationOpt) error {
	options := &presentationOptions{
		proc:       &processor.ProcessorOptions{},
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

func (e *EmbeddedPresentation) AddCustomProof(proof interface{}) error {
	if p, ok := proof.(*dto.Proof); ok {
		e.proof = p
	} else {
		return fmt.Errorf("proof must be a dto.Proof")
	}
	return (*jsonmap.JSONMap)(&e.jsonPresentation).AddCustomProof(e.proof)
}

func (e *EmbeddedPresentation) Verify(opts ...PresentationOpt) error {
	options := &presentationOptions{
		proc:       &processor.ProcessorOptions{},
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
	contents, err := e.ParsePresentationContents()
	if err != nil {
		return fmt.Errorf("failed to parse presentation contents: %w", err)
	}
	if err := verifyCredentials(contents.VerifiableCredentials); err != nil {
		return fmt.Errorf("failed to verify credentials: %w", err)
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

// ParsePresentationContents parses the Presentation into structured contents.
func (e *EmbeddedPresentation) ParsePresentationContents() (PresentationContents, error) {
	var contents PresentationContents
	parsers := []func(JSONPresentation, *PresentationContents) error{
		parseContext,
		parseID,
		parseTypes,
		parseHolder,
		parseVerifiableCredentials,
		parseProofs,
	}

	for _, parser := range parsers {
		if err := parser(e.jsonPresentation, &contents); err != nil {
			return contents, fmt.Errorf("failed to parse presentation contents: %w", err)
		}
	}
	return contents, nil
}

// ToJSON serializes the Presentation to JSON.
func (e *EmbeddedPresentation) ToJSON() ([]byte, error) {
	return (*jsonmap.JSONMap)(&e.jsonPresentation).ToJSON()
}

// CreatePresentationEmbedded creates an embedded presentation from PresentationContents.
func CreatePresentationEmbedded(vpc PresentationContents, opts ...PresentationOpt) (Presentation, error) {
	if len(vpc.Context) == 0 && vpc.ID == "" && vpc.Holder == "" {
		return nil, fmt.Errorf("contents must have context, ID, or holder")
	}

	return NewEmbeddedPresentation(vpc)
}
