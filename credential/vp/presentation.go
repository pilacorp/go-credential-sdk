package vp

import (
	"encoding/json"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
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

// Presentation represents a W3C Verifiable Presentation as a JSON object.
type Presentation jsonmap.JSONMap

// PresentationContents represents the structured contents of a Presentation.
type PresentationContents struct {
	Context               []interface{}
	ID                    string
	Types                 []string
	Holder                string
	VerifiableCredentials []*vc.Credential
	Proofs                []dto.Proof
}

// PresentationOpt configures presentation processing options.
type PresentationOpt func(*presentationOptions)

// presentationOptions holds configuration for presentation processing.
type presentationOptions struct {
	proc       *processor.ProcessorOptions
	didBaseURL string
}

// WithPresentationProcessorOptions sets processor options for presentation processing.
func WithPresentationProcessorOptions(options ...processor.ProcessorOpt) PresentationOpt {
	return func(p *presentationOptions) {
		p.proc = &processor.ProcessorOptions{}
		for _, opt := range options {
			opt(p.proc)
		}
	}
}

// WithBaseURL sets the DID base URL for presentation processing.
func WithBaseURL(baseURL string) PresentationOpt {
	return func(p *presentationOptions) {
		p.didBaseURL = baseURL
	}
}

// ParsePresentation parses a JSON string into a Presentation.
func ParsePresentation(rawJSON []byte, opts ...PresentationOpt) (*Presentation, error) {
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

	// Add schema validation if needed (not in original code)
	// if err := validatePresentation(m, options.processor); err != nil {
	// 	return nil, fmt.Errorf("failed to validate presentation: %w", err)
	// }

	p := Presentation(m)
	return &p, nil
}

// CreatePresentationWithContent creates a Presentation from PresentationContents.
func CreatePresentationWithContent(vpc PresentationContents) (*Presentation, error) {
	if len(vpc.Context) == 0 && vpc.ID == "" && vpc.Holder == "" {
		return nil, fmt.Errorf("contents must have context, ID, or holder")
	}

	m, err := serializePresentationContents(&vpc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize presentation contents: %w", err)
	}
	p := Presentation(m)
	return &p, nil
}

// ToJSON serializes the Presentation to JSON.
func (p *Presentation) ToJSON() ([]byte, error) {
	return (*jsonmap.JSONMap)(p).ToJSON()
}

// AddECDSAProof adds an ECDSA proof to the Presentation.
func (p *Presentation) AddECDSAProof(priv, verificationMethod string, opts ...PresentationOpt) error {
	options := &presentationOptions{
		proc:       &processor.ProcessorOptions{},
		didBaseURL: config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	return (*jsonmap.JSONMap)(p).AddECDSAProof(priv, verificationMethod, "authentication", options.didBaseURL)
}

// AddCustomProof adds a custom proof to the Presentation.
func (p *Presentation) AddCustomProof(priv, proof *dto.Proof) error {

	return (*jsonmap.JSONMap)(p).AddCustomProof(proof)
}

// CanonicalizePresentation canonicalizes the Presentation for signing or verification.
func (p *Presentation) CanonicalizePresentation() ([]byte, error) {
	return (*jsonmap.JSONMap)(p).Canonicalize()
}

// VerifyECDSAPresentation verifies an ECDSA-signed Presentation.
func VerifyECDSAPresentation(vp *Presentation, opts ...PresentationOpt) (bool, error) {
	options := &presentationOptions{
		proc:       &processor.ProcessorOptions{},
		didBaseURL: config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	isValid, err := (*jsonmap.JSONMap)(vp).VerifyECDSA(options.didBaseURL)
	if err != nil {
		return false, err
	}

	// Verify embedded credentials
	contents, err := vp.ParsePresentationContents()
	if err != nil {
		return false, fmt.Errorf("failed to parse presentation contents: %w", err)
	}
	if err := verifyCredentials(contents.VerifiableCredentials); err != nil {
		return false, fmt.Errorf("failed to verify credentials: %w", err)
	}

	return isValid, nil
}

// ParsePresentationContents parses the Presentation into structured contents.
func (p *Presentation) ParsePresentationContents() (PresentationContents, error) {
	var contents PresentationContents
	parsers := []func(*Presentation, *PresentationContents) error{
		parseContext,
		parseID,
		parseTypes,
		parseHolder,
		parseVerifiableCredentials,
		parseProofs,
	}

	for _, parser := range parsers {
		if err := parser(p, &contents); err != nil {
			return contents, fmt.Errorf("failed to parse presentation contents: %w", err)
		}
	}
	return contents, nil
}
