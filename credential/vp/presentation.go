package vp

import (
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
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

type Presentation interface {
	AddProof(priv string, opts ...PresentationOpt) error

	GetSigningInput() ([]byte, error)
	AddCustomProof(proof *dto.Proof) error

	Verify(opts ...PresentationOpt) error

	// Serialize returns the presentation in its native format
	// - For JWT presentations: returns the JWT string
	// - For embedded presentations: returns the JSON object with proof
	Serialize() (interface{}, error)

	ToJSON() ([]byte, error)
}

// JSONPresentation represents a W3C Verifiable Presentation as a JSON object.
type JSONPresentation jsonmap.JSONMap

// PresentationContents represents the structured contents of a Presentation.
type PresentationContents struct {
	Context               []interface{}
	ID                    string
	Types                 []string
	Holder                string
	VerifiableCredentials []vc.Credential
}

// PresentationOpt configures presentation processing options.
type PresentationOpt func(*presentationOptions)

// presentationOptions holds configuration for presentation processing.
type presentationOptions struct {
	validate   bool
	didBaseURL string
}

func WithEnableValidation() PresentationOpt {
	return func(p *presentationOptions) {
		p.validate = true
	}
}

// WithBaseURL sets the DID base URL for presentation processing.
func WithBaseURL(baseURL string) PresentationOpt {
	return func(p *presentationOptions) {
		p.didBaseURL = baseURL
	}
}

// ParsePresentation parses a presentation into a Presentation.
func ParsePresentation(rawPresentation []byte, opts ...PresentationOpt) (Presentation, error) {
	if len(rawPresentation) == 0 {
		return nil, fmt.Errorf("presentation is empty")
	}

	// try to parse as JWT
	presentation, err := ParsePresentationJWT(string(rawPresentation), opts...)
	if err == nil {
		return presentation, nil
	}

	// try to parse as embedded
	presentation, err = ParsePresentationEmbedded(rawPresentation, opts...)
	if err == nil {
		return presentation, nil
	}

	return nil, fmt.Errorf("failed to parse presentation")
}
