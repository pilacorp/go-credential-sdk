package vp

import (
	"encoding/json"
	"fmt"
	"strings"

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

	GetContents() ([]byte, error)

	GetType() string
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

// WithEnableValidation enables validation for credentials in the presentation.
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

	var valMap map[string]interface{}
	err := json.Unmarshal(rawPresentation, &valMap)
	if err == nil && valMap != nil {
		return ParsePresentationEmbedded(rawPresentation, opts...)
	}

	valStr := string(rawPresentation)
	// check valStr is a valid jwt token
	// count the number of dots in valStr
	dotCount := strings.Count(valStr, ".")
	if dotCount > 0 && dotCount < 3 {
		return ParsePresentationJWT(valStr, opts...)
	}

	return nil, fmt.Errorf("failed to parse presentation")
}
