package vp

import (
	"fmt"

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

type PresentationType string

const (
	PresentationTypeEmbedded PresentationType = "embedded"
	PresentationTypeJWT      PresentationType = "jwt"
)

type Presentation interface {
	Type() PresentationType

	AddProof(priv string, opts ...PresentationOpt) error

	GetSigningInput() ([]byte, error)
	AddCustomProof(proof interface{}) error

	Verify(opts ...PresentationOpt) error

	// Serialize returns the presentation in its native format
	// - For JWT presentations: returns the JWT string
	// - For embedded presentations: returns the JSON object with proof
	Serialize() (interface{}, error)

	// ParsePresentationContents parses the presentation into structured contents
	ParsePresentationContents() (PresentationContents, error)
}

// JSONPresentation represents a W3C Verifiable Presentation as a JSON object.
type JSONPresentation jsonmap.JSONMap

// PresentationContents represents the structured contents of a Presentation.
type PresentationContents struct {
	Context               []interface{}
	ID                    string
	Types                 []string
	Holder                string
	VerifiableCredentials []*vc.Credential
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

// ParsePresentation parses a presentation into a Presentation.
func ParsePresentation(rawPresentation interface{}, opts ...PresentationOpt) (Presentation, error) {
	switch rawPresentation.(type) {
	case []byte:
		return ParsePresentationEmbedded(rawPresentation.([]byte), opts...)
	case string:
		return ParsePresentationJWT(rawPresentation.(string), opts...)
	default:
		return nil, fmt.Errorf("invalid presentation type")
	}
}

// CreatePresentationWithContents creates a presentation based on the specified type.
func CreatePresentationWithContents(presType PresentationType, vpc PresentationContents, opts ...PresentationOpt) (Presentation, error) {
	if len(vpc.Context) == 0 && vpc.ID == "" && vpc.Holder == "" {
		return nil, fmt.Errorf("contents must have context, ID, or holder")
	}

	switch presType {
	case PresentationTypeJWT:
		return CreatePresentationJWT(vpc, opts...)
	case PresentationTypeEmbedded:
		return CreatePresentationEmbedded(vpc, opts...)
	default:
		return nil, fmt.Errorf("unsupported presentation type: %s", presType)
	}
}
