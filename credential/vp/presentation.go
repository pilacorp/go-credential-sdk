package vp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
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
	// AddProof signs using a local private key (legacy API).
	AddProof(priv string, opts ...PresentationOpt) error

	// GetSigningInput returns the signing bytes for external signing (legacy API).
	GetSigningInput() ([]byte, error)
	// AddCustomProof attaches a caller-provided proof/signature (legacy API).
	AddCustomProof(proof *dto.Proof, opts ...PresentationOpt) error

	// AddProofByProvider signs using a signer provider (Vault/HSM/local).
	AddProofByProvider(signerProvider signer.SignerProvider, opts ...PresentationOpt) error

	Verify(opts ...PresentationOpt) error

	// Serialize returns the presentation in its native format
	// - For JWT presentations: returns the JWT string
	// - For embedded presentations: returns the JSON object with proof
	Serialize() (interface{}, error)

	GetContents() ([]byte, error)

	GetType() string

	executeOptions(opts ...PresentationOpt) error
}

// PresentationData represents presentation data in JSON format (suitable for both JWT and JSON presentations).
type PresentationData jsonmap.JSONMap

// PresentationContents represents the structured contents of a Presentation.
type PresentationContents struct {
	Context               []interface{}
	ID                    string
	Types                 []string
	Holder                string
	ValidFrom             time.Time // Issuance date
	ValidUntil            time.Time // Expiration date
	VerifiableCredentials []vc.Credential
}

// PresentationOpt configures presentation processing options.
type PresentationOpt func(*presentationOptions)

// presentationOptions holds configuration for presentation processing.
type presentationOptions struct {
	isValidateVC          bool
	isVerifyProof         bool
	isCheckExpiration     bool
	didBaseURL            string
	verificationMethodKey string
	resolver              verificationmethod.ResolverProvider
}

// WithVCValidation enables validation for credentials in the presentation.
func WithVCValidation() PresentationOpt {
	return func(p *presentationOptions) {
		p.isValidateVC = true
	}
}

// WithBaseURL sets the DID base URL for presentation processing.
func WithBaseURL(baseURL string) PresentationOpt {
	return func(p *presentationOptions) {
		p.didBaseURL = baseURL
	}
}

// WithVerificationMethodKey sets the verification method fragment used when
// signing — e.g. "key-2". When omitted, the SDK resolves the holder DID and
// picks the latest active VM in the authentication relationship array.
func WithVerificationMethodKey(key string) PresentationOpt {
	return func(p *presentationOptions) {
		p.verificationMethodKey = key
	}
}

// WithVerifyProof enables proof verification during presentation parsing.
func WithVerifyProof() PresentationOpt {
	return func(p *presentationOptions) {
		p.isVerifyProof = true
	}
}

// WithCheckExpiration enables expiration check during presentation parsing.
func WithCheckExpiration() PresentationOpt {
	return func(p *presentationOptions) {
		p.isCheckExpiration = true
	}
}

// WithResolver sets the document resolver for presentation signing/verification.
func WithResolver(resolver verificationmethod.ResolverProvider) PresentationOpt {
	return func(p *presentationOptions) {
		p.resolver = resolver
	}
}

func getOptions(opts ...PresentationOpt) *presentationOptions {
	options := &presentationOptions{
		isValidateVC:      false,
		isVerifyProof:     false,
		isCheckExpiration: false,
		didBaseURL:        config.BaseURL,
		// verificationMethodKey is left empty so AddProof resolves the
		// latest VM in the authentication array. Override with
		// WithVerificationMethodKey to pin a specific kid.
		verificationMethodKey: "",
		resolver:              nil,
	}

	for _, opt := range opts {
		opt(options)
	}

	if options.resolver == nil {
		options.resolver = verificationmethod.NewHTTPResolver(options.didBaseURL)
	}

	return options
}

// ParsePresentation parses a presentation into a Presentation.
func ParsePresentation(rawPresentation []byte, opts ...PresentationOpt) (Presentation, error) {
	if len(rawPresentation) == 0 {
		return nil, fmt.Errorf("presentation is empty")
	}

	if isJSONPresentation(rawPresentation) {
		return ParseJSONPresentation(rawPresentation, opts...)
	}

	valStr := string(rawPresentation)
	if isJWTPresentation(valStr) {
		return ParseJWTPresentation(valStr, opts...)
	}

	return nil, fmt.Errorf("failed to parse presentation")
}

// ParsePresentationWithValidation parses a presentation into a Presentation with validation.
func ParsePresentationWithValidation(rawPresentation []byte) (Presentation, error) {
	return ParsePresentation(rawPresentation, WithVCValidation(), WithVerifyProof())
}

func isJSONPresentation(rawPresentation []byte) bool {
	if len(rawPresentation) == 0 {
		return false
	}

	if !json.Valid(rawPresentation) {
		return false
	}

	var jsonMap map[string]interface{}
	err := json.Unmarshal(rawPresentation, &jsonMap)
	if err != nil {
		return false
	}

	return true
}

func isJWTPresentation(valStr string) bool {
	valStr = strings.Trim(valStr, "\"")
	regex := `^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$`
	match, _ := regexp.MatchString(regex, valStr)
	return match
}
