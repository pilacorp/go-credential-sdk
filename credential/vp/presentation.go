package vp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/bbs"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// config holds package-level configuration set via Init.
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
	Verify(opts ...PresentationOpt) error

	// Serialize returns the presentation in its native format:
	// the JWT string (JWT) or the JSON object with proof (JSON).
	Serialize() (any, error)

	GetContents() ([]byte, error)

	GetType() string

	// ExtractField returns a field by dot-notation path, or nil if absent.
	ExtractField(path string) any
}

// PresentationData represents presentation data in JSON format (suitable for both JWT and JSON presentations).
type PresentationData jsonmap.JSONMap

// PresentationContents represents the structured contents of a Presentation.
type PresentationContents struct {
	Context               []interface{}   `json:"context,omitempty"`
	ID                    string          `json:"id,omitempty"`
	Types                 []string        `json:"type,omitempty"`
	Holder                string          `json:"holder,omitempty"`
	ValidFrom             time.Time       `json:"validFrom,omitempty"`  // Issuance date
	ValidUntil            time.Time       `json:"validUntil,omitempty"` // Expiration date
	VerifiableCredentials []vc.Credential `json:"verifiableCredential,omitempty"`
}

// PresentationOpt configures presentation processing options.
type PresentationOpt func(*presentationOptions)

// presentationOptions holds configuration for presentation processing.
type presentationOptions struct {
	isValidateVC            bool
	isVerifyProof           bool
	isCheckExpiration       bool
	didBaseURL              string
	verificationMethodKey   string
	resolver                verificationmethod.ResolverProvider
	proofVerificationMethod string
	bbsEngine              bbs.Engine
}

// WithProofVerificationMethod restricts proof verification to the single proof
// bound to the given verification method URL. By default all proofs in the set
// must verify; with this option only the selected proof is checked.
func WithProofVerificationMethod(vm string) PresentationOpt {
	return func(p *presentationOptions) {
		p.proofVerificationMethod = vm
	}
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
//
// The cryptosuite is chosen from the bound VM's key type. If the DID holds
// keys of DIFFERENT types, you MUST pin the VM here, otherwise the latest
// active VM is used and may not match your signer.
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

// WithBBSEngine sets the bbs-2023 engine used when verifying embedded BBS
// credentials inside a presentation.
func WithBBSEngine(engine bbs.Engine) PresentationOpt {
	return func(p *presentationOptions) {
		p.bbsEngine = engine
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
