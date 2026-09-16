package vp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
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
//
// TODO(opts): one option type is reused across constructors, Parse, signing
// and verification, so some options are meaningless in some call sites and
// are silently ignored there (e.g. WithVerificationMethodKey on
// NewJSONPresentation, which only signing reads). Splitting into
// per-operation option sets is planned; until then each option documents
// where it applies.
type PresentationOpt func(*presentationOptions)

// presentationOptions holds configuration for presentation processing.
type presentationOptions struct {
	isValidateVC bool
	// vcOpts is forwarded to every embedded credential's Verify when
	// isValidateVC is set; the presentation resolver is prepended.
	vcOpts                  []vc.CredentialOpt
	isVerifyProof           bool
	isCheckExpiration       bool
	didBaseURL              string
	verificationMethodKey   string
	resolver                verificationmethod.ResolverProvider
	proofVerificationMethod string
	// Signing: written into proof.challenge / proof.domain.
	challenge string
	domain    string
	// Verifying: every checked proof must carry exactly these values.
	expectedChallenge string
	expectedDomain    string
}

// WithProofVerificationMethod restricts proof verification to the single proof
// bound to the given verification method URL. By default all proofs in the set
// must verify; with this option only the selected proof is checked.
func WithProofVerificationMethod(vm string) PresentationOpt {
	return func(p *presentationOptions) {
		p.proofVerificationMethod = vm
	}
}

// WithVCValidation verifies every credential embedded in the presentation.
// With no arguments only each credential's proof is verified; pass vc options
// to add checks, which are forwarded to vc.Credential.Verify as given, e.g.
//
//	vp.WithVCValidation(vc.WithSchemaValidation(), vc.WithCheckRevocation())
//
// The presentation's resolver is passed along, so callers do not repeat
// vc.WithResolver unless they want a different one for the credentials.
func WithVCValidation(opts ...vc.CredentialOpt) PresentationOpt {
	return func(p *presentationOptions) {
		p.isValidateVC = true
		p.vcOpts = append(p.vcOpts, opts...)
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
// picks its only VM, or the latest active VM in the authentication
// relationship array.
//
// The cryptosuite is chosen from the bound VM's key type. If the DID holds
// keys of DIFFERENT types, you MUST pin the VM here, otherwise the selected
// VM may not match your signer.
//
// For JSON presentations pass it to AddProofByProvider / AddProof; the
// constructors and Parse functions ignore it (see the TODO on
// PresentationOpt). For JWT presentations pass it to NewJWTPresentation, which
// builds the header from it.
func WithVerificationMethodKey(key string) PresentationOpt {
	return func(p *presentationOptions) {
		if key == "" {
			return
		}
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

// WithChallenge (signing) binds the presentation proof to the nonce the
// verifier issued, so the presentation cannot be replayed. It is signed as part
// of the proof configuration (Data Integrity § 3.2.5).
func WithChallenge(challenge string) PresentationOpt {
	return func(p *presentationOptions) {
		p.challenge = challenge
	}
}

// WithDomain (signing) binds the presentation proof to the relying party it is
// intended for. Signed alongside challenge.
func WithDomain(domain string) PresentationOpt {
	return func(p *presentationOptions) {
		p.domain = domain
	}
}

// WithExpectedChallenge (verifying) requires every verified proof to carry this
// challenge; a missing or different value fails verification. Implies
// WithVerifyProof, since the challenge is only trustworthy on a verified proof.
func WithExpectedChallenge(challenge string) PresentationOpt {
	return func(p *presentationOptions) {
		p.expectedChallenge = challenge
		p.isVerifyProof = true
	}
}

// WithExpectedDomain (verifying) requires every verified proof to carry this
// domain; a missing or different value fails verification. Implies
// WithVerifyProof, since the domain is only trustworthy on a verified proof.
func WithExpectedDomain(domain string) PresentationOpt {
	return func(p *presentationOptions) {
		p.expectedDomain = domain
		p.isVerifyProof = true
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
		isValidateVC:          false,
		isVerifyProof:         false,
		isCheckExpiration:     false,
		didBaseURL:            config.BaseURL,
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
