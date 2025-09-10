package vp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/jwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
)

type JWTPresentationHeaders map[string]interface{}

type JWTPresentation struct {
	Headers   JWTPresentationHeaders
	Payload   JSONPresentation
	signature string
}

// JWTPresentationOpt is an alias for PresentationOpt for JWT presentations
type JWTPresentationOpt = PresentationOpt

func NewJWTPresentation(vpc PresentationContents, opts ...PresentationOpt) (Presentation, error) {
	options := &presentationOptions{
		proc:       &processor.ProcessorOptions{},
		didBaseURL: config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	// Convert PresentationContents to JSONPresentation directly
	m, err := serializePresentationContents(&vpc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize presentation contents: %w", err)
	}

	headers := extractPresentationClaims(m)
	payload := JSONPresentation(m)

	return &JWTPresentation{
		Headers: headers,
		Payload: payload,
	}, nil
}

func ParsePresentationJWT(rawJWT string, opts ...PresentationOpt) (Presentation, error) {
	m, err := jwt.GetDocumentFromJWT(rawJWT, "vp")
	if err != nil {
		return nil, fmt.Errorf("failed to get document from JWT: %w", err)
	}

	options := &presentationOptions{
		proc:       &processor.ProcessorOptions{},
		didBaseURL: config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	return &JWTPresentation{
		Headers:   extractPresentationClaims(m),
		Payload:   JSONPresentation(m),
		signature: rawJWT,
	}, nil
}

func (j *JWTPresentation) Type() PresentationType {
	return PresentationTypeJWT
}

func (j *JWTPresentation) AddProof(priv string, opts ...PresentationOpt) error {
	signer := jwt.NewJWTSigner(priv, j.Payload["holder"].(string))

	jwtString, err := signer.SignDocument((jsonmap.JSONMap)(j.Payload), "vp")
	if err != nil {
		return err
	}
	j.signature = jwtString

	return nil
}

func (j *JWTPresentation) GetSigningInput() ([]byte, error) {
	headersBytes, err := json.Marshal(j.Headers)
	if err != nil {
		return nil, err
	}
	headerStr := base64.StdEncoding.EncodeToString(headersBytes)

	payloadBytes, err := json.Marshal(j.Payload)
	if err != nil {
		return nil, err
	}
	payloadStr := base64.StdEncoding.EncodeToString(payloadBytes)

	return []byte(fmt.Sprintf("%s.%s", headerStr, payloadStr)), nil
}

func (j *JWTPresentation) AddCustomProof(proof interface{}) error {
	if _, ok := proof.(string); ok {
		j.signature = proof.(string)
	} else {
		return fmt.Errorf("proof must be a string")
	}

	return nil
}

func (j *JWTPresentation) Verify(opts ...PresentationOpt) error {
	options := &presentationOptions{
		proc:       &processor.ProcessorOptions{},
		didBaseURL: config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	verifier := jwt.NewJWTVerifier(options.didBaseURL)

	err := verifier.VerifyDocument(j.signature, "vp")
	if err != nil {
		return err
	}

	// Verify embedded JWT credentials
	contents, err := j.ParsePresentationContents()
	if err != nil {
		return fmt.Errorf("failed to parse presentation contents: %w", err)
	}
	if err := verifyCredentials(contents.VerifiableCredentials); err != nil {
		return fmt.Errorf("failed to verify credentials: %w", err)
	}

	return nil
}

func (j *JWTPresentation) Serialize() (interface{}, error) {
	if j.signature == "" {
		return nil, fmt.Errorf("presentation must be signed before serialization")
	}
	return j.signature, nil
}

func extractPresentationClaims(m jsonmap.JSONMap) JWTPresentationHeaders {
	headers := make(JWTPresentationHeaders)

	if m["holder"] != "" {
		headers["iss"] = m["holder"]
	}
	if m["id"] != "" {
		headers["jti"] = m["id"]
	}
	headers["typ"] = "vp"
	headers["alg"] = "ES256"

	return headers
}

// ParsePresentationContents parses the Presentation into structured contents.
func (j *JWTPresentation) ParsePresentationContents() (PresentationContents, error) {
	var contents PresentationContents
	parsers := []func(JSONPresentation, *PresentationContents) error{
		parseContext,
		parseID,
		parseTypes,
		parseHolder,
		parseVerifiableCredentials,
	}

	for _, parser := range parsers {
		if err := parser(j.Payload, &contents); err != nil {
			return contents, fmt.Errorf("failed to parse presentation contents: %w", err)
		}
	}
	return contents, nil
}

// CreatePresentationJWT creates a JWT presentation from PresentationContents.
func CreatePresentationJWT(vpc PresentationContents, opts ...PresentationOpt) (Presentation, error) {
	if len(vpc.Context) == 0 && vpc.ID == "" && vpc.Holder == "" {
		return nil, fmt.Errorf("contents must have context, ID, or holder")
	}

	return NewJWTPresentation(vpc, opts...)
}
