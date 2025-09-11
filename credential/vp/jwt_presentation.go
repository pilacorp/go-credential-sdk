package vp

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
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
		signature: strings.Split(rawJWT, ".")[2],
	}, nil
}

func (j *JWTPresentation) AddProof(priv string, opts ...PresentationOpt) error {
	signer := jwt.NewJWTSigner(priv, j.Payload["holder"].(string))

	jwtString, err := signer.SignDocument((jsonmap.JSONMap)(j.Payload), "vp")
	if err != nil {
		return err
	}
	parts := strings.Split(jwtString, ".")
	j.signature = parts[2]

	return nil
}

func (j *JWTPresentation) GetSigningInput() ([]byte, error) {
	signer := jwt.NewJWTSigner("", j.Payload["holder"].(string))
	signingInput, err := signer.SigningInput((jsonmap.JSONMap)(j.Payload), "vp")
	if err != nil {
		return nil, fmt.Errorf("failed to get signing input: %w", err)
	}
	return []byte(signingInput), nil
}

func (j *JWTPresentation) AddCustomProof(proof *dto.Proof) error {
	if proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}
	if len(proof.Signature) == 0 {
		return fmt.Errorf("proof signature cannot be empty")
	}
	j.signature = base64.RawURLEncoding.EncodeToString(proof.Signature)
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

	verifier := jwt.NewJWTVerifier(config.BaseURL)

	serialized, err := j.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize presentation: %w", err)
	}

	err = verifier.VerifyDocument(serialized.(string), "vp")
	if err != nil {
		return err
	}

	// Verify embedded JWT credentials
	contents, err := j.parsePresentationContents()
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
	signingInput, err := j.GetSigningInput()
	if err != nil {
		return nil, fmt.Errorf("failed to get signing input: %w", err)
	}
	return fmt.Sprintf("%s.%s", signingInput, j.signature), nil
}

func (j *JWTPresentation) GetType() string {
	return "JWTPresentation"
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

// parsePresentationContents parses the Presentation into structured contents.
func (j *JWTPresentation) parsePresentationContents() (PresentationContents, error) {
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
