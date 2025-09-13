package vc

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/jwt"
)

type JWTHeaders map[string]interface{}

type JWTCredential struct {
	Payload   JSONCredential
	signature string
}

func NewJWTCredential(vcc CredentialContents, opts ...CredentialOpt) (Credential, error) {
	options := &credentialOptions{
		validate:   false,
		didBaseURL: config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	// Convert CredentialContents to JSONCredential directly
	m, err := serializeCredentialContents(&vcc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize credential contents: %w", err)
	}

	if options.validate {
		if err := validateCredential(m); err != nil {
			return nil, fmt.Errorf("failed to validate credential: %w", err)
		}
	}

	payload := JSONCredential(m)

	return &JWTCredential{
		Payload: payload,
	}, nil
}

func ParseCredentialJWT(rawJWT string, opts ...CredentialOpt) (Credential, error) {
	// Remove JSON quotes if present (from json.Marshal of a string)
	rawJWT = strings.Trim(rawJWT, `"`)

	m, err := jwt.GetDocumentFromJWT(rawJWT, "vc")
	if err != nil {
		return nil, fmt.Errorf("failed to get document from JWT: %w", err)
	}

	options := &credentialOptions{
		validate:   false,
		didBaseURL: config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	if options.validate {
		if err := validateCredential(m); err != nil {
			return nil, fmt.Errorf("failed to validate credential: %w", err)
		}
	}

	return &JWTCredential{
		Payload:   JSONCredential(m),
		signature: strings.Split(rawJWT, ".")[2],
	}, nil
}

func (j *JWTCredential) AddProof(priv string, opts ...CredentialOpt) error {
	signer := jwt.NewJWTSigner(priv, j.Payload["issuer"].(string))

	jwtString, err := signer.SignDocument((jsonmap.JSONMap)(j.Payload), "vc")
	if err != nil {
		return err
	}

	parts := strings.Split(jwtString, ".")
	if len(parts) < 2 {
		return fmt.Errorf("invalid JWT token")
	}
	j.signature = parts[2]

	return nil
}

func (j *JWTCredential) GetSigningInput() ([]byte, error) {
	signer := jwt.NewJWTSigner("", j.Payload["issuer"].(string))

	return signer.SigningInput((jsonmap.JSONMap)(j.Payload), "vc")
}

func (j *JWTCredential) AddCustomProof(proof *dto.Proof) error {
	if proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}

	if len(proof.Signature) == 0 {
		return fmt.Errorf("proof signature cannot be empty")
	}

	j.signature = base64.RawURLEncoding.EncodeToString(proof.Signature)

	return nil
}

func (j *JWTCredential) Verify(opts ...CredentialOpt) error {
	options := &credentialOptions{
		validate:   false,
		didBaseURL: config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	verifier := jwt.NewJWTVerifier(config.BaseURL)

	serialized, err := j.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize credential: %w", err)
	}

	err = verifier.VerifyDocument(serialized.(string), "vc")
	if err != nil {
		return err
	}

	if options.validate {
		if err := validateCredential(jsonmap.JSONMap(j.Payload)); err != nil {
			return fmt.Errorf("failed to validate credential: %w", err)
		}
	}

	return nil
}

func (j *JWTCredential) Serialize() (interface{}, error) {
	if j.signature == "" {
		return nil, fmt.Errorf("credential must be signed before serialization")
	}

	signingInput, err := j.GetSigningInput()
	if err != nil {
		return nil, fmt.Errorf("failed to get signing input: %w", err)
	}

	return fmt.Sprintf("%s.%s", signingInput, j.signature), nil
}

func (j *JWTCredential) GetContents() ([]byte, error) {
	return (*jsonmap.JSONMap)(&j.Payload).ToJSON()
}

func (j *JWTCredential) GetType() string {
	return "JWT"
}
