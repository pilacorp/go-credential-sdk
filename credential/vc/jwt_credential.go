package vc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/jwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
)

type JWTHeaders map[string]interface{}

type JWTCredential struct {
	Headers   JWTHeaders
	Payload   JSONCredential
	signature string
}

func NewJWTCredential(vcc CredentialContents, opts ...CredentialOpt) (Credential, error) {
	options := &credentialOptions{
		proc:       &processor.ProcessorOptions{},
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
		if err := validateCredential(m, options.proc); err != nil {
			return nil, fmt.Errorf("failed to validate credential: %w", err)
		}
	}

	headers := extractClaims(m)
	payload := JSONCredential(m)

	return &JWTCredential{
		Headers: headers,
		Payload: payload,
	}, nil
}

func ParseCredentialJWT(rawJWT string, opts ...CredentialOpt) (Credential, error) {
	m, err := jwt.GetDocumentFromJWT(rawJWT, "vc")
	if err != nil {
		return nil, fmt.Errorf("failed to get document from JWT: %w", err)
	}

	options := &credentialOptions{
		proc:       &processor.ProcessorOptions{},
		validate:   true,
		didBaseURL: config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	if options.validate {
		if err := validateCredential(m, options.proc); err != nil {
			return nil, fmt.Errorf("failed to validate credential: %w", err)
		}
	}

	return &JWTCredential{Headers: extractClaims(m), Payload: JSONCredential(m)}, nil
}

func (j *JWTCredential) Type() CredentialType {
	return CredentialTypeJWT
}

func (j *JWTCredential) AddProof(priv string, opts ...CredentialOpt) error {
	signer := jwt.NewJWTSigner(priv, j.Payload["issuer"].(string))

	jwtString, err := signer.SignDocument((jsonmap.JSONMap)(j.Payload), "vc")
	if err != nil {
		return err
	}
	j.signature = jwtString

	return nil
}

func (j *JWTCredential) GetSigningInput() ([]byte, error) {
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

func (j *JWTCredential) AddCustomProof(proof interface{}) error {
	if _, ok := proof.(string); ok {
		j.signature = proof.(string)
	} else {
		return fmt.Errorf("proof must be a string")
	}

	return nil
}

func (j *JWTCredential) Verify(opts ...CredentialOpt) error {
	options := &credentialOptions{
		proc:       &processor.ProcessorOptions{},
		validate:   true,
		didBaseURL: config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	verifier := jwt.NewJWTVerifier(j.signature)

	err := verifier.VerifyDocument(j.signature, "vc")
	if err != nil {
		return err
	}

	return nil
}

func (j *JWTCredential) Serialize() (interface{}, error) {
	if j.signature == "" {
		return nil, fmt.Errorf("credential must be signed before serialization")
	}
	return j.signature, nil
}

func extractClaims(m jsonmap.JSONMap) JWTHeaders {
	headers := make(JWTHeaders)

	if m["issuer"] != "" {
		headers["iss"] = m["issuer"]
	}
	if m["id"] != "" {
		headers["jti"] = m["id"]
	}
	if m["validFrom"] != nil {
		headers["iat"] = m["validFrom"]
	}
	if m["validUntil"] != nil {
		headers["exp"] = m["validUntil"]
	}
	headers["typ"] = "vc"
	headers["alg"] = "ES256"

	return headers
}
