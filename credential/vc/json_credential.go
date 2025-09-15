package vc

import (
	"encoding/json"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
)

type JSONCredential struct {
	presentationData CredentialData
	proof            *dto.Proof
}

func NewJSONCredential(vcc CredentialContents, opts ...CredentialOpt) (Credential, error) {
	options := &credentialOptions{
		isValidateSchema: false,
		didBaseURL:       config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	m, err := serializeCredentialContents(&vcc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize credential contents: %w", err)
	}

	if options.isValidateSchema {
		if err := validateCredential(m); err != nil {
			return nil, fmt.Errorf("failed to validate credential: %w", err)
		}
	}

	return &JSONCredential{presentationData: m}, nil
}

func ParseJSONCredential(rawJSON []byte, opts ...CredentialOpt) (Credential, error) {
	if !isJSONCredential(rawJSON) {
		return nil, fmt.Errorf("invalid JSON format")
	}

	options := &credentialOptions{
		isValidateSchema: false,
		didBaseURL:       config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	if len(rawJSON) == 0 {
		return nil, fmt.Errorf("JSON string is empty")
	}

	var m CredentialData
	if err := json.Unmarshal(rawJSON, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential: %w", err)
	}

	if options.isValidateSchema {
		if err := validateCredential(m); err != nil {
			return nil, fmt.Errorf("failed to validate credential: %w", err)
		}
	}

	return &JSONCredential{presentationData: m}, nil
}

func (e *JSONCredential) AddProof(priv string, opts ...CredentialOpt) error {
	options := &credentialOptions{
		isValidateSchema: false,
		didBaseURL:       config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	return (*jsonmap.JSONMap)(&e.presentationData).AddECDSAProof(priv, e.getVerificationMethod(), "assertionMethod", options.didBaseURL)
}

func (e *JSONCredential) getVerificationMethod() string {
	return fmt.Sprintf("%s#%s", e.presentationData["issuer"].(string), "key-1")
}

func (e *JSONCredential) GetSigningInput() ([]byte, error) {
	return (*jsonmap.JSONMap)(&e.presentationData).Canonicalize()
}

func (e *JSONCredential) AddCustomProof(proof *dto.Proof) error {
	if proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}

	e.proof = proof

	return (*jsonmap.JSONMap)(&e.presentationData).AddCustomProof(e.proof)
}

func (e *JSONCredential) Verify(opts ...CredentialOpt) error {
	options := &credentialOptions{
		isValidateSchema: false,
		didBaseURL:       config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	isValid, err := (*jsonmap.JSONMap)(&e.presentationData).VerifyProof(options.didBaseURL)
	if err != nil {
		return err
	}
	if !isValid {
		return fmt.Errorf("invalid proof")
	}

	if options.isValidateSchema {
		if err := validateCredential(e.presentationData); err != nil {
			return fmt.Errorf("failed to validate credential: %w", err)
		}
	}

	return nil
}

func (e *JSONCredential) Serialize() (interface{}, error) {
	// Check if credential has proof
	if e.presentationData["proof"] == nil {
		return nil, fmt.Errorf("credential must have proof before serialization")
	}

	// Return the JSON credential object directly
	return map[string]interface{}(e.presentationData), nil
}

func (e *JSONCredential) GetContents() ([]byte, error) {
	return (*jsonmap.JSONMap)(&e.presentationData).ToJSON()
}

func (e *JSONCredential) GetType() string {
	return "JSON"
}
