package vc

import (
	"encoding/json"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
)

type JSONCredentialStruct struct {
	jsonCredential jsonmap.JSONMap
	proof          *dto.Proof
}

func NewJSONCredential(vcc CredentialContents, opts ...CredentialOpt) (Credential, error) {
	options := &credentialOptions{
		validate:   false,
		didBaseURL: config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	m, err := serializeCredentialContents(&vcc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize credential contents: %w", err)
	}

	if options.validate {
		if err := validateCredential(m); err != nil {
			return nil, fmt.Errorf("failed to validate credential: %w", err)
		}
	}

	return &JSONCredentialStruct{jsonCredential: m}, nil
}

func ParseCredentialJSON(rawJSON []byte, opts ...CredentialOpt) (Credential, error) {
	options := &credentialOptions{
		validate:   false,
		didBaseURL: config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	if len(rawJSON) == 0 {
		return nil, fmt.Errorf("JSON string is empty")
	}

	var m jsonmap.JSONMap
	if err := json.Unmarshal(rawJSON, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential: %w", err)
	}

	if options.validate {
		if err := validateCredential(m); err != nil {
			return nil, fmt.Errorf("failed to validate credential: %w", err)
		}
	}

	return &JSONCredentialStruct{jsonCredential: m}, nil
}

func (e *JSONCredentialStruct) AddProof(priv string, opts ...CredentialOpt) error {
	options := &credentialOptions{
		validate:   false,
		didBaseURL: config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	return (*jsonmap.JSONMap)(&e.jsonCredential).AddECDSAProof(priv, e.getVerificationMethod(), "assertionMethod", options.didBaseURL)
}

func (e *JSONCredentialStruct) getVerificationMethod() string {
	return fmt.Sprintf("%s#%s", e.jsonCredential["issuer"].(string), "key-1")
}

func (e *JSONCredentialStruct) GetSigningInput() ([]byte, error) {
	return (*jsonmap.JSONMap)(&e.jsonCredential).Canonicalize()
}

func (e *JSONCredentialStruct) AddCustomProof(proof *dto.Proof) error {
	if proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}

	e.proof = proof

	return (*jsonmap.JSONMap)(&e.jsonCredential).AddCustomProof(e.proof)
}

func (e *JSONCredentialStruct) Verify(opts ...CredentialOpt) error {
	options := &credentialOptions{
		validate:   false,
		didBaseURL: config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	isValid, err := (*jsonmap.JSONMap)(&e.jsonCredential).VerifyProof(options.didBaseURL)
	if err != nil {
		return err
	}
	if !isValid {
		return fmt.Errorf("invalid proof")
	}

	if options.validate {
		if err := validateCredential(jsonmap.JSONMap(e.jsonCredential)); err != nil {
			return fmt.Errorf("failed to validate credential: %w", err)
		}
	}

	return nil
}

func (e *JSONCredentialStruct) Serialize() (interface{}, error) {
	// Check if credential has proof
	if e.jsonCredential["proof"] == nil {
		return nil, fmt.Errorf("credential must have proof before serialization")
	}

	// Return the JSON credential object directly
	return map[string]interface{}(e.jsonCredential), nil
}

func (e *JSONCredentialStruct) GetContents() ([]byte, error) {
	return (*jsonmap.JSONMap)(&e.jsonCredential).ToJSON()
}

func (e *JSONCredentialStruct) GetType() string {
	return "JSON"
}
