package vc

import (
	"encoding/json"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
)

type EmbededCredential struct {
	jsonCredential JSONCredential
	proof          *dto.Proof
}

func NewEmbededCredential(vcc CredentialContents) (Credential, error) {
	m, err := serializeCredentialContents(&vcc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize credential contents: %w", err)
	}
	return &EmbededCredential{jsonCredential: JSONCredential(m)}, nil
}

func ParseCredentialEmbedded(rawJSON []byte, opts ...CredentialOpt) (Credential, error) {
	if len(rawJSON) == 0 {
		return nil, fmt.Errorf("JSON string is empty")
	}

	var m jsonmap.JSONMap
	if err := json.Unmarshal(rawJSON, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential: %w", err)
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

	return &EmbededCredential{jsonCredential: JSONCredential(m)}, nil
}

func (e *EmbededCredential) Type() CredentialType {
	return CredentialTypeEmbedded
}

func (e *EmbededCredential) AddProof(priv string, opts ...CredentialOpt) error {
	options := &credentialOptions{
		proc:       &processor.ProcessorOptions{},
		validate:   true,
		didBaseURL: config.BaseURL,
	}
	return (*jsonmap.JSONMap)(&e.jsonCredential).AddECDSAProof(priv, e.getVerificationMethod(), "assertionMethod", options.didBaseURL)
}

func (e *EmbededCredential) getVerificationMethod() string {
	return fmt.Sprintf("%s#%s", e.jsonCredential["issuer"].(string), "key-1")
}

func (e *EmbededCredential) GetSigningInput() ([]byte, error) {
	return (*jsonmap.JSONMap)(&e.jsonCredential).Canonicalize()
}

func (e *EmbededCredential) AddCustomProof(proof interface{}) error {
	if _, ok := proof.(*dto.Proof); ok {
		e.proof = proof.(*dto.Proof)
	} else {
		return fmt.Errorf("proof must be a dto.Proof")
	}
	return (*jsonmap.JSONMap)(&e.jsonCredential).AddCustomProof(e.proof)
}

func (e *EmbededCredential) Verify(opts ...CredentialOpt) error {
	options := &credentialOptions{
		proc:       &processor.ProcessorOptions{},
		validate:   true,
		didBaseURL: config.BaseURL,
	}
	for _, opt := range opts {
		opt(options)
	}

	isValid, err := (*jsonmap.JSONMap)(&e.jsonCredential).VerifyProof(config.BaseURL)
	if err != nil {
		return err
	}
	if !isValid {
		return fmt.Errorf("invalid proof")
	}
	return nil
}

func (e *EmbededCredential) Serialize() (interface{}, error) {
	// Check if credential has proof
	if e.jsonCredential["proof"] == nil {
		return nil, fmt.Errorf("credential must have proof before serialization")
	}

	// Return the JSON credential object directly
	return map[string]interface{}(e.jsonCredential), nil
}
