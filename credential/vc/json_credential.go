package vc

import (
	"encoding/json"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"golang.org/x/sync/errgroup"
)

type JSONCredential struct {
	credentialData     CredentialData
	proof              *dto.Proof
	verificationMethod string
}

func NewJSONCredential(vcc CredentialContents, opts ...CredentialOpt) (Credential, error) {
	m, err := serializeCredentialContents(&vcc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize credential contents: %w", err)
	}

	options := getOptions(opts...)

	e := &JSONCredential{
		credentialData:     m,
		verificationMethod: options.verificationMethodKey,
	}

	return e, e.executeOptions(opts...)
}

func ParseJSONCredential(rawJSON []byte, opts ...CredentialOpt) (Credential, error) {
	if !isJSONCredential(rawJSON) {
		return nil, fmt.Errorf("invalid JSON format")
	}

	if len(rawJSON) == 0 {
		return nil, fmt.Errorf("JSON string is empty")
	}

	var m CredentialData
	if err := json.Unmarshal(rawJSON, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential: %w", err)
	}

	e := &JSONCredential{credentialData: m}

	return e, e.executeOptions(opts...)
}

func (e *JSONCredential) AddProof(priv string, opts ...CredentialOpt) error {
	err := e.executeOptions(opts...)
	if err != nil {
		return err
	}

	verificationMethod := fmt.Sprintf("%s#%s", e.credentialData["issuer"].(string), e.verificationMethod)

	options := getOptions(opts...)

	return (*jsonmap.JSONMap)(&e.credentialData).AddECDSAProof(priv, verificationMethod, "assertionMethod", options.didBaseURL)
}

func (e *JSONCredential) GetSigningInput() ([]byte, error) {
	return (*jsonmap.JSONMap)(&e.credentialData).Canonicalize()
}

func (e *JSONCredential) AddCustomProof(proof *dto.Proof, opts ...CredentialOpt) error {
	if proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}

	err := e.executeOptions(opts...)
	if err != nil {
		return err
	}

	e.proof = proof

	return (*jsonmap.JSONMap)(&e.credentialData).AddCustomProof(e.proof)
}

func (e *JSONCredential) Verify(opts ...CredentialOpt) error {
	opts = append(opts, WithVerifyProof())

	return e.executeOptions(opts...)
}

func (e *JSONCredential) Serialize() (interface{}, error) {
	// Check if credential has proof
	if e.credentialData["proof"] == nil {
		return nil, fmt.Errorf("credential must have proof before serialization")
	}

	return (*jsonmap.JSONMap)(&e.credentialData).ToMap()
}

func (e *JSONCredential) GetContents() (*CredentialContents, error) {
	contents := &CredentialContents{}
	data, err := (*jsonmap.JSONMap)(&e.credentialData).ToJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize credential contents: %w", err)
	}

	if err := json.Unmarshal(data, &contents); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential contents: %w", err)
	}

	return contents, nil
}

func (e *JSONCredential) GetType() string {
	return "JSON"
}

func (e *JSONCredential) executeOptions(opts ...CredentialOpt) error {
	options := getOptions(opts...)

	g := &errgroup.Group{}

	if options.isValidateSchema {
		g.Go(func() error {
			if err := validateCredential(e.credentialData); err != nil {
				return fmt.Errorf("validate credential: %w", err)
			}

			return nil
		})
	}

	if options.isCheckRevocation {
		g.Go(func() error {
			if err := checkRevocation(e.credentialData); err != nil {
				return fmt.Errorf("check revocation: %w", err)
			}

			return nil
		})
	}

	if options.isVerifyProof {
		g.Go(func() error {
			isValid, err := (*jsonmap.JSONMap)(&e.credentialData).VerifyProof(options.didBaseURL)
			if err != nil {
				return fmt.Errorf("verify proof: %w", err)
			}

			if !isValid {
				return fmt.Errorf("invalid proof")
			}

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("credential verification failed: %w", err)
	}

	// checkExpiration always runs sequentially after parallel validations
	if options.isCheckExpiration {
		if err := checkExpiration(e.credentialData); err != nil {
			return fmt.Errorf("failed to check expiration: %w", err)
		}
	}

	return nil
}
