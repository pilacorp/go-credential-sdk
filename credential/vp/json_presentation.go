package vp

import (
	"encoding/json"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
)

type JSONPresentation struct {
	presentationData PresentationData
	proof            *dto.Proof
}

func NewJSONPresentation(vpc PresentationContents, opts ...PresentationOpt) (Presentation, error) {
	options := GetOptions(opts...)

	m, err := serializePresentationContents(&vpc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize presentation contents: %w", err)
	}

	if options.isValidateVC {
		if err := verifyCredentials(m); err != nil {
			return nil, fmt.Errorf("failed to validate presentation: %w", err)
		}
	}

	return &JSONPresentation{presentationData: m}, nil
}

func ParseJSONPresentation(rawJSON []byte, opts ...PresentationOpt) (Presentation, error) {
	options := GetOptions(opts...)

	if len(rawJSON) == 0 {
		return nil, fmt.Errorf("JSON string is empty")
	}

	if !isJSONPresentation(rawJSON) {
		return nil, fmt.Errorf("invalid JSON format")
	}

	var m PresentationData
	if err := json.Unmarshal(rawJSON, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal presentation: %w", err)
	}

	if options.isValidateVC {
		if err := verifyCredentials(m); err != nil {
			return nil, fmt.Errorf("failed to validate presentation: %w", err)
		}
	}

	return &JSONPresentation{presentationData: m}, nil
}

func (e *JSONPresentation) AddProof(priv string, opts ...PresentationOpt) error {
	options := GetOptions(opts...)

	if options.isValidateVC {
		if err := verifyCredentials(PresentationData(e.presentationData)); err != nil {
			return fmt.Errorf("failed to validate presentation: %w", err)
		}
	}

	verificationMethod := fmt.Sprintf("%s#%s", e.presentationData["holder"].(string), options.verificationMethodKey)

	return (*jsonmap.JSONMap)(&e.presentationData).AddECDSAProof(priv, verificationMethod, "authentication", options.didBaseURL)
}

func (e *JSONPresentation) GetSigningInput() ([]byte, error) {
	return (*jsonmap.JSONMap)(&e.presentationData).Canonicalize()
}

func (e *JSONPresentation) AddCustomProof(proof *dto.Proof) error {
	if proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}

	e.proof = proof

	return (*jsonmap.JSONMap)(&e.presentationData).AddCustomProof(e.proof)
}

func (e *JSONPresentation) Verify(opts ...PresentationOpt) error {
	options := GetOptions(opts...)

	isValid, err := (*jsonmap.JSONMap)(&e.presentationData).VerifyProof(options.didBaseURL)
	if err != nil {
		return err
	}
	if !isValid {
		return fmt.Errorf("invalid proof")
	}

	// Verify embedded credentials
	if options.isValidateVC {
		if err := verifyCredentials(PresentationData(e.presentationData)); err != nil {
			return fmt.Errorf("failed to verify credentials: %w", err)
		}
	}

	return nil
}

func (e *JSONPresentation) Serialize() (interface{}, error) {
	// Check if presentation has proof
	if e.presentationData["proof"] == nil {
		return nil, fmt.Errorf("presentation must have proof before serialization")
	}

	// Return the JSON presentation object directly
	return map[string]interface{}(e.presentationData), nil
}

func (e *JSONPresentation) GetContents() ([]byte, error) {
	return (*jsonmap.JSONMap)(&e.presentationData).ToJSON()
}

func (e *JSONPresentation) GetType() string {
	return "JSON"
}
