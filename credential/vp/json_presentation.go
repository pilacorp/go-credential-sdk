package vp

import (
	"encoding/json"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
)

type JSONPresentation struct {
	presentationData   PresentationData
	proof              *dto.Proof
	verificationMethod string
}

func NewJSONPresentation(vpc PresentationContents, opts ...PresentationOpt) (Presentation, error) {
	m, err := serializePresentationContents(&vpc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize presentation contents: %w", err)
	}

	options := getOptions(opts...)

	e := &JSONPresentation{presentationData: m, verificationMethod: options.verificationMethodKey}

	return e, e.executeOptions(opts...)
}

func ParseJSONPresentation(rawJSON []byte, opts ...PresentationOpt) (Presentation, error) {
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

	e := &JSONPresentation{presentationData: m}

	return e, e.executeOptions(opts...)
}

func (e *JSONPresentation) AddProof(priv string, opts ...PresentationOpt) error {
	err := e.executeOptions(opts...)
	if err != nil {
		return err
	}

	verificationMethod := fmt.Sprintf("%s#%s", e.presentationData["holder"].(string), e.verificationMethod)

	options := getOptions(opts...)

	return (*jsonmap.JSONMap)(&e.presentationData).AddECDSAProof(priv, verificationMethod, "authentication", options.didBaseURL)
}

func (e *JSONPresentation) GetSigningInput() ([]byte, error) {
	return (*jsonmap.JSONMap)(&e.presentationData).Canonicalize()
}

func (e *JSONPresentation) AddCustomProof(proof *dto.Proof, opts ...PresentationOpt) error {
	if proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}

	err := e.executeOptions(opts...)
	if err != nil {
		return err
	}

	e.proof = proof

	return (*jsonmap.JSONMap)(&e.presentationData).AddCustomProof(e.proof)
}

func (e *JSONPresentation) Verify(opts ...PresentationOpt) error {
	opts = append(opts, WithVerifyProof())

	return e.executeOptions(opts...)
}

func (e *JSONPresentation) Serialize() (interface{}, error) {
	// Check if presentation has proof
	if e.presentationData["proof"] == nil {
		return nil, fmt.Errorf("presentation must have proof before serialization")
	}

	// Return the JSON presentation object directly
	return map[string]interface{}(e.presentationData), nil
}

func (e *JSONPresentation) GetContents() (*PresentationContents, error) {
	contents, err := parsePresentationContents(e.presentationData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse presentation contents: %w", err)
	}
	return &contents, nil
}

func (e *JSONPresentation) GetType() string {
	return "JSON"
}

func (e *JSONPresentation) executeOptions(opts ...PresentationOpt) error {
	options := getOptions(opts...)

	if options.isValidateVC {
		if err := verifyCredentials(PresentationData(e.presentationData)); err != nil {
			return fmt.Errorf("failed to verify presentation: %w", err)
		}
	}

	if options.isVerifyProof {
		isValid, err := (*jsonmap.JSONMap)(&e.presentationData).VerifyProof(options.didBaseURL)
		if err != nil {
			return fmt.Errorf("failed to verify presentation: %w", err)
		}
		if !isValid {
			return fmt.Errorf("invalid proof")
		}
	}

	return nil
}
