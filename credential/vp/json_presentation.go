package vp

import (
	"encoding/json"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

type JSONPresentation struct {
	presentationData   PresentationData
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
	defaultSigner, err := signer.NewDefaultProvider(priv)
	if err != nil {
		return fmt.Errorf("failed to create default signer: %w", err)
	}
	return e.AddProofByProvider(defaultSigner, opts...)
}

func (e *JSONPresentation) AddProofByProvider(signerProvider signer.SignerProvider, opts ...PresentationOpt) error {
	if signerProvider == nil {
		return fmt.Errorf("signer provider cannot be nil")
	}

	err := e.executeOptions(opts...)
	if err != nil {
		return err
	}

	holder, ok := e.presentationData["holder"].(string)
	if !ok || holder == "" {
		return fmt.Errorf("holder is missing or invalid")
	}

	options := getOptions(opts...)

	verificationMethod, err := resolveVerificationMethodURL(holder, "authentication", e.verificationMethod, options.didBaseURL)
	if err != nil {
		return fmt.Errorf("resolve verification method: %w", err)
	}

	return (*jsonmap.JSONMap)(&e.presentationData).AddECDSAProof(signerProvider, verificationMethod, "authentication", options.didBaseURL)
}

// resolveVerificationMethodURL returns the full verification method URL for
// a presentation proof. See vc.resolveVerificationMethodURL for resolution
// rules — the only difference is the default purpose (authentication).
func resolveVerificationMethodURL(did, purpose, kid, didBaseURL string) (string, error) {
	if kid != "" {
		return fmt.Sprintf("%s#%s", did, kid), nil
	}
	resolver := verificationmethod.NewResolver(didBaseURL)
	_, vmID, err := resolver.GetVerificationMethodByPurpose(did, purpose)
	if err != nil {
		return "", err
	}
	return vmID, nil
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

	return (*jsonmap.JSONMap)(&e.presentationData).AddCustomProof(proof)
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

func (e *JSONPresentation) GetContents() ([]byte, error) {
	return (*jsonmap.JSONMap)(&e.presentationData).ToJSON()
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

	if options.isCheckExpiration {
		if err := checkExpiration(PresentationData(e.presentationData)); err != nil {
			return fmt.Errorf("failed to check expiration: %w", err)
		}
	}

	if options.isVerifyProof {
		isValid, err := (*jsonmap.JSONMap)(&e.presentationData).VerifyProof(
			options.didBaseURL,
			jsonmap.WithStrictProofPurpose(options.strictProofPurpose),
		)
		if err != nil {
			return fmt.Errorf("failed to verify presentation: %w", err)
		}
		if !isValid {
			return fmt.Errorf("invalid proof")
		}
	}

	return nil
}
