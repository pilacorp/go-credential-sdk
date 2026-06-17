package vp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

type JSONPresentation struct {
	presentationData      PresentationData
	verificationMethodKey string
}

var _ Presentation = (*JSONPresentation)(nil)

func NewJSONPresentation(vpc PresentationContents, opts ...PresentationOpt) (*JSONPresentation, error) {
	m, err := serializePresentationContents(&vpc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize presentation contents: %w", err)
	}

	options := getOptions(opts...)

	e := &JSONPresentation{presentationData: m, verificationMethodKey: options.verificationMethodKey}

	return e, e.executeOptions(opts...)
}

func ParseJSONPresentation(rawJSON []byte, opts ...PresentationOpt) (*JSONPresentation, error) {
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

//go:deprecated
func (e *JSONPresentation) AddProof(priv string, opts ...PresentationOpt) error {
	defaultSigner, err := signer.NewDefaultProvider(priv)
	if err != nil {
		return fmt.Errorf("failed to create default signer: %w", err)
	}
	return e.AddProofByProvider(defaultSigner, opts...)
}

func (e *JSONPresentation) AddProofByProvider(provider any, opts ...PresentationOpt) error {
	if provider == nil {
		return fmt.Errorf("signer provider cannot be nil")
	}

	if err := e.executeOptions(opts...); err != nil {
		return err
	}

	// Resolve the VM AFTER knowing the provider type, so the chosen VM holds a
	// key compatible with the signer's cryptosuite.
	switch p := provider.(type) {
	case signer.JWSSignerProvider:
		vmURL, err := e.resolveSigningVM(verificationmethod.KeyRSA, opts...)
		if err != nil {
			return err
		}
		return (*jsonmap.JSONMap)(&e.presentationData).AddJWSProof(p, vmURL, "authentication")
	case *signer.P256Provider, *signer.P256FuncProvider:
		// P-256 providers structurally satisfy ECDSASignerProvider but
		// secp256k1 ecdsa-rdfc-2019 is not P-256; reject to avoid a broken proof.
		return fmt.Errorf("P-256 signer is not supported for presentations (use secp256k1 or RSA)")
	case signer.ECDSASignerProvider:
		vmURL, err := e.resolveSigningVM(verificationmethod.KeySecp256k1, opts...)
		if err != nil {
			return err
		}
		return (*jsonmap.JSONMap)(&e.presentationData).AddECDSAProof(p, vmURL, "authentication")
	default:
		return fmt.Errorf("unsupported signer provider type: %T", provider)
	}
}

// resolveSigningVM picks the verification method URL for signing: per-call opt >
// constructor pin > resolve the latest active authentication VM whose key
// matches kind.
func (e *JSONPresentation) resolveSigningVM(kind verificationmethod.KeyKind, opts ...PresentationOpt) (string, error) {
	holder, ok := e.presentationData["holder"].(string)
	if !ok || holder == "" {
		return "", fmt.Errorf("holder is missing or invalid")
	}

	options := getOptions(opts...)

	verificationMethodKey := e.verificationMethodKey
	if options.verificationMethodKey != "" {
		verificationMethodKey = options.verificationMethodKey
	}

	if verificationMethodKey == "" {
		vmURL, err := verificationmethod.ResolveVerificationMethodURLForKey(context.Background(), holder, "authentication", kind, options.resolver)
		if err != nil {
			return "", fmt.Errorf("resolve verification method: %w", err)
		}
		return vmURL, nil
	}
	return verificationmethod.NormalizeVerificationMethodURL(holder, verificationMethodKey), nil
}

// resolveVerificationMethodURL returns the full verification method URL for
// a presentation proof. See vc.resolveVerificationMethodURL for resolution
// rules — the only difference is the default purpose (authentication).
//
//go:deprecated
func (e *JSONPresentation) GetSigningInput() ([]byte, error) {
	return (*jsonmap.JSONMap)(&e.presentationData).Canonicalize()
}

//go:deprecated
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
			options.resolver,
			options.proofVerificationMethod,
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
