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

// Deprecated: prefer AddProofByProvider with a signer provider; this legacy signing helper may be removed in a future release.
func (e *JSONPresentation) AddProof(priv string, opts ...PresentationOpt) error {
	defaultSigner, err := signer.NewDefaultProvider(priv)
	if err != nil {
		return fmt.Errorf("failed to create default signer: %w", err)
	}
	return e.AddProofByProvider(defaultSigner, opts...)
}

// AddProofByProvider signs the presentation. The cryptosuite is chosen from the
// bound verification method's key type: secp256k1 → ecdsa-rdfc-2019, RSA →
// JsonWebSignature2020 (alg via AlgorithmProvider, default RS256). The VM is the
// pinned one (WithVerificationMethodKey) or the latest active authentication VM.
//
// A resolver is REQUIRED at signing time — the SDK reads the VM's key type from
// the resolved DID document to pick the cryptosuite, even when the VM is pinned.
func (e *JSONPresentation) AddProofByProvider(provider signer.SignerProvider, opts ...PresentationOpt) error {
	if provider == nil {
		return fmt.Errorf("signer provider cannot be nil")
	}

	if err := e.executeOptions(opts...); err != nil {
		return err
	}

	vm, vmURL, err := e.resolveSigningVMEntry(opts...)
	if err != nil {
		return err
	}

	kind, ok := verificationmethod.VMKeyKind(vm)
	if !ok {
		return fmt.Errorf("verification method %q has an unrecognized key type", vmURL)
	}

	switch kind {
	case verificationmethod.KeySecp256k1:
		return (*jsonmap.JSONMap)(&e.presentationData).AddECDSAProof(provider, vmURL, "authentication")
	case verificationmethod.KeyRSA:
		return (*jsonmap.JSONMap)(&e.presentationData).AddJWSProof(provider, vmURL, "authentication")
	default:
		return fmt.Errorf("verification method %q key kind %v is not supported for presentations (secp256k1 or RSA)", vmURL, kind)
	}
}

// resolveSigningVMEntry resolves the verification method to sign with (pinned
// kid > latest active authentication VM) and returns the entry so the caller
// can read its key type and choose the cryptosuite.
func (e *JSONPresentation) resolveSigningVMEntry(opts ...PresentationOpt) (*verificationmethod.VerificationMethodEntry, string, error) {
	holder, ok := e.presentationData["holder"].(string)
	if !ok || holder == "" {
		return nil, "", fmt.Errorf("holder is missing or invalid")
	}

	options := getOptions(opts...)

	pinned := e.verificationMethodKey
	if options.verificationMethodKey != "" {
		pinned = options.verificationMethodKey
	}

	return verificationmethod.ResolveSigningVM(context.Background(), holder, "authentication", pinned, options.resolver)
}

// resolveVerificationMethodURL returns the full verification method URL for
// a presentation proof. See vc.resolveVerificationMethodURL for resolution
// rules — the only difference is the default purpose (authentication).
//
// Deprecated: prefer AddProofByProvider with a signer provider; this legacy signing helper may be removed in a future release.
func (e *JSONPresentation) GetSigningInput() ([]byte, error) {
	return (*jsonmap.JSONMap)(&e.presentationData).Canonicalize()
}

// Deprecated: prefer AddProofByProvider with a signer provider; this legacy signing helper may be removed in a future release.
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

func (e *JSONPresentation) ExtractField(path string) interface{} {
	return extractFieldFromMap(e.presentationData, path)
}

func (e *JSONPresentation) executeOptions(opts ...PresentationOpt) error {
	options := getOptions(opts...)

	if options.isValidateVC {
		if err := verifyCredentials(PresentationData(e.presentationData), options.resolver); err != nil {
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
