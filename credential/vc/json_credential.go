package vc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"golang.org/x/sync/errgroup"
)

type JSONCredential struct {
	credentialData        CredentialData
	verificationMethodKey string
}

var _ Credential = (*JSONCredential)(nil)

func NewJSONCredential(vcc CredentialContents, opts ...CredentialOpt) (*JSONCredential, error) {
	m, err := serializeCredentialContents(&vcc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize credential contents: %w", err)
	}

	options := getOptions(opts...)

	e := &JSONCredential{
		credentialData:        m,
		verificationMethodKey: options.verificationMethodKey,
	}

	return e, e.executeOptions(opts...)
}

func ParseJSONCredential(rawJSON []byte, opts ...CredentialOpt) (*JSONCredential, error) {
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

//go:deprecated
func (e *JSONCredential) AddProof(priv string, opts ...CredentialOpt) error {
	defaultSigner, err := signer.NewDefaultProvider(priv)
	if err != nil {
		return fmt.Errorf("failed to create default signer: %w", err)
	}
	return e.AddProofByProvider(defaultSigner, opts...)
}

// AddProofByProvider signs with a provider; the cryptosuite is chosen by the
// provider type: SignerProvider (secp256k1) → ecdsa-rdfc-2019, JWSSignerProvider
// (RSA) → JsonWebSignature2020. The verification method is resolved to a key of
// the matching kind, so a DID holding both key types binds the proof to the
// right VM automatically. With several VMs of the same kind, pin one with
// WithVerificationMethodKey.
func (e *JSONCredential) AddProofByProvider(provider any, opts ...CredentialOpt) error {
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
		return (*jsonmap.JSONMap)(&e.credentialData).AddJWSProof(p, vmURL, "assertionMethod")
	case *signer.P256Provider, *signer.P256FuncProvider:
		// P-256 providers structurally satisfy ECDSASignerProvider (they have
		// Sign) but secp256k1 ecdsa-rdfc-2019 is not P-256. P-256 is for
		// ecdsa-sd-2023; route it through ECDSASDCredential instead.
		return fmt.Errorf("P-256 signer is for ecdsa-sd-2023; use ECDSASDCredential.AddProofByProvider, not JSONCredential")
	case signer.ECDSASignerProvider:
		vmURL, err := e.resolveSigningVM(verificationmethod.KeySecp256k1, opts...)
		if err != nil {
			return err
		}
		return (*jsonmap.JSONMap)(&e.credentialData).AddECDSAProof(p, vmURL, "assertionMethod")
	default:
		return fmt.Errorf("unsupported signer provider type: %T", provider)
	}
}

//go:deprecated
func (e *JSONCredential) GetSigningInput() ([]byte, error) {
	return (*jsonmap.JSONMap)(&e.credentialData).Canonicalize()
}

//go:deprecated
func (e *JSONCredential) AddCustomProof(proof *dto.Proof, opts ...CredentialOpt) error {
	if proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}

	err := e.executeOptions(opts...)
	if err != nil {
		return err
	}

	return (*jsonmap.JSONMap)(&e.credentialData).AddCustomProof(proof)
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

func (e *JSONCredential) GetContents() ([]byte, error) {
	return (*jsonmap.JSONMap)(&e.credentialData).ToJSON()
}

func (e *JSONCredential) GetType() string {
	return "JSON"
}

func (e *JSONCredential) ExtractField(path string) interface{} {
	if e.credentialData == nil {
		return nil
	}
	return extractFieldFromMap(e.credentialData, path)
}

func (e *JSONCredential) executeOptions(opts ...CredentialOpt) error {
	options := getOptions(opts...)

	g := &errgroup.Group{}

	if options.isValidateSchema {
		g.Go(func() error {
			if err := validateCredential(e.credentialData, options); err != nil {
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
			isValid, err := (*jsonmap.JSONMap)(&e.credentialData).VerifyProof(
				options.resolver,
				options.proofVerificationMethod,
			)
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

// resolveSigningVM picks the verification method URL: per-call option >
// constructor pin > resolve the latest active VM whose key matches kind (so the
// resolved VM is compatible with the signer's cryptosuite).
func (e *JSONCredential) resolveSigningVM(kind verificationmethod.KeyKind, opts ...CredentialOpt) (string, error) {
	issuer, ok := e.credentialData["issuer"].(string)
	if !ok || issuer == "" {
		return "", fmt.Errorf("issuer is missing or invalid")
	}

	options := getOptions(opts...)

	verificationMethodKey := e.verificationMethodKey
	if options.verificationMethodKey != "" {
		verificationMethodKey = options.verificationMethodKey
	}

	if verificationMethodKey == "" {
		vmURL, err := verificationmethod.ResolveVerificationMethodURLForKey(context.Background(), issuer, "assertionMethod", kind, options.resolver)
		if err != nil {
			return "", fmt.Errorf("resolve verification method: %w", err)
		}
		return vmURL, nil
	}
	return verificationmethod.NormalizeVerificationMethodURL(issuer, verificationMethodKey), nil
}
