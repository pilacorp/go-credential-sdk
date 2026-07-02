package vc

import (
	"context"
	"encoding/hex"
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

func NewJSONCredential(vcc CredentialContents, opts ...CredentialOpt) (Credential, error) {
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
	defaultSigner, err := signer.NewDefaultProvider(priv)
	if err != nil {
		return fmt.Errorf("failed to create default signer: %w", err)
	}
	return e.AddProofByProvider(defaultSigner, opts...)
}

func (e *JSONCredential) AddProofByProvider(provider any, opts ...CredentialOpt) error {
	if provider == nil {
		return fmt.Errorf("signer provider cannot be nil")
	}
	switch p := provider.(type) {
	case signer.JWSSignerProvider:
		vmURL, err := e.resolveVMForSigning(jsonmap.JsonWebKey2020, opts...)
		if err != nil {
			return err
		}
		return (*jsonmap.JSONMap)(&e.credentialData).AddJWSProof(p, vmURL, "assertionMethod")
	case signer.SignerProvider:
		vmURL, err := e.resolveVMForSigning(jsonmap.ECDSASECPKEY, opts...)
		if err != nil {
			return err
		}
		return (*jsonmap.JSONMap)(&e.credentialData).AddECDSAProof(p, vmURL, "assertionMethod")
	default:
		return fmt.Errorf("unsupported provider type: %T", provider)
	}
}

func (e *JSONCredential) resolveVMForSigning(vmType string, opts ...CredentialOpt) (string, error) {
	if err := e.executeOptions(opts...); err != nil {
		return "", err
	}

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
		resolved, err := verificationmethod.ResolveVerificationMethodURLByType(context.Background(), issuer, "assertionMethod", vmType, options.resolver)
		if err != nil {
			return "", fmt.Errorf("resolve verification method: %w", err)
		}
		return resolved, nil
	}
	return verificationmethod.NormalizeVerificationMethodURL(issuer, verificationMethodKey), nil
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

// Hash returns the SHA-256 hash (hex-encoded) of the JSON-LD canonicalized (URDNA2015)
// full credential, including the proof field. The credential must have proof before hashing.
func (e *JSONCredential) Hash() (string, error) {
	if e.credentialData["proof"] == nil {
		return "", fmt.Errorf("credential must have proof before hashing")
	}

	digest, err := (*jsonmap.JSONMap)(&e.credentialData).CanonicalizeFull()
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize credential: %w", err)
	}

	return hex.EncodeToString(digest), nil
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

func (e *JSONCredential) AddSelectiveDisclosures(selectivePaths []string) (Credential, error) {
	return nil, fmt.Errorf("JSON credential does not support selective disclosures")
}
