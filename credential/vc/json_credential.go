package vc

import (
	"encoding/json"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"golang.org/x/sync/errgroup"
)

type JSONCredential struct {
	credentialData     CredentialData
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
	defaultSigner, err := signer.NewDefaultProvider(priv)
	if err != nil {
		return fmt.Errorf("failed to create default signer: %w", err)
	}
	return e.AddProofByProvider(defaultSigner, opts...)
}

func (e *JSONCredential) AddProofByProvider(signerProvider signer.SignerProvider, opts ...CredentialOpt) error {
	if signerProvider == nil {
		return fmt.Errorf("signer provider cannot be nil")
	}

	err := e.executeOptions(opts...)
	if err != nil {
		return err
	}

	issuer, ok := e.credentialData["issuer"].(string)
	if !ok || issuer == "" {
		return fmt.Errorf("issuer is missing or invalid")
	}

	options := getOptions(opts...)

	verificationMethod, err := resolveVerificationMethodURL(issuer, "assertionMethod", e.verificationMethod, options.didBaseURL)
	if err != nil {
		return fmt.Errorf("resolve verification method: %w", err)
	}

	return (*jsonmap.JSONMap)(&e.credentialData).AddECDSAProof(signerProvider, verificationMethod, "assertionMethod", options.didBaseURL)
}

// resolveVerificationMethodURL returns the full verification method URL for
// the proof. Resolution order:
//
//  1. If kid is non-empty, return "<did>#<kid>" (caller-specified pin).
//  2. Otherwise resolve the DID and pick the latest active VM in the given
//     purpose array. This keeps single-VM partners working unchanged
//     (their only VM is #key-1 and it's in assertionMethod) while letting
//     multi-VM callers omit kid and get the most recent rotation.
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
				options.didBaseURL,
				jsonmap.WithStrictProofPurpose(options.strictProofPurpose),
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
