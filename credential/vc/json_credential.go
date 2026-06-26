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

// Deprecated: prefer AddProofByProvider with a signer provider; this legacy signing helper may be removed in a future release.
func (e *JSONCredential) AddProof(priv string, opts ...CredentialOpt) error {
	defaultSigner, err := signer.NewDefaultProvider(priv)
	if err != nil {
		return fmt.Errorf("failed to create default signer: %w", err)
	}
	return e.AddProofByProvider(defaultSigner, opts...)
}

// AddProofByProvider signs with a provider. The cryptosuite is chosen from the
// bound verification method's key type: secp256k1 → ecdsa-rdfc-2019, RSA →
// JsonWebSignature2020 (alg via AlgorithmProvider, default RS256). The VM is the
// pinned one (WithVerificationMethodKey) or the latest active assertionMethod VM.
//
// A resolver is REQUIRED at signing time — the SDK reads the VM's key type from
// the resolved DID document to pick the cryptosuite, even when the VM is pinned.
// Provide one with WithResolver (a default HTTP resolver is used otherwise).
func (e *JSONCredential) AddProofByProvider(provider signer.SignerProvider, opts ...CredentialOpt) error {
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
		return (*jsonmap.JSONMap)(&e.credentialData).AddECDSAProof(provider, vmURL, "assertionMethod")
	case verificationmethod.KeyRSA:
		return (*jsonmap.JSONMap)(&e.credentialData).AddJWSProof(provider, vmURL, "assertionMethod")
	case verificationmethod.KeyP256:
		return fmt.Errorf("verification method %q holds a P-256 key; use ECDSASDCredential for ecdsa-sd-2023", vmURL)
	default:
		return fmt.Errorf("unsupported key kind %v for JSON credential", kind)
	}
}

// Deprecated: prefer AddProofByProvider with a signer provider; this legacy signing helper may be removed in a future release.
func (e *JSONCredential) GetSigningInput() ([]byte, error) {
	return (*jsonmap.JSONMap)(&e.credentialData).Canonicalize()
}

// Deprecated: prefer AddProofByProvider with a signer provider; this legacy signing helper may be removed in a future release.
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

func (e *JSONCredential) Serialize() (any, error) {
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

func (e *JSONCredential) ExtractField(path string) any {
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
				options.bbsEngine,
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

// resolveSigningVMEntry resolves the verification method to sign with (pinned
// kid > latest active assertionMethod VM) and returns the entry so the caller
// can read its key type and choose the cryptosuite.
func (e *JSONCredential) resolveSigningVMEntry(opts ...CredentialOpt) (*verificationmethod.VerificationMethodEntry, string, error) {
	issuer, ok := issuerDIDFromField(e.credentialData["issuer"])
	if !ok {
		return nil, "", fmt.Errorf("issuer is missing or invalid")
	}

	options := getOptions(opts...)

	pinned := e.verificationMethodKey
	if options.verificationMethodKey != "" {
		pinned = options.verificationMethodKey
	}

	return verificationmethod.ResolveSigningVM(context.Background(), issuer, "assertionMethod", pinned, options.resolver)
}

// resolveSigningVM picks the verification method URL: per-call option >
// constructor pin > resolve the latest active VM whose key matches kind (so the
// resolved VM is compatible with the signer's cryptosuite).
func (e *JSONCredential) resolveSigningVM(kind verificationmethod.KeyKind, opts ...CredentialOpt) (string, error) {
	issuer, ok := issuerDIDFromField(e.credentialData["issuer"])
	if !ok {
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

// issuerDIDFromField extracts the issuer DID from either the string form
// ("did:...") or the W3C object form ({"id": "did:...", ...}), matching what the
// verification path accepts.
func issuerDIDFromField(v interface{}) (string, bool) {
	switch t := v.(type) {
	case string:
		if t != "" {
			return t, true
		}
	case map[string]interface{}:
		if id, ok := t["id"].(string); ok && id != "" {
			return id, true
		}
	}
	return "", false
}
