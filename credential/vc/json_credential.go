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
	credentialData CredentialData
}

var _ Credential = (*JSONCredential)(nil)

func NewJSONCredential(vcc CredentialContents, opts ...CredentialOpt) (*JSONCredential, error) {
	m, err := serializeCredentialContents(&vcc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize credential contents: %w", err)
	}

	e := &JSONCredential{
		credentialData: m,
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
	if err := requireCredentialProperties(m); err != nil {
		return nil, err
	}

	e := &JSONCredential{credentialData: m}

	return e, e.executeOptions(opts...)
}

// Required on every credential by VC Data Model 2.0 §4.3, §4.5, §4.7, §4.8.
var requiredCredentialProperties = []string{"@context", "type", "issuer", "credentialSubject"}

// requireCredentialProperties checks presence only; value rules like the v2
// @context URL would reject the VC 1.1 documents this SDK still signs.
func requireCredentialProperties(m CredentialData) error {
	for _, p := range requiredCredentialProperties {
		if isEmptyValue(m[p]) {
			return fmt.Errorf("credential is missing %s", p)
		}
	}
	return nil
}

// isEmptyValue treats absent, null, "" and empty arrays/objects alike.
func isEmptyValue(v interface{}) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case []interface{}:
		return len(t) == 0
	case map[string]interface{}:
		return len(t) == 0
	}
	return false
}

// AddProof signs with a raw P-256 private key (hex scalar).
//
// Deprecated: prefer AddProofByProvider, which keeps the key outside the SDK.
func (e *JSONCredential) AddProof(priv string, opts ...CredentialOpt) error {
	p256Signer, err := signer.NewP256ProviderFromHex(priv)
	if err != nil {
		return fmt.Errorf("failed to create P-256 signer: %w", err)
	}
	return e.AddProofByProvider(p256Signer, opts...)
}

// AddProofByProvider signs with a provider, producing an ecdsa-rdfc-2019 proof
// bound to "<issuer>#key-1" unless WithVerificationMethodKey pins another kid.
// The VM must hold a P-256 key — secp256k1 and RSA are rejected.
//
// A resolver is REQUIRED at signing time: the SDK reads the VM's key type from
// the resolved DID document. Provide one with WithResolver (a default HTTP
// resolver is used otherwise).
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
	case verificationmethod.KeyP256:
		vmPub, err := verificationmethod.ECPubFromVM(vm)
		if err != nil {
			return fmt.Errorf("verification method %q: %w", vmURL, err)
		}
		return (*jsonmap.JSONMap)(&e.credentialData).AddECDSAProof(
			provider, vmURL, "assertionMethod", jsonmap.WithVMPublicKey(vmPub))
	default:
		return fmt.Errorf("unsupported key kind %v for JSON credential", kind)
	}
}

// resolveSigningVMEntry resolves the verification method to sign with and
// returns the entry so the caller can read its key type and choose the
// cryptosuite. Shared with ECDSASDCredential.
func (e *JSONCredential) resolveSigningVMEntry(opts ...CredentialOpt) (*verificationmethod.VerificationMethodEntry, string, error) {
	issuer, ok := jsonmap.DIDFromField(e.credentialData["issuer"])
	if !ok {
		return nil, "", fmt.Errorf("issuer is missing or invalid")
	}

	options := getOptions(opts...)

	return verificationmethod.ResolveSigningVM(context.Background(), issuer, "assertionMethod", options.verificationMethodKey, options.resolver)
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
