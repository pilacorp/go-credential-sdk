package vc

import (
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// ECDSASDCredential is a JSON-LD credential signed with the ecdsa-sd-2023
// cryptosuite. Issuers sign a base proof; holders Derive a reduced credential.
type ECDSASDCredential struct {
	base *JSONCredential
}

var _ Credential = (*ECDSASDCredential)(nil)

// NewECDSASDCredential builds an unsigned ecdsa-sd-2023 credential.
func NewECDSASDCredential(vcc CredentialContents, opts ...CredentialOpt) (*ECDSASDCredential, error) {
	jc, err := NewJSONCredential(vcc, opts...)
	if err != nil {
		return nil, err
	}
	return &ECDSASDCredential{base: jc}, nil
}

// ParseECDSASDCredential parses a JSON-LD credential for ecdsa-sd-2023 use:
// issuers parse a raw document then sign with AddProof/AddProofByProvider;
// holders parse an issued base credential then Derive.
func ParseECDSASDCredential(rawJSON []byte, opts ...CredentialOpt) (*ECDSASDCredential, error) {
	jc, err := ParseJSONCredential(rawJSON, opts...)
	if err != nil {
		return nil, err
	}
	return &ECDSASDCredential{base: jc}, nil
}

// AddProofByProvider signs the credential into an ecdsa-sd-2023 base proof.
// mandatoryPaths (dot-notation) are always disclosed; all other claims become
// selectively disclosable.
//
// The standard issuer key is P-256. As a non-standard extension this SDK also
// accepts a secp256k1 issuer key (it does not interoperate with conformant
// ecdsa-sd-2023 verifiers); to use it, pin a secp256k1 verification method with
// WithVerificationMethodKey, since auto-resolution selects a P-256 VM.
func (e *ECDSASDCredential) AddProofByProvider(signerProvider signer.SignerProvider, mandatoryPaths []string, opts ...CredentialOpt) error {
	if signerProvider == nil {
		return fmt.Errorf("signer provider cannot be nil")
	}
	if err := e.base.executeOptions(opts...); err != nil {
		return err
	}
	vmURL, err := e.base.resolveSigningVM(verificationmethod.KeyP256, opts...)
	if err != nil {
		return err
	}
	return (*jsonmap.JSONMap)(&e.base.credentialData).AddECDSASDBaseProof(
		signerProvider, vmURL, "assertionMethod", dotPathsToPointers(mandatoryPaths))
}

// Derive returns a new credential revealing the mandatory claims plus
// selectivePaths; the rest are removed. The receiver is unchanged. The result
// is a plain *JSONCredential — a derived SD credential cannot be derived again.
func (e *ECDSASDCredential) Derive(selectivePaths []string) (*JSONCredential, error) {
	derived, err := (*jsonmap.JSONMap)(&e.base.credentialData).DeriveECDSASD(dotPathsToPointers(selectivePaths))
	if err != nil {
		return nil, fmt.Errorf("failed to derive selective disclosure: %w", err)
	}
	return &JSONCredential{
		credentialData:        CredentialData(derived),
		verificationMethodKey: e.base.verificationMethodKey,
	}, nil
}

// --- consumer surface: forwarded to the wrapped JSONCredential ---

func (e *ECDSASDCredential) Verify(opts ...CredentialOpt) error { return e.base.Verify(opts...) }

func (e *ECDSASDCredential) Serialize() (any, error) { return e.base.Serialize() }

func (e *ECDSASDCredential) GetContents() ([]byte, error) { return e.base.GetContents() }

func (e *ECDSASDCredential) GetType() string { return e.base.GetType() }

func (e *ECDSASDCredential) ExtractField(path string) any { return e.base.ExtractField(path) }
