package vc

import (
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/bbs"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// BBSCredential is a JSON-LD credential signed with the bbs-2023 cryptosuite.
type BBSCredential struct {
	base *JSONCredential
}

var _ Credential = (*BBSCredential)(nil)

// NewBBSCredential builds an unsigned bbs-2023 credential from its contents.
func NewBBSCredential(vcc CredentialContents, opts ...CredentialOpt) (*BBSCredential, error) {
	jc, err := NewJSONCredential(vcc, opts...)
	if err != nil {
		return nil, err
	}
	return &BBSCredential{base: jc}, nil
}

// ParseBBSCredential parses a JSON credential as a bbs-2023 credential.
func ParseBBSCredential(rawJSON []byte, opts ...CredentialOpt) (*BBSCredential, error) {
	jc, err := ParseJSONCredential(rawJSON, opts...)
	if err != nil {
		return nil, err
	}
	return &BBSCredential{base: jc}, nil
}

// AddProofByProvider adds a bbs-2023 base proof, with mandatoryPaths always disclosed on derive.
func (e *BBSCredential) AddProofByProvider(issuerSigner bbs.Signer, mandatoryPaths []string, opts ...CredentialOpt) error {
	if issuerSigner == nil {
		return fmt.Errorf("bbs signer cannot be nil")
	}
	if err := e.base.executeOptions(opts...); err != nil {
		return err
	}
	vmURL, err := e.base.resolveSigningVM(verificationmethod.KeyBLS12381G2, opts...)
	if err != nil {
		return err
	}
	return (*jsonmap.JSONMap)(&e.base.credentialData).AddBBSBaseProof(
		issuerSigner, vmURL, "assertionMethod", dotPathsToPointers(mandatoryPaths))
}

// Derive produces a selectively disclosed credential revealing selectivePaths
// plus the issuer's mandatory paths. Requires WithBBSEngine.
func (e *BBSCredential) Derive(selectivePaths []string, opts ...CredentialOpt) (*JSONCredential, error) {
	options := getOptions(opts...)
	derived, err := (*jsonmap.JSONMap)(&e.base.credentialData).DeriveBBS(
		dotPathsToPointers(selectivePaths),
		options.bbsPresentationHeader,
		options.bbsEngine,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to derive bbs selective disclosure: %w", err)
	}
	return &JSONCredential{
		credentialData:        CredentialData(derived),
		verificationMethodKey: e.base.verificationMethodKey,
	}, nil
}

func (e *BBSCredential) Verify(opts ...CredentialOpt) error { return e.base.Verify(opts...) }
func (e *BBSCredential) Serialize() (any, error)            { return e.base.Serialize() }
func (e *BBSCredential) GetContents() ([]byte, error)       { return e.base.GetContents() }
func (e *BBSCredential) GetType() string                    { return e.base.GetType() }
func (e *BBSCredential) ExtractField(path string) any       { return e.base.ExtractField(path) }
