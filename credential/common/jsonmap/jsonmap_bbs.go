package jsonmap

import (
	"fmt"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/bbs"
	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// AddBBSBaseProof adds a bbs-2023 base proof to the JSONMap.
func (m *JSONMap) AddBBSBaseProof(
	issuerSigner bbs.Signer,
	verificationMethod, proofPurpose string,
	mandatoryPointers []string,
) error {
	if m == nil {
		return fmt.Errorf("jsonmap: JSONMap is nil")
	}
	if issuerSigner == nil {
		return fmt.Errorf("jsonmap: bbs signer cannot be nil")
	}
	if verificationMethod == "" {
		return fmt.Errorf("jsonmap: verification method is required")
	}
	if proofPurpose == "" {
		return fmt.Errorf("jsonmap: proof purpose is required")
	}
	if _, ok := (*m)["credentialSubject"]; !ok {
		return fmt.Errorf("jsonmap: credential is missing credentialSubject")
	}

	m.ensureDataIntegrityContext()

	proof := dto.Proof{
		Type:               DataIntegrityProof,
		Cryptosuite:        bbs.Cryptosuite,
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: verificationMethod,
		ProofPurpose:       proofPurpose,
	}

	docNoProof, err := m.bodyWithoutProof()
	if err != nil {
		return err
	}
	proofValue, err := bbs.CreateBaseProof(docNoProof, proofConfigMapFor(proof), mandatoryPointers, issuerSigner)
	if err != nil {
		return fmt.Errorf("jsonmap: create bbs base proof: %w", err)
	}
	proof.ProofValue = proofValue
	m.setSingleProof(proof)
	return nil
}

// DeriveBBS derives a bbs-2023 credential with the selected fields revealed.
func (m *JSONMap) DeriveBBS(selectivePointers []string, presentationHeader []byte, engine bbs.Engine) (JSONMap, error) {
	if m == nil {
		return nil, fmt.Errorf("jsonmap: JSONMap is nil")
	}
	if engine == nil {
		return nil, fmt.Errorf("jsonmap: bbs engine cannot be nil")
	}
	baseProof, ok := m.findBBSProof()
	if !ok {
		return nil, fmt.Errorf("jsonmap: credential has no bbs-2023 proof to derive from")
	}

	docNoProof, err := m.bodyWithoutProof()
	if err != nil {
		return nil, err
	}
	revealDoc, derivedValue, err := bbs.DeriveProof(docNoProof, baseProof.ProofValue, selectivePointers, presentationHeader, engine)
	if err != nil {
		return nil, fmt.Errorf("jsonmap: derive bbs proof: %w", err)
	}

	derivedProof := baseProof
	derivedProof.ProofValue = derivedValue

	result := JSONMap(revealDoc)
	result.setSingleProof(derivedProof)
	return result, nil
}

func (m *JSONMap) verifyBBSProof(doc *verificationmethod.DIDDocument, proof *dto.Proof, engine bbs.Engine) (bool, error) {
	if engine == nil {
		return false, fmt.Errorf("bbs-2023 verification requires WithBBSEngine")
	}
	vm, err := verificationmethod.FindVerificationMethod(doc, proof.VerificationMethod)
	if err != nil {
		return false, fmt.Errorf("failed to resolve verification method: %w", err)
	}
	pub, err := verificationmethod.PublicKeyMultibaseBytesFromVM(vm)
	if err != nil {
		return false, fmt.Errorf("decode BLS public key: %w", err)
	}

	docNoProof, err := m.bodyWithoutProof()
	if err != nil {
		return false, err
	}
	if err := bbs.VerifyProof(docNoProof, proofConfigMapFor(*proof), proof.ProofValue, pub, engine); err != nil {
		return false, err
	}
	if err := strictPurposeCheck(doc, vm, proof.ProofPurpose, proof.Created); err != nil {
		return false, err
	}
	return true, nil
}

func (m *JSONMap) findBBSProof() (dto.Proof, bool) {
	proof, err := ParseRawToProof(m.getFirstProof())
	if err != nil {
		return dto.Proof{}, false
	}
	if proof.Type == DataIntegrityProof && proof.Cryptosuite == bbs.Cryptosuite {
		return proof, true
	}
	return dto.Proof{}, false
}
