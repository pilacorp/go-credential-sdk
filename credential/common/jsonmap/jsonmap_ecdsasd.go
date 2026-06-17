package jsonmap

import (
	"fmt"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/ecdsasd"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	"github.com/pilacorp/go-credential-sdk/credential/common/util"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// ECDSASD2023 is the cryptosuite identifier for the ecdsa-sd-2023
// selective-disclosure suite (P-256).
const ECDSASD2023 string = "ecdsa-sd-2023"

// AddECDSASDBaseProof adds an ecdsa-sd-2023 base proof to the JSONMap. The body
// is left unchanged (blank nodes preserved); holders can later derive
// selective-disclosure proofs. mandatoryPointers lists claims (as JSON Pointers,
// RFC 6901) the issuer forces to always be disclosed; all other claims become
// selectively disclosable.
func (m *JSONMap) AddECDSASDBaseProof(
	signerProvider signer.SignerProvider,
	verificationMethod, proofPurpose string,
	mandatoryPointers []string,
) error {
	if m == nil {
		return fmt.Errorf("jsonmap: JSONMap is nil")
	}
	if signerProvider == nil {
		return fmt.Errorf("jsonmap: signer provider cannot be nil")
	}
	if verificationMethod == "" {
		return fmt.Errorf("jsonmap: verification method is required")
	}
	if proofPurpose == "" {
		return fmt.Errorf("jsonmap: proof purpose is required")
	}

	proof := dto.Proof{
		Type:               DataIntegrityProof,
		Cryptosuite:        ECDSASD2023,
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: verificationMethod,
		ProofPurpose:       proofPurpose,
	}

	docNoProof, err := m.bodyWithoutProof()
	if err != nil {
		return err
	}

	proofValue, err := ecdsasd.CreateBaseProof(
		docNoProof,
		proofConfigMapFor(proof),
		mandatoryPointers,
		signerProvider,
	)
	if err != nil {
		return fmt.Errorf("jsonmap: create ecdsa-sd base proof: %w", err)
	}

	proof.ProofValue = proofValue
	m.setSingleProof(proof)
	return nil
}

// DeriveECDSASD produces a new JSONMap revealing only the mandatory claims plus
// the claims addressed by selectivePointers (JSON Pointers, RFC 6901), carrying
// a derived ecdsa-sd-2023 proof. The receiver (a credential with an
// ecdsa-sd-2023 base proof) is left unchanged.
func (m *JSONMap) DeriveECDSASD(selectivePointers []string) (JSONMap, error) {
	if m == nil {
		return nil, fmt.Errorf("jsonmap: JSONMap is nil")
	}
	baseProof, ok := m.findECDSASDProof()
	if !ok {
		return nil, fmt.Errorf("jsonmap: credential has no ecdsa-sd-2023 proof to derive from")
	}

	docNoProof, err := m.bodyWithoutProof()
	if err != nil {
		return nil, err
	}

	revealDoc, derivedValue, err := ecdsasd.DeriveProof(docNoProof, baseProof.ProofValue, selectivePointers)
	if err != nil {
		return nil, fmt.Errorf("jsonmap: derive ecdsa-sd proof: %w", err)
	}

	derivedProof := baseProof
	derivedProof.ProofValue = derivedValue

	result := JSONMap(revealDoc)
	result.setSingleProof(derivedProof)
	return result, nil
}

// verifyECDSASDProof verifies an ecdsa-sd-2023 base or derived proof.
func (m *JSONMap) verifyECDSASDProof(doc *verificationmethod.DIDDocument, proof *dto.Proof) (bool, error) {
	vm, err := verificationmethod.FindVerificationMethod(doc, proof.VerificationMethod)
	if err != nil {
		return false, fmt.Errorf("failed to resolve verification method: %w", err)
	}
	if vm.PublicKeyJwk == nil {
		return false, fmt.Errorf("ecdsa-sd-2023 verification method '%s' must publish a P-256 publicKeyJwk", vm.ID)
	}
	pub, err := verificationmethod.P256PubKeyFromJWK(vm.PublicKeyJwk)
	if err != nil {
		return false, fmt.Errorf("parse P-256 jwk: %w", err)
	}

	docNoProof, err := m.bodyWithoutProof()
	if err != nil {
		return false, err
	}

	if err := ecdsasd.VerifyProof(docNoProof, proofConfigMapFor(*proof), proof.ProofValue, pub); err != nil {
		return false, err
	}
	if err := strictPurposeCheck(doc, vm, proof.ProofPurpose, proof.Created); err != nil {
		return false, err
	}
	return true, nil
}

// proofConfigMapFor builds the canonical proof-config map (without proofValue)
// used for the proof hash. Issue and verify must build it identically.
func proofConfigMapFor(p dto.Proof) map[string]interface{} {
	return map[string]interface{}{
		"type":               p.Type,
		"created":            p.Created,
		"verificationMethod": p.VerificationMethod,
		"proofPurpose":       p.ProofPurpose,
		"cryptosuite":        p.Cryptosuite,
	}
}

func (m *JSONMap) findECDSASDProof() (dto.Proof, bool) {
	proof, err := ParseRawToProof(m.getFirstProof())
	if err != nil {
		return dto.Proof{}, false
	}
	if proof.Type == DataIntegrityProof && proof.Cryptosuite == ECDSASD2023 {
		return proof, true
	}
	return dto.Proof{}, false
}

// bodyWithoutProof returns a deep copy of the JSONMap without the proof field.
func (m *JSONMap) bodyWithoutProof() (map[string]interface{}, error) {
	full, err := m.ToMap()
	if err != nil {
		return nil, fmt.Errorf("jsonmap: copy body: %w", err)
	}
	delete(full, proofField)
	return full, nil
}

// setSingleProof sets proof to a single proof object.
func (m *JSONMap) setSingleProof(p dto.Proof) {
	(*m)[proofField] = util.SerializeProofs([]dto.Proof{p})
}
