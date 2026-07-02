package bbs

import "fmt"

// Cryptosuite is the W3C Data Integrity cryptosuite identifier implemented here.
const Cryptosuite = "bbs-2023"

// Signer signs the BBS message vector for an issuer and exposes the issuer
// public key bytes that must be embedded in the base proof value.
type Signer interface {
	Sign(header []byte, messages [][]byte) ([]byte, error)
	PublicKey() []byte
}

// Engine verifies base signatures and derives/verifies disclosure proofs.
type Engine interface {
	Verify(publicKey, signature, header []byte, messages [][]byte) error
	ProofGen(publicKey, signature, header, presentationHeader []byte, messages [][]byte, disclosedIndexes []int) ([]byte, error)
	ProofVerify(publicKey, proof, header, presentationHeader []byte, disclosedMessages [][]byte, disclosedIndexes []int) error
}

// CreateBaseProof produces a bbs-2023 base proof value over document.
func CreateBaseProof(document map[string]interface{}, proofConfig map[string]interface{}, mandatoryPointers []string, issuerSigner Signer) (string, error) {
	if issuerSigner == nil {
		return "", fmt.Errorf("bbs: issuer signer cannot be nil")
	}
	return createBaseProof(document, proofConfig, mandatoryPointers, issuerSigner)
}

// DeriveProof produces a revealed document plus a derived bbs-2023 proof value.
func DeriveProof(document map[string]interface{}, baseProofValue string, selectivePointers []string, presentationHeader []byte, engine Engine) (map[string]interface{}, string, error) {
	if engine == nil {
		return nil, "", fmt.Errorf("bbs: engine cannot be nil")
	}
	dd, err := createDisclosureData(document, baseProofValue, selectivePointers, presentationHeader, engine)
	if err != nil {
		return nil, "", err
	}
	proofValue, err := serializeDerivedProofValue(dd)
	if err != nil {
		return nil, "", err
	}
	return dd.revealDoc, proofValue, nil
}

// VerifyProof verifies a bbs-2023 base or derived proof. issuerPublicKey is
// required for derived proofs and ignored for base proofs.
func VerifyProof(document map[string]interface{}, proofConfig map[string]interface{}, proofValue string, issuerPublicKey []byte, engine Engine) error {
	if engine == nil {
		return fmt.Errorf("bbs: engine cannot be nil")
	}
	if _, err := decodeProofValue(proofValue, baseProofHeader); err == nil {
		return verifyBaseProof(document, proofConfig, proofValue, engine)
	}
	if _, err := decodeProofValue(proofValue, derivedProofHeader); err == nil {
		return verifyDerivedProof(document, proofConfig, proofValue, issuerPublicKey, engine)
	}
	return fmt.Errorf("bbs: unrecognized proof value header")
}
