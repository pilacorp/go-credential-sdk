package ecdsasd

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
)

// Cryptosuite is the W3C Data Integrity cryptosuite identifier implemented here.
const Cryptosuite = "ecdsa-sd-2023"

// CreateBaseProof produces an ecdsa-sd-2023 base proof value over document.
// proofConfig holds the proof options (type/cryptosuite/created/
// verificationMethod/proofPurpose) without proofValue. mandatoryPointers are
// JSON Pointers (RFC 6901) the issuer forces to always be disclosed; every
// other statement becomes selectively disclosable. issuerSigner signs the base
// signature with the issuer's P-256 key. The document body is left unchanged.
func CreateBaseProof(document map[string]interface{}, proofConfig map[string]interface{}, mandatoryPointers []string, issuerSigner signer.SignerProvider) (string, error) {
	return createBaseProof(document, proofConfig, mandatoryPointers, issuerSigner)
}

// DeriveProof produces a revealed document plus a derived (disclosure) proof
// value, revealing the mandatory statements plus those addressed by
// selectivePointers (JSON Pointers). The base credential is not modified.
func DeriveProof(document map[string]interface{}, baseProofValue string, selectivePointers []string) (map[string]interface{}, string, error) {
	dd, err := createDisclosureData(document, baseProofValue, selectivePointers)
	if err != nil {
		return nil, "", err
	}
	proofValue, err := serializeDisclosureProofValue(&specDerivedProof{
		BaseSignature:    dd.baseSignature,
		PublicKey:        dd.publicKey,
		Signatures:       dd.signatures,
		LabelMap:         dd.labelMap,
		MandatoryIndexes: dd.mandatoryIndexes,
	})
	if err != nil {
		return nil, "", err
	}
	return dd.revealDoc, proofValue, nil
}

// VerifyProof verifies an ecdsa-sd-2023 proof against the issuer's P-256 public
// key, routing on the proof value header: base proof (0xd95d00) over the full
// document, or derived proof (0xd95d01) over a revealed document.
func VerifyProof(document map[string]interface{}, proofConfig map[string]interface{}, proofValue string, issuerPub *ecdsa.PublicKey) error {
	if _, err := decodeProofValue(proofValue, baseProofHeader); err == nil {
		return verifyBaseProof(document, proofConfig, proofValue, issuerPub)
	}
	if _, err := decodeProofValue(proofValue, derivedProofHeader); err == nil {
		return verifyDerivedProof(document, proofConfig, proofValue, issuerPub)
	}
	return fmt.Errorf("ecdsasd: unrecognized proof value header")
}
