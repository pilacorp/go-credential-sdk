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
// An optional issuerPub is the key the verification method publishes; when
// given, the base signature is checked against it. Every mandatory pointer must
// be "" or start with "/", and must match document.
func CreateBaseProof(document map[string]interface{}, proofConfig map[string]interface{}, mandatoryPointers []string, issuerSigner signer.SignerProvider, issuerPub ...*ecdsa.PublicKey) (string, error) {
	if err := checkPointers(document, mandatoryPointers); err != nil {
		return "", err
	}
	var pub *ecdsa.PublicKey
	if len(issuerPub) > 0 {
		pub = issuerPub[0]
	}
	return createBaseProof(document, proofConfig, mandatoryPointers, issuerSigner, pub)
}

// DeriveProof produces a revealed document plus a derived (disclosure) proof
// value, revealing the mandatory statements plus those addressed by
// selectivePointers (JSON Pointers). The base credential is not modified. Every
// selective pointer must be "" or start with "/", and must match document; the
// mandatory pointers stored in the base proof are read as they were issued.
func DeriveProof(document map[string]interface{}, baseProofValue string, selectivePointers []string) (map[string]interface{}, string, error) {
	if err := checkPointers(document, selectivePointers); err != nil {
		return nil, "", err
	}
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

// VerifyBaseProof verifies an ecdsa-sd-2023 base proof. It is the check an
// issuer runs on a proof it still holds. Verifiers use VerifyProof, which
// refuses this header because the base proof carries the HMAC key.
func VerifyBaseProof(document map[string]interface{}, proofConfig map[string]interface{}, proofValue string, issuerPub *ecdsa.PublicKey) error {
	return verifyBaseProof(document, proofConfig, proofValue, issuerPub)
}

// VerifyProof verifies an ecdsa-sd-2023 derived proof against the issuer's
// public key. DI ECDSA 1.0 §3.5.8 accepts only the derived header 0xd95d01.
// A base proof (0xd95d00) carries the HMAC key and is refused here; the issuer
// checks that proof when it is created, inside CreateBaseProof.
func VerifyProof(document map[string]interface{}, proofConfig map[string]interface{}, proofValue string, issuerPub *ecdsa.PublicKey) error {
	if _, err := decodeProofValue(proofValue, baseProofHeader); err == nil {
		return fmt.Errorf("ecdsasd: base proof (header 0xd95d00) cannot be verified; DI ECDSA 1.0 §3.5.8 accepts only a derived proof (header 0xd95d01)")
	}
	if _, err := decodeProofValue(proofValue, derivedProofHeader); err == nil {
		return verifyDerivedProof(document, proofConfig, proofValue, issuerPub)
	}
	return fmt.Errorf("ecdsasd: unrecognized proof value header")
}
