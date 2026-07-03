package ecdsasd

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"sort"

	commoncrypto "github.com/pilacorp/go-credential-sdk/credential/common/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// verifyBaseProof verifies an ecdsa-sd-2023 base proof on a full document,
// against the issuer's public key (P-256 standard, or secp256k1 as a
// non-standard extension). It re-derives the canonical grouping using the HMAC
// key embedded in the proof, then checks the issuer base signature and every
// per-statement ephemeral signature. The per-statement ephemeral keys are always
// P-256 regardless of the issuer curve.
func verifyBaseProof(document map[string]interface{}, proofConfig map[string]interface{}, baseProofValue string, issuerPub *ecdsa.PublicKey) error {
	bp, err := parseBaseProofValue(baseProofValue)
	if err != nil {
		return err
	}
	ephPub, err := verificationmethod.P256PubFromMultikeyBytes(bp.PublicKey)
	if err != nil {
		return fmt.Errorf("ecdsasd: decode ephemeral key: %w", err)
	}

	grouped, err := canonicalizeAndGroup(document, bp.HMACKey, map[string][]string{"mandatory": bp.MandatoryPointers})
	if err != nil {
		return err
	}
	mg := grouped.groups["mandatory"]
	nonMandatory := orderedValues(mg.nonMatching)
	mandatoryHash := hashMandatory(mg.matching)

	proofHash, err := hashProofConfig(proofConfig, document["@context"])
	if err != nil {
		return err
	}

	signData := make([]byte, 0, len(proofHash)+len(bp.PublicKey)+len(mandatoryHash))
	signData = append(signData, proofHash...)
	signData = append(signData, bp.PublicKey...)
	signData = append(signData, mandatoryHash...)
	digest := sha256.Sum256(signData)
	if !commoncrypto.VerifyECDSA(issuerPub, digest[:], bp.BaseSignature) {
		return fmt.Errorf("ecdsasd: issuer base signature invalid")
	}

	if len(bp.Signatures) != len(nonMandatory) {
		return fmt.Errorf("ecdsasd: signature count %d != non-mandatory quads %d", len(bp.Signatures), len(nonMandatory))
	}
	for i, nq := range nonMandatory {
		d := sha256.Sum256([]byte(nq))
		if !commoncrypto.VerifyP256(ephPub, d[:], bp.Signatures[i]) {
			return fmt.Errorf("ecdsasd: non-mandatory statement signature invalid: %s", nq)
		}
	}
	return nil
}

// verifyDerivedProof verifies an ecdsa-sd-2023 derived (disclosure) proof on a
// revealed document, against the issuer's public key (P-256 standard, or
// secp256k1 as a non-standard extension).
func verifyDerivedProof(revealDoc map[string]interface{}, proofConfig map[string]interface{}, derivedProofValue string, issuerPub *ecdsa.PublicKey) error {
	dp, err := parseDisclosureProofValue(derivedProofValue)
	if err != nil {
		return err
	}
	ephPub, err := verificationmethod.P256PubFromMultikeyBytes(dp.PublicKey)
	if err != nil {
		return fmt.Errorf("ecdsasd: decode ephemeral key: %w", err)
	}

	// Canonicalize the revealed document and relabel its canonical blank-node
	// labels to the HMAC labels from the proof, then sort.
	canonicalNQuads, _, err := processor.CanonicalizeWithIdMap(revealDoc)
	if err != nil {
		return fmt.Errorf("ecdsasd: canonicalize reveal doc: %w", err)
	}
	relabeled := relabelBlankNodes(canonicalNQuads, dp.LabelMap)
	sort.Strings(relabeled)

	// Split into mandatory / non-mandatory by the relative mandatory indexes.
	mandatorySet := make(map[int]bool, len(dp.MandatoryIndexes))
	for _, i := range dp.MandatoryIndexes {
		mandatorySet[i] = true
	}
	var mandatory, nonMandatory []string
	for i, nq := range relabeled {
		if mandatorySet[i] {
			mandatory = append(mandatory, nq)
		} else {
			nonMandatory = append(nonMandatory, nq)
		}
	}

	// Recompute hashes.
	proofHash, err := hashProofConfig(proofConfig, revealDoc["@context"])
	if err != nil {
		return err
	}
	var mb []byte
	for _, nq := range mandatory {
		mb = append(mb, nq...)
	}
	mandatoryHashArr := sha256.Sum256(mb)

	// Verify the issuer base signature over proofHash || ephemeralPub || mandatoryHash.
	signData := make([]byte, 0, len(proofHash)+len(dp.PublicKey)+len(mandatoryHashArr))
	signData = append(signData, proofHash...)
	signData = append(signData, dp.PublicKey...)
	signData = append(signData, mandatoryHashArr[:]...)
	digest := sha256.Sum256(signData)
	if !commoncrypto.VerifyECDSA(issuerPub, digest[:], dp.BaseSignature) {
		return fmt.Errorf("ecdsasd: issuer base signature invalid")
	}

	// Verify each revealed non-mandatory quad with the ephemeral key.
	if len(dp.Signatures) != len(nonMandatory) {
		return fmt.Errorf("ecdsasd: signature count %d != non-mandatory quads %d", len(dp.Signatures), len(nonMandatory))
	}
	for i, nq := range nonMandatory {
		d := sha256.Sum256([]byte(nq))
		if !commoncrypto.VerifyP256(ephPub, d[:], dp.Signatures[i]) {
			return fmt.Errorf("ecdsasd: non-mandatory statement signature invalid: %s", nq)
		}
	}
	return nil
}
