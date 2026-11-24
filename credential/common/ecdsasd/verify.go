package ecdsasd

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"sort"

	commoncrypto "github.com/pilacorp/go-credential-sdk/credential/common/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/internal/sdverify"
)

func init() { sdverify.Register(verifyProof) }

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
	ephPub, err := verificationmethod.ECPubFromMultikeyBytes(bp.PublicKey)
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

	proofHash, err := hashProofConfig(proofConfig)
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

// verifyProof refuses every proof value but a derived one, then verifies it.
// VerifyProof and the jsonmap proof-set cache both call it, so the two paths
// refuse the same values with the same errors.
func verifyProof(canon func() ([]string, error), proofConfig map[string]interface{}, proofValue string, issuerPub *ecdsa.PublicKey) error {
	if _, err := decodeProofValue(proofValue, baseProofHeader); err == nil {
		return fmt.Errorf("ecdsasd: a base proof (header 0xd95d00) stays with the holder and cannot be verified; derive a proof from it and verify that (header 0xd95d01)")
	}
	if _, err := decodeProofValue(proofValue, derivedProofHeader); err != nil {
		return fmt.Errorf("ecdsasd: unrecognized proof value header")
	}
	return verifyDerivedProof(canon, proofConfig, proofValue, issuerPub)
}

// canonicalizer returns the canon function verifyDerivedProof expects for a
// document that is verified once.
func canonicalizer(document map[string]interface{}) func() ([]string, error) {
	return func() ([]string, error) { return processor.CanonicalizeNQuads(document) }
}

// verifyDerivedProof verifies an ecdsa-sd-2023 derived (disclosure) proof
// against the issuer's public key (P-256 standard, or secp256k1 as a
// non-standard extension). canon returns the canonical N-Quads of the revealed
// document; it is called only after the proof value has parsed, so a malformed
// proof is refused without canonicalizing.
func verifyDerivedProof(canon func() ([]string, error), proofConfig map[string]interface{}, derivedProofValue string, issuerPub *ecdsa.PublicKey) error {
	dp, err := parseDisclosureProofValue(derivedProofValue)
	if err != nil {
		return err
	}
	ephPub, err := verificationmethod.ECPubFromMultikeyBytes(dp.PublicKey)
	if err != nil {
		return fmt.Errorf("ecdsasd: decode ephemeral key: %w", err)
	}

	// Canonicalize the revealed document and relabel its canonical blank-node
	// labels to the HMAC labels from the proof, then sort.
	canonicalNQuads, err := canon()
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
	proofHash, err := hashProofConfig(proofConfig)
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
