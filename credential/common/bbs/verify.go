package bbs

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	"github.com/pilacorp/go-credential-sdk/credential/common/sd"
)

func verifyBaseProof(document map[string]interface{}, proofConfig map[string]interface{}, baseProofValue string, engine Engine) error {
	bp, err := parseBaseProofValue(baseProofValue)
	if err != nil {
		return err
	}

	grouped, err := sd.CanonicalizeAndGroup(document, bp.HMACKey, map[string][]string{"mandatory": bp.MandatoryPointers})
	if err != nil {
		return err
	}
	grouped = normalizeGroupedCanonLabels(grouped)
	mg := grouped.Groups["mandatory"]
	nonMandatory := sd.OrderedValues(mg.NonMatching)
	mandatoryHash := sd.HashMandatory(mg.Matching)
	proofHash, err := sd.HashProofConfig(proofConfig, document["@context"])
	if err != nil {
		return err
	}
	header := append(append([]byte{}, proofHash...), mandatoryHash...)
	if !bytes.Equal(header, bp.BBSHeader) {
		return fmt.Errorf("bbs: header mismatch")
	}
	messages := make([][]byte, len(nonMandatory))
	for i, nq := range nonMandatory {
		messages[i] = []byte(nq)
	}
	return engine.Verify(bp.PublicKey, bp.BBSSignature, header, messages)
}

func verifyDerivedProof(revealDoc map[string]interface{}, proofConfig map[string]interface{}, derivedProofValue string, issuerPublicKey []byte, engine Engine) error {
	dp, err := parseDerivedProofValue(derivedProofValue)
	if err != nil {
		return err
	}
	if len(issuerPublicKey) == 0 {
		return fmt.Errorf("bbs: issuer public key is required for derived proof verification")
	}

	canonicalNQuads, _, err := processor.CanonicalizeWithIdMap(revealDoc)
	if err != nil {
		return fmt.Errorf("bbs: canonicalize reveal doc: %w", err)
	}
	relabeled := sd.RelabelBlankNodes(canonicalNQuads, dp.labelMap)
	sort.Strings(relabeled)

	mandatorySet := make(map[int]bool, len(dp.mandatoryIndexes))
	for _, i := range dp.mandatoryIndexes {
		mandatorySet[i] = true
	}
	var mandatory, disclosedMessages [][]byte
	for i, nq := range relabeled {
		if mandatorySet[i] {
			mandatory = append(mandatory, []byte(nq))
		} else {
			disclosedMessages = append(disclosedMessages, []byte(nq))
		}
	}

	proofHash, err := sd.HashProofConfig(proofConfig, revealDoc["@context"])
	if err != nil {
		return err
	}
	var mb []byte
	for _, nq := range mandatory {
		mb = append(mb, nq...)
	}
	mandatoryHash := sha256.Sum256(mb)
	header := append(append([]byte{}, proofHash...), mandatoryHash[:]...)

	return engine.ProofVerify(
		issuerPublicKey,
		dp.bbsProof,
		header,
		dp.presentationHeader,
		disclosedMessages,
		dp.selectiveIndexes,
	)
}
