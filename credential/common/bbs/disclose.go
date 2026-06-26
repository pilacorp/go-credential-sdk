package bbs

import (
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	"github.com/pilacorp/go-credential-sdk/credential/common/sd"
)

func createDisclosureData(document map[string]interface{}, baseProofValue string, selectivePointers []string, presentationHeader []byte, engine Engine) (*disclosureData, error) {
	bp, err := parseBaseProofValue(baseProofValue)
	if err != nil {
		return nil, err
	}

	combined := append(append([]string{}, bp.MandatoryPointers...), selectivePointers...)
	grouped, err := sd.CanonicalizeAndGroup(document, bp.HMACKey, map[string][]string{
		"mandatory": bp.MandatoryPointers,
		"selective": selectivePointers,
		"combined":  combined,
	})
	if err != nil {
		return nil, err
	}
	grouped = normalizeGroupedCanonLabels(grouped)
	mandatoryGroup := grouped.Groups["mandatory"]
	selectiveGroup := grouped.Groups["selective"]
	combinedGroup := grouped.Groups["combined"]

	var mandatoryIndexes []int
	for rel, abs := range sd.SortedIndexes(combinedGroup.Matching) {
		if _, ok := mandatoryGroup.Matching[abs]; ok {
			mandatoryIndexes = append(mandatoryIndexes, rel)
		}
	}

	nonMandatoryIndexes := sd.SortedIndexes(mandatoryGroup.NonMatching)
	absToNonMandatory := make(map[int]int, len(nonMandatoryIndexes))
	for rel, abs := range nonMandatoryIndexes {
		absToNonMandatory[abs] = rel
	}
	var selectiveIndexes []int
	for _, abs := range sd.SortedIndexes(selectiveGroup.Matching) {
		if rel, ok := absToNonMandatory[abs]; ok {
			selectiveIndexes = append(selectiveIndexes, rel)
		}
	}

	nonMandatory := sd.OrderedValues(mandatoryGroup.NonMatching)
	messages := make([][]byte, len(nonMandatory))
	for i, nq := range nonMandatory {
		messages[i] = []byte(nq)
	}

	bbsProof, err := engine.ProofGen(bp.PublicKey, bp.BBSSignature, bp.BBSHeader, presentationHeader, messages, selectiveIndexes)
	if err != nil {
		return nil, err
	}

	revealDoc, err := sd.SelectJSONLD(document, combined)
	if err != nil {
		return nil, err
	}

	_, rawIDMap, err := processor.CanonicalizeNQuadsWithIdMap(combinedGroup.DeskolemizedNQuads)
	if err != nil {
		return nil, err
	}
	verifierLabelMap := make(map[string]string, len(rawIDMap))
	for inputLabel, c14n := range rawIDMap {
		in := strings.TrimPrefix(inputLabel, "_:")
		verifier := strings.TrimPrefix(c14n, "_:")
		verifierLabelMap[verifier] = grouped.LabelMap[in]
	}

	return &disclosureData{
		bbsProof:           bbsProof,
		bbsSignature:       bp.BBSSignature,
		bbsHeader:          bp.BBSHeader,
		publicKey:          bp.PublicKey,
		hmacKey:            bp.HMACKey,
		labelMap:           verifierLabelMap,
		mandatoryIndexes:   mandatoryIndexes,
		selectiveIndexes:   selectiveIndexes,
		presentationHeader: append([]byte{}, presentationHeader...),
		revealDoc:          revealDoc,
	}, nil
}
