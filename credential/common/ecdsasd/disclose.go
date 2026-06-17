package ecdsasd

import (
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
)

type disclosureData struct {
	baseSignature    []byte
	publicKey        []byte
	signatures       [][]byte
	labelMap         map[string]string // verifier c14n label -> HMAC label
	mandatoryIndexes []int             // relative indexes within the revealed set
	revealDoc        map[string]interface{}
}

// createDisclosureData derives the data needed for a disclosure (derived) proof
// from the base proof and the holder's selective pointers. Ports
// ecdsa-sd-2023-cryptosuite createDisclosureData.
func createDisclosureData(document map[string]interface{}, baseProofValue string, selectivePointers []string) (*disclosureData, error) {
	// 1. Parse base proof value.
	bp, err := parseBaseProofValue(baseProofValue)
	if err != nil {
		return nil, err
	}

	// 3-4. Canonicalize and group by mandatory, selective, combined pointers.
	combined := append(append([]string{}, bp.MandatoryPointers...), selectivePointers...)
	grouped, err := canonicalizeAndGroup(document, bp.HMACKey, map[string][]string{
		"mandatory": bp.MandatoryPointers,
		"selective": selectivePointers,
		"combined":  combined,
	})
	if err != nil {
		return nil, err
	}
	mandatoryGroup := grouped.groups["mandatory"]
	selectiveGroup := grouped.groups["selective"]
	combinedGroup := grouped.groups["combined"]

	// 5. Convert absolute mandatory indexes to relative indexes within combined.
	var mandatoryIndexes []int
	for rel, abs := range sortedIndexes(combinedGroup.matching) {
		if _, ok := mandatoryGroup.matching[abs]; ok {
			mandatoryIndexes = append(mandatoryIndexes, rel)
		}
	}

	// 6. Filter base signatures to non-mandatory quads that are selectively
	//    disclosed.
	var filtered [][]byte
	index := 0
	for _, sig := range bp.Signatures {
		for {
			if _, ok := mandatoryGroup.matching[index]; ok {
				index++
				continue
			}
			break
		}
		if _, ok := selectiveGroup.matching[index]; ok {
			filtered = append(filtered, sig)
		}
		index++
	}

	// 7. Reveal document.
	revealDoc, err := selectJsonLd(document, combined)
	if err != nil {
		return nil, err
	}

	// 8. Canonicalize the combined group's deskolemized N-Quads to get the
	//    canonical labels the verifier will see.
	_, rawIDMap, err := processor.CanonicalizeNQuadsWithIdMap(combinedGroup.deskolemizedNQuads)
	if err != nil {
		return nil, err
	}

	// 9. Map verifier canonical labels -> HMAC labels.
	verifierLabelMap := make(map[string]string, len(rawIDMap))
	for inputLabel, c14n := range rawIDMap {
		in := strings.TrimPrefix(inputLabel, "_:")
		verifier := strings.TrimPrefix(c14n, "_:")
		verifierLabelMap[verifier] = grouped.labelMap[in]
	}

	return &disclosureData{
		baseSignature:    bp.BaseSignature,
		publicKey:        bp.PublicKey,
		signatures:       filtered,
		labelMap:         verifierLabelMap,
		mandatoryIndexes: mandatoryIndexes,
		revealDoc:        revealDoc,
	}, nil
}
