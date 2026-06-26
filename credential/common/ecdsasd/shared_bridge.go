package ecdsasd

import "github.com/pilacorp/go-credential-sdk/credential/common/sd"

type groupIndexes struct {
	matching           map[int]string
	nonMatching        map[int]string
	deskolemizedNQuads []string
}

type groupedCanon struct {
	hmacNQuads        []string
	labelMap          map[string]string
	skolemizedCompact map[string]interface{}
	groups            map[string]*groupIndexes
}

func selectJsonLd(document map[string]interface{}, pointers []string) (map[string]interface{}, error) {
	return sd.SelectJSONLD(document, pointers)
}

func hashProofConfig(proofConfig map[string]interface{}, context interface{}) ([]byte, error) {
	return sd.HashProofConfig(proofConfig, context)
}

func hashMandatory(matching map[int]string) []byte {
	return sd.HashMandatory(matching)
}

func canonicalizeAndGroup(document map[string]interface{}, hmacKey []byte, groups map[string][]string) (*groupedCanon, error) {
	grouped, err := sd.CanonicalizeAndGroup(document, hmacKey, groups)
	if err != nil {
		return nil, err
	}

	compat := &groupedCanon{
		hmacNQuads:        grouped.HMACNQuads,
		labelMap:          grouped.LabelMap,
		skolemizedCompact: grouped.SkolemizedCompact,
		groups:            make(map[string]*groupIndexes, len(grouped.Groups)),
	}

	for name, group := range grouped.Groups {
		compat.groups[name] = &groupIndexes{
			matching:           group.Matching,
			nonMatching:        group.NonMatching,
			deskolemizedNQuads: group.DeskolemizedNQuads,
		}
	}

	return compat, nil
}

func sortedIndexes(m map[int]string) []int {
	return sd.SortedIndexes(m)
}

func orderedValues(m map[int]string) []string {
	return sd.OrderedValues(m)
}
