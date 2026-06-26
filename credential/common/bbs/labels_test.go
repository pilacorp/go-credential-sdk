package bbs

import (
	"reflect"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/sd"
)

func TestNormalizeGroupedCanonLabels_RewritesHMACLabelsToBLabels(t *testing.T) {
	grouped := &sd.GroupedCanon{
		HMACNQuads: []string{
			"_:uSecond <p> _:uFirst .\n",
			"_:uFirst <q> \"x\" .\n",
		},
		LabelMap: map[string]string{
			"in0": "uFirst",
			"in1": "uSecond",
		},
		Groups: map[string]*sd.GroupIndexes{
			"mandatory": {
				Matching: map[int]string{
					0: "_:uSecond <p> _:uFirst .\n",
				},
				NonMatching: map[int]string{
					1: "_:uFirst <q> \"x\" .\n",
				},
			},
		},
	}

	got := normalizeGroupedCanonLabels(grouped)

	// Compact labels are assigned by the sorted rank of the HMAC labels, not by
	// order of appearance: "uFirst" < "uSecond" so uFirst->b0 and uSecond->b1.
	// The quads are then re-sorted by the new labels.
	if !reflect.DeepEqual(got.HMACNQuads, []string{
		"_:b0 <q> \"x\" .\n",
		"_:b1 <p> _:b0 .\n",
	}) {
		t.Fatalf("normalized HMACNQuads = %#v", got.HMACNQuads)
	}
	if !reflect.DeepEqual(got.LabelMap, map[string]string{
		"in0": "b0",
		"in1": "b1",
	}) {
		t.Fatalf("normalized LabelMap = %#v", got.LabelMap)
	}
	if got.Groups["mandatory"].Matching[1] != "_:b1 <p> _:b0 .\n" {
		t.Fatalf("normalized matching quad = %q", got.Groups["mandatory"].Matching[1])
	}
	if got.Groups["mandatory"].NonMatching[0] != "_:b0 <q> \"x\" .\n" {
		t.Fatalf("normalized nonMatching quad = %q", got.Groups["mandatory"].NonMatching[0])
	}
}
