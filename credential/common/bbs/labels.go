package bbs

import (
	"regexp"
	"sort"
	"strconv"

	"github.com/pilacorp/go-credential-sdk/credential/common/sd"
)

var bbsBlankNodeRe = regexp.MustCompile(`_:([^\s]+)`)

// normalizeGroupedCanonLabels rewrites the HMAC blank-node labels to compact
// "b<N>" labels (so the proof value stays small) and then RE-SORTS and
// RE-INDEXES the quads by those new labels. The re-sort is essential: the
// verifier reconstructs the disclosed messages by canonicalizing the reveal
// document, relabelling to "b<N>" and sorting — so the issuer side must order
// its signed/disclosed messages by the same "b<N>" order, not by the original
// HMAC-label order.
func normalizeGroupedCanonLabels(grouped *sd.GroupedCanon) *sd.GroupedCanon {
	if grouped == nil {
		return nil
	}

	// Assign compact "b<N>" labels by the sorted order of the HMAC labels, not by
	// their order of appearance. The specification ranks each blank node by its
	// HMAC label and numbers them in that order; appearance order diverges once a
	// node is first seen as an object of an earlier node.
	labelSet := make(map[string]struct{})
	for _, nq := range grouped.HMACNQuads {
		for _, match := range bbsBlankNodeRe.FindAllStringSubmatch(nq, -1) {
			labelSet[match[1]] = struct{}{}
		}
	}
	if len(labelSet) == 0 {
		return grouped
	}

	labels := make([]string, 0, len(labelSet))
	for label := range labelSet {
		labels = append(labels, label)
	}
	sort.Strings(labels)

	relabel := make(map[string]string, len(labels))
	for idx, old := range labels {
		relabel[old] = "b" + strconv.Itoa(idx)
	}

	// Relabel then re-sort so the canonical order matches the order the verifier
	// produces, and assign each quad its position in that sorted order.
	sortedNQuads := sd.RelabelBlankNodes(grouped.HMACNQuads, relabel)
	sort.Strings(sortedNQuads)
	newIndex := make(map[string]int, len(sortedNQuads))
	for i, nq := range sortedNQuads {
		newIndex[nq] = i
	}

	reindex := func(src map[int]string) map[int]string {
		out := make(map[int]string, len(src))
		for _, nq := range src {
			rl := sd.RelabelBlankNodes([]string{nq}, relabel)[0]
			out[newIndex[rl]] = rl
		}
		return out
	}

	out := &sd.GroupedCanon{
		HMACNQuads:        sortedNQuads,
		LabelMap:          make(map[string]string, len(grouped.LabelMap)),
		SkolemizedCompact: grouped.SkolemizedCompact,
		Groups:            make(map[string]*sd.GroupIndexes, len(grouped.Groups)),
	}
	for input, old := range grouped.LabelMap {
		if newLabel, ok := relabel[old]; ok {
			out.LabelMap[input] = newLabel
		} else {
			out.LabelMap[input] = old
		}
	}
	for name, group := range grouped.Groups {
		out.Groups[name] = &sd.GroupIndexes{
			Matching:           reindex(group.Matching),
			NonMatching:        reindex(group.NonMatching),
			DeskolemizedNQuads: append([]string{}, group.DeskolemizedNQuads...),
		}
	}
	return out
}

