package sd

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	"github.com/pilacorp/go-credential-sdk/credential/common/util"
)

var (
	urnBnidRe = regexp.MustCompile(`<urn:bnid:([^>]+)>`)
	bnodeRe   = regexp.MustCompile(`_:([^\s]+)`)
)

type skolemLabeler struct {
	prefix string
	random string
	count  int
}

type GroupIndexes struct {
	Matching           map[int]string
	NonMatching        map[int]string
	DeskolemizedNQuads []string
}

type GroupedCanon struct {
	HMACNQuads        []string
	LabelMap          map[string]string
	SkolemizedCompact map[string]interface{}
	Groups            map[string]*GroupIndexes
}

func skolemizeExpanded(expanded []interface{}, l *skolemLabeler) []interface{} {
	out := make([]interface{}, 0, len(expanded))
	for _, element := range expanded {
		m, isObj := element.(map[string]interface{})
		if !isObj {
			out = append(out, util.DeepCopy(element))
			continue
		}
		if _, hasValue := m["@value"]; hasValue {
			out = append(out, util.DeepCopy(element))
			continue
		}
		node := make(map[string]interface{}, len(m))
		for prop, value := range m {
			if arr, ok := value.([]interface{}); ok {
				node[prop] = skolemizeExpanded(arr, l)
			} else {
				node[prop] = skolemizeExpanded([]interface{}{value}, l)[0]
			}
		}
		if id, ok := node["@id"].(string); !ok {
			node["@id"] = fmt.Sprintf("%s_%s_%d", l.prefix, l.random, l.count)
			l.count++
		} else if strings.HasPrefix(id, "_:") {
			node["@id"] = l.prefix + id[2:]
		}
		out = append(out, node)
	}
	return out
}

func skolemizeCompactJSONLD(document map[string]interface{}) ([]interface{}, map[string]interface{}, error) {
	expanded, err := processor.ExpandJSONLD(document)
	if err != nil {
		return nil, nil, err
	}
	random, err := randomHex(16)
	if err != nil {
		return nil, nil, err
	}
	labeler := &skolemLabeler{prefix: "urn:bnid:", random: random}
	skolemized := skolemizeExpanded(expanded, labeler)
	compact, err := processor.CompactJSONLD(skolemized, document["@context"])
	if err != nil {
		return nil, nil, err
	}
	return skolemized, compact, nil
}

func deskolemizeNQuads(nquads []string) []string {
	out := make([]string, len(nquads))
	for i, nq := range nquads {
		if strings.Contains(nq, "<urn:bnid:") {
			out[i] = urnBnidRe.ReplaceAllString(nq, "_:$1")
		} else {
			out[i] = nq
		}
	}
	return out
}

func toDeskolemizedNQuads(document interface{}) ([]string, error) {
	nquads, err := processor.ToRDFNQuads(document)
	if err != nil {
		return nil, err
	}
	return deskolemizeNQuads(nquads), nil
}

// RelabelBlankNodes replaces each `_:label` using labelMap[label] -> `_:newLabel`.
func RelabelBlankNodes(nquads []string, labelMap map[string]string) []string {
	out := make([]string, len(nquads))
	for i, nq := range nquads {
		out[i] = bnodeRe.ReplaceAllStringFunc(nq, func(match string) string {
			label := match[2:]
			if nl, ok := labelMap[label]; ok {
				return "_:" + nl
			}
			return match
		})
	}
	return out
}

func createHmacLabelMap(canonicalIDMap map[string]string, hmacKey []byte) map[string]string {
	out := make(map[string]string, len(canonicalIDMap))
	for input, c14n := range canonicalIDMap {
		mac := hmac.New(sha256.New, hmacKey)
		_, _ = mac.Write([]byte(c14n))
		out[input] = "u" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}
	return out
}

func labelReplacementCanonicalizeNQuads(nquads []string, hmacKey []byte) ([]string, map[string]string, error) {
	canonicalNQuads, rawIDMap, err := processor.CanonicalizeNQuadsWithIdMap(nquads)
	if err != nil {
		return nil, nil, err
	}
	canonicalIDMap := make(map[string]string, len(rawIDMap))
	for k, v := range rawIDMap {
		canonicalIDMap[strings.TrimPrefix(k, "_:")] = strings.TrimPrefix(v, "_:")
	}
	labelMap := createHmacLabelMap(canonicalIDMap, hmacKey)

	c14nToNew := make(map[string]string, len(labelMap))
	for input, newLabel := range labelMap {
		c14nToNew[canonicalIDMap[input]] = newLabel
	}
	out := RelabelBlankNodes(canonicalNQuads, c14nToNew)
	sort.Strings(out)
	return out, labelMap, nil
}

func selectCanonicalNQuads(compact map[string]interface{}, pointers []string, labelMap map[string]string) (deskolemized, relabeled []string, err error) {
	selection, err := SelectJSONLD(compact, pointers)
	if err != nil {
		return nil, nil, err
	}
	if selection == nil {
		return nil, nil, nil
	}
	deskolemized, err = toDeskolemizedNQuads(selection)
	if err != nil {
		return nil, nil, err
	}
	return deskolemized, RelabelBlankNodes(deskolemized, labelMap), nil
}

// CanonicalizeAndGroup returns the relabeled canonical N-Quads plus the index
// partitions for each named pointer group.
func CanonicalizeAndGroup(document map[string]interface{}, hmacKey []byte, groups map[string][]string) (*GroupedCanon, error) {
	expanded, compact, err := skolemizeCompactJSONLD(document)
	if err != nil {
		return nil, err
	}
	deskolemized, err := toDeskolemizedNQuads(expanded)
	if err != nil {
		return nil, err
	}
	hmacNQuads, labelMap, err := labelReplacementCanonicalizeNQuads(deskolemized, hmacKey)
	if err != nil {
		return nil, err
	}

	result := &GroupedCanon{
		HMACNQuads:        hmacNQuads,
		LabelMap:          labelMap,
		SkolemizedCompact: compact,
		Groups:            make(map[string]*GroupIndexes, len(groups)),
	}
	for name, pointers := range groups {
		deskolemizedSel, selNQuads, err := selectCanonicalNQuads(compact, pointers, labelMap)
		if err != nil {
			return nil, err
		}
		selSet := make(map[string]bool, len(selNQuads))
		for _, nq := range selNQuads {
			selSet[nq] = true
		}
		gi := &GroupIndexes{
			Matching:           map[int]string{},
			NonMatching:        map[int]string{},
			DeskolemizedNQuads: deskolemizedSel,
		}
		for idx, nq := range hmacNQuads {
			if selSet[nq] {
				gi.Matching[idx] = nq
			} else {
				gi.NonMatching[idx] = nq
			}
		}
		result.Groups[name] = gi
	}
	return result, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// SortedIndexes returns the sorted keys of a quad-indexed map.
func SortedIndexes(m map[int]string) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// OrderedValues returns values in ascending key order.
func OrderedValues(m map[int]string) []string {
	idxs := SortedIndexes(m)
	out := make([]string, len(idxs))
	for i, k := range idxs {
		out[i] = m[k]
	}
	return out
}
