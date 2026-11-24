package ecdsasd

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
)

// This file ports the selective-disclosure label primitives from the
// digitalbazaar di-sd-primitives reference (skolemize.js, canonicalize.js,
// group.js) so blank-node identity survives JSON-pointer selection and the
// HMAC-relabeled canonical N-Quads match between the full document and its
// selections.

var (
	urnBnidRe = regexp.MustCompile(`<urn:bnid:([^>]+)>`)
	bnodeRe   = regexp.MustCompile(`_:([^\s]+)`)
)

type skolemLabeler struct {
	prefix string
	random string
	count  int
}

// skolemizeExpanded recursively replaces blank nodes in an expanded JSON-LD
// document with stable `urn:bnid:` IRIs (ports skolemizeExpandedJsonLd).
func skolemizeExpanded(expanded []interface{}, l *skolemLabeler) []interface{} {
	out := make([]interface{}, 0, len(expanded))
	for _, element := range expanded {
		m, isObj := element.(map[string]interface{})
		if !isObj {
			out = append(out, deepCopy(element))
			continue
		}
		if _, hasValue := m["@value"]; hasValue {
			out = append(out, deepCopy(element))
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

// skolemizeCompactJsonLd expands, skolemizes, then re-compacts the document.
// Returns the skolemized expanded and compact forms.
func skolemizeCompactJsonLd(document map[string]interface{}) ([]interface{}, map[string]interface{}, error) {
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

// deskolemizeNQuads converts `<urn:bnid:X>` IRIs back to `_:X` blank nodes.
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

// toDeskolemizedNQuads converts a (skolemized) JSON-LD document to N-Quads with
// blank-node labels restored.
func toDeskolemizedNQuads(document interface{}) ([]string, error) {
	nquads, err := processor.ToRDFNQuads(document)
	if err != nil {
		return nil, err
	}
	return deskolemizeNQuads(nquads), nil
}

// relabelBlankNodes replaces each `_:label` using labelMap[label] -> `_:newLabel`.
func relabelBlankNodes(nquads []string, labelMap map[string]string) []string {
	out := make([]string, len(nquads))
	for i, nq := range nquads {
		out[i] = bnodeRe.ReplaceAllStringFunc(nq, func(match string) string {
			label := match[2:] // strip "_:"
			if nl, ok := labelMap[label]; ok {
				return "_:" + nl
			}
			return match
		})
	}
	return out
}

// createHmacLabelMap maps each input blank-node label to "u"+base64url(HMAC of
// its canonical label) (ports createHmacIdLabelMapFunction).
func createHmacLabelMap(canonicalIdMap map[string]string, hmacKey []byte) map[string]string {
	out := make(map[string]string, len(canonicalIdMap))
	for input, c14n := range canonicalIdMap {
		mac := hmac.New(sha256.New, hmacKey)
		mac.Write([]byte(c14n))
		out[input] = "u" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}
	return out
}

// labelReplacementCanonicalizeNQuads canonicalizes nquads, HMAC-relabels the
// blank nodes, sorts, and returns the relabeled N-Quads plus the label map
// (keyed by input blank-node label).
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
	out := relabelBlankNodes(canonicalNQuads, c14nToNew)
	sort.Strings(out)
	return out, labelMap, nil
}

// selectCanonicalNQuads selects a sub-document by pointers and returns its
// deskolemized N-Quads (input bnode labels) and the HMAC-relabeled N-Quads
// (consistent with the full document).
func selectCanonicalNQuads(compact map[string]interface{}, pointers []string, labelMap map[string]string) (deskolemized, relabeled []string, err error) {
	selection, err := selectJsonLd(compact, pointers)
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
	return deskolemized, relabelBlankNodes(deskolemized, labelMap), nil
}

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

// canonicalizeAndGroup produces the HMAC-relabeled canonical N-Quads for the
// document and, for each named group of JSON pointers, the indexes of the
// matching (selected) and non-matching N-Quads (ports canonicalizeAndGroup).
func canonicalizeAndGroup(document map[string]interface{}, hmacKey []byte, groups map[string][]string) (*groupedCanon, error) {
	expanded, compact, err := skolemizeCompactJsonLd(document)
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

	result := &groupedCanon{
		hmacNQuads:        hmacNQuads,
		labelMap:          labelMap,
		skolemizedCompact: compact,
		groups:            make(map[string]*groupIndexes, len(groups)),
	}
	for name, pointers := range groups {
		deskolemized, selNQuads, err := selectCanonicalNQuads(compact, pointers, labelMap)
		if err != nil {
			return nil, err
		}
		selSet := make(map[string]bool, len(selNQuads))
		for _, nq := range selNQuads {
			selSet[nq] = true
		}
		gi := &groupIndexes{matching: map[int]string{}, nonMatching: map[int]string{}, deskolemizedNQuads: deskolemized}
		for idx, nq := range hmacNQuads {
			if selSet[nq] {
				gi.matching[idx] = nq
			} else {
				gi.nonMatching[idx] = nq
			}
		}
		result.groups[name] = gi
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

func sortedIndexes(m map[int]string) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}
