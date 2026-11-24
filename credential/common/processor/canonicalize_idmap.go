package processor

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/internal/nquads"
	ld "github.com/pilacorp/json-gold/ld"
)

// CanonicalizeWithIdMap canonicalizes a JSON-LD document with URDNA2015 and
// returns the canonical N-Quads (each ending in "\n") plus a map from each
// input blank-node label to its canonical label, e.g. "_:b0" -> "_:c14n0".
func CanonicalizeWithIdMap(doc map[string]interface{}) (nquads []string, idMap map[string]string, err error) {
	if doc == nil {
		return nil, nil, fmt.Errorf("canonicalize: document is nil")
	}
	defer finishJSONLD(&err, "canonicalize with id map")
	dataset, err := toRDFDataset(doc)
	if err != nil {
		return nil, nil, err
	}
	return canonicalizeDatasetWithIdMap(dataset)
}

// toRDFDataset expands doc once and converts the expanded form to an RDF
// dataset. ExpandJSONLD rejects input whose terms or types would be dropped
// (legacy credentials take the CanonicalizeDocument path instead); its output
// is fed straight to the low-level JsonLdApi.ToRDF, which unlike
// JsonLdProcessor.ToRDF does not expand again.
func toRDFDataset(doc map[string]interface{}) (*ld.RDFDataset, error) {
	expanded, err := ExpandJSONLD(doc)
	if err != nil {
		return nil, err
	}
	dataset, err := ld.NewJsonLdApi().ToRDF(expanded, sdOptions())
	if err != nil {
		return nil, fmt.Errorf("canonicalize: to rdf: %w", err)
	}
	return dataset, nil
}

// Canonicalize returns doc's canonical N-Quads as a single byte string.
// Unlike CanonicalizeDocument it keeps JSON number types (xsd:integer /
// xsd:double instead of xsd:string), so a signature over the result commits to
// them, and it fails on undefined terms instead of silently returning nothing.
// Both Data Integrity cryptosuites (ecdsa-rdfc-2019 and ecdsa-sd-2023) hash
// their documents and proof configurations through here.
func Canonicalize(doc map[string]interface{}) ([]byte, error) {
	return nquads.Join(CanonicalizeNQuads(doc))
}

// CanonicalizeNQuads is CanonicalizeWithIdMap without the blank-node map: the
// same URDNA2015 N-Quads, one per element, each ending in "\n".
func CanonicalizeNQuads(doc map[string]interface{}) (nquads []string, err error) {
	if doc == nil {
		return nil, fmt.Errorf("canonicalize: document is nil")
	}
	defer finishJSONLD(&err, "canonicalize")
	// toRDFDataset rather than Normalize, whose two steps cannot stop between
	// them to check the dataset's cost.
	dataset, err := toRDFDataset(doc)
	if err != nil {
		return nil, err
	}

	nqStr, err := normalizeDataset(dataset)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: %w", err)
	}
	return splitNQuadsKeepNL(nqStr), nil
}

// CanonicalizeNQuadsWithIdMap canonicalizes an N-Quads dataset (the form used
// by the selective-disclosure label-replacement step).
func CanonicalizeNQuadsWithIdMap(nquads []string) (canonical []string, idMap map[string]string, err error) {
	defer finishJSONLD(&err, "canonicalize")
	dataset, err := ld.ParseNQuads(strings.Join(nquads, ""))
	if err != nil {
		return nil, nil, fmt.Errorf("canonicalize: parse nquads: %w", err)
	}
	return canonicalizeDatasetWithIdMap(dataset)
}

func canonicalizeDatasetWithIdMap(dataset *ld.RDFDataset) ([]string, map[string]string, error) {
	type slot struct {
		quad *ld.Quad
		idx  int
		orig string
	}
	var slots []slot
	for _, quads := range dataset.Graphs {
		for _, q := range quads {
			for idx := 0; idx < 3; idx++ {
				if n := nodeAt(q, idx); n != nil && ld.IsBlankNode(n) {
					slots = append(slots, slot{q, idx, n.GetValue()})
				}
			}
		}
	}

	nqStr, err := normalizeDataset(dataset)
	if err != nil {
		return nil, nil, fmt.Errorf("canonicalize: %w", err)
	}

	idMap := make(map[string]string, len(slots))
	for _, s := range slots {
		if n := nodeAt(s.quad, s.idx); n != nil {
			idMap[s.orig] = n.GetValue()
		}
	}
	return splitNQuadsKeepNL(nqStr), idMap, nil
}

// normalizeDataset is the one call into URDNA2015, refusing a dataset that
// would take it factorial time. json-gold has no limit of its own.
func normalizeDataset(dataset *ld.RDFDataset) (string, error) {
	if blankNodeWork(dataset) > maxBlankNodeWork {
		return "", fmt.Errorf("normalize: %w", ErrBlankNodeWork)
	}
	return canonicalNQuads(dataset)
}

// canonicalNQuads is what Main returns. Main joins its lines with +=, which is
// quadratic and scores nothing in blankNodeWork, so this writes them itself.
func canonicalNQuads(dataset *ld.RDFDataset) (string, error) {
	na := ld.NewNormalisationAlgorithm(ld.AlgorithmURDNA2015)
	na.Normalize(dataset)
	var b strings.Builder
	serializer := &ld.NQuadRDFSerializer{}
	for _, q := range na.Quads() {
		name := "@default"
		if q.Graph != nil {
			name = q.Graph.GetValue()
		}
		one := &ld.RDFDataset{Graphs: map[string][]*ld.Quad{name: {q}}}
		if err := serializer.SerializeTo(&b, one); err != nil {
			return "", fmt.Errorf("normalize: %w", err)
		}
	}
	return b.String(), nil
}

// ErrBlankNodeWork is a dataset refused for the search it would take.
var ErrBlankNodeWork = errors.New("too many interchangeable blank nodes")

// maxBlankNodeWork admits every document in this SDK's tests, which score 0, or
// 8 per pair of interchangeable proofs, and a list of 102 equal values, and
// refuses anything shaped like the known attacks (a clique of 4 scores 46656).
// A cap on the number of blank nodes cannot do this: a 1.4 KB clique of 9 takes
// URDNA2015 half a minute, and a credential with 9 anonymous objects is ordinary.
const maxBlankNodeWork = 20000

// blankNodeWork scores the search URDNA2015 will do. json-gold has no limit,
// and it cannot be stopped from outside.
//
// A blank node whose quads, with blank nodes masked, match no other node's is
// labelled at once and costs nothing. The rest are interchangeable: Hash
// N-Degree Quads tries every ordering of each list of nodes related to one the
// same way, and recurses into the unlabelled ones. So a group of interchangeable
// nodes joined by shared quads scores the product of those orderings over its
// members, times its size for the walk that starts from each member, times its
// edges to blank nodes for the hashing each walk does. A quad with no other
// blank node is left out: it costs a step of a loop, so a node heavy in literals
// costs what its bytes do. A group of one node with one ordering has no search.
func blankNodeWork(dataset *ld.RDFDataset) int {
	type relation struct{ how, id string }
	lines := make(map[string][]string)
	related := make(map[string][]relation)
	for graph, quads := range dataset.Graphs {
		for _, q := range quads {
			// NewQuad derives the graph node the way json-gold's Normalize does.
			nodes := []ld.Node{q.Subject, q.Object, ld.NewQuad(q.Subject, q.Predicate, q.Object, graph).Graph}
			for _, n := range nodes {
				if !ld.IsBlankNode(n) {
					continue
				}
				id := n.GetValue()
				lines[id] = append(lines[id], fmt.Sprintf("%v %v %v %v", masked(nodes[0], id), q.Predicate, masked(nodes[1], id), masked(nodes[2], id)))
				for i, other := range nodes {
					if ld.IsBlankNode(other) && other.GetValue() != id {
						// Hash Related Blank Node leaves the predicate out for a graph name.
						how := "g"
						if i < 2 {
							how = fmt.Sprint(i, q.Predicate)
						}
						related[id] = append(related[id], relation{how, other.GetValue()})
					}
				}
			}
		}
	}

	// Signatures are interned because a list key below copies one per relation.
	signatures := make(map[string]int, len(lines))
	interned := make(map[string]int, len(lines))
	sharing := make(map[int]int, len(lines))
	for id, l := range lines {
		sort.Strings(l)
		sig := strings.Join(l, "\n")
		n, ok := interned[sig]
		if !ok {
			n = len(interned)
			interned[sig] = n
		}
		signatures[id] = n
		sharing[n]++
	}
	interchangeable := func(id string) bool { return sharing[signatures[id]] > 1 }

	work := 0
	seen := make(map[string]bool, len(lines))
	for start := range lines {
		if seen[start] || !interchangeable(start) {
			continue
		}
		seen[start] = true
		group := []string{start}
		orderings := 1
		edges := 0
		for i := 0; i < len(group); i++ {
			edges += len(related[group[i]])
			// Lists can repeat a node, and json-gold's permutator then yields
			// the distinct orderings: the running multinomial of each list.
			counts := make(map[string]int)
			for _, r := range related[group[i]] {
				list := r.how + "\x00" + strconv.Itoa(signatures[r.id])
				counts[list]++
				counts[list+"\x00"+r.id]++
				orderings = orderings * counts[list] / counts[list+"\x00"+r.id]
				if orderings > maxBlankNodeWork {
					return orderings
				}
				if !seen[r.id] && interchangeable(r.id) {
					seen[r.id] = true
					group = append(group, r.id)
				}
			}
		}
		if search := orderings * len(group); search > 1 {
			if work += search * edges; work > maxBlankNodeWork {
				return work
			}
		}
	}
	return work
}

// masked is the Hash First Degree Quads rule: the blank node under test reads
// as _:a and every other as _:z.
func masked(n ld.Node, id string) interface{} {
	switch {
	case !ld.IsBlankNode(n):
		return n
	case n.GetValue() == id:
		return "_:a"
	default:
		return "_:z"
	}
}

// ExpandJSONLD expands a compact JSON-LD document.
func ExpandJSONLD(doc map[string]interface{}) (result []interface{}, err error) {
	defer finishJSONLD(&err, "expand")
	std, err := standardizeForCanonicalization(doc)
	if err != nil {
		return nil, fmt.Errorf("expand: standardize: %w", err)
	}
	opts := sdOptions()
	if err := limitInlineContexts(opts, std); err != nil {
		return nil, fmt.Errorf("expand: %w", err)
	}
	out, err := ld.NewJsonLdProcessor().Expand(std, opts)
	if err != nil {
		return nil, fmt.Errorf("expand: %w", err)
	}
	// SafeMode above catches dropped properties; these catch dropped types
	// and node identifiers.
	if err := checkExpandedTypes(out); err != nil {
		return nil, err
	}
	if err := rejectRelativeIDs(out); err != nil {
		return nil, err
	}
	return out, nil
}

// CompactJSONLD compacts an expanded JSON-LD document against ctx.
func CompactJSONLD(expanded []interface{}, ctx interface{}) (result map[string]interface{}, err error) {
	defer finishJSONLD(&err, "compact")
	out, err := ld.NewJsonLdProcessor().Compact(expanded, ctx, sdOptions())
	if err != nil {
		return nil, fmt.Errorf("compact: %w", err)
	}
	return out, nil
}

// CompactDocumentForm expands a JSON-LD document body (without proof) and
// compacts it back against the document's own @context, so that every property
// is under the short name the context defines — the compacted document form
// VCDM 2.0 §6.1 requires.
//
// Expansion is permissive (no SafeMode): terms not defined in @context are
// silently dropped rather than causing an error. This is correct because the
// comparison list covers only well-known VC/VP properties that every context
// defines. SafeMode for undefined terms is enforced by most proof suites
// (Canonicalize / ExpandJSONLD), but not by JwtProof2020 or the legacy hex
// proof, so expandPermissive applies limitInlineContexts independently.
//
// If the document has no @context, it is returned unchanged.
func CompactDocumentForm(body map[string]interface{}) (compacted map[string]interface{}, expanded []interface{}, err error) {
	ctx, ok := body["@context"]
	if !ok || ctx == nil {
		return body, nil, nil
	}

	expanded, err = expandPermissive(body)
	if err != nil {
		return nil, nil, fmt.Errorf("compact document form: expand: %w", err)
	}

	compacted, err = CompactJSONLD(expanded, ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("compact document form: compact: %w", err)
	}

	return compacted, expanded, nil
}

// expandPermissive expands a JSON-LD document without SafeMode. Terms not
// defined by @context are dropped instead of causing an error. Used by
// CompactDocumentForm where the caller only compares well-known properties.
//
// limitInlineContexts is applied before json-gold processes the body, to
// enforce the same term-definition budget that ExpandJSONLD and Canonicalize
// use. This matters for proof types that do no JSON-LD work on the document
// (JwtProof2020, the legacy hex proof, JsonWebSignature2020): without the
// limit, a large inline @context could cause excessive allocation or a stack
// overflow.
func expandPermissive(doc map[string]interface{}) (result []interface{}, err error) {
	defer finishJSONLD(&err, "expand")
	std, err := standardizeForCanonicalization(doc)
	if err != nil {
		return nil, fmt.Errorf("expand: standardize: %w", err)
	}
	opts := ld.NewJsonLdOptions("")
	opts.Algorithm = ld.AlgorithmURDNA2015
	opts.DocumentLoader = newContextBudget()
	if err := limitInlineContexts(opts, std); err != nil {
		return nil, fmt.Errorf("expand: %w", err)
	}
	// No SafeMode: undefined terms are dropped rather than refused.
	out, err := ld.NewJsonLdProcessor().Expand(std, opts)
	if err != nil {
		return nil, fmt.Errorf("expand: %w", err)
	}
	return out, nil
}

// ErrNotCompactedForm signals that a verified document's raw JSON is not in
// compacted form for one or more properties the SDK reads by short name.
// A holder rewrote the JSON into an equivalent form (e.g. @nest, full IRI)
// that would hide a property from post-proof checks.
var ErrNotCompactedForm = errors.New("document is not in compacted form")

// VerifyCompactedKeys checks that for each key in keys, the value in raw
// matches the value in compacted after normalizing single-element arrays to
// scalars (JSON-LD @set containers may wrap/unwrap). Keys in presenceOnly are
// compared by presence and element count only — their internal structure is
// verified independently (e.g. each embedded VC in verifiableCredential).
//
// graphKeys maps short names to full IRIs for properties whose JSON-LD context
// uses @container: @graph. The compactor places these under the full IRI
// instead of the short name; VerifyCompactedKeys checks the full IRI as a
// fallback. Pass nil when no graph-container properties are in the list.
func VerifyCompactedKeys(raw, compacted map[string]interface{}, keys []string, presenceOnly map[string]bool, graphKeys map[string]string) error {
	for _, key := range keys {
		rv := raw[key]
		cv := compacted[key]
		// For graph-container properties the JSON-LD compactor may place the
		// value under the full IRI instead of the short name.
		if cv == nil {
			if iri, ok := graphKeys[key]; ok {
				cv = compacted[iri]
			}
		}
		if presenceOnly[key] {
			if !presenceCountEqual(rv, cv) {
				return fmt.Errorf("%w: %s", ErrNotCompactedForm, key)
			}
		} else {
			if !normalizedDeepEqual(rv, cv) {
				return fmt.Errorf("%w: %s", ErrNotCompactedForm, key)
			}
		}
	}
	return nil
}

// normalizedDeepEqual returns true when a and b are equal after recursively
// unwrapping single-element arrays. This handles JSON-LD @set containers
// that wrap/unwrap scalars vs arrays.
func normalizedDeepEqual(a, b interface{}) bool {
	return reflect.DeepEqual(normalizeForCompare(a), normalizeForCompare(b))
}

// normalizeForCompare recursively unwraps single-element arrays so that
// "value" and ["value"] compare equal, as do {"k":"v"} and [{"k":"v"}].
func normalizeForCompare(v interface{}) interface{} {
	switch val := v.(type) {
	case []interface{}:
		if len(val) == 1 {
			return normalizeForCompare(val[0])
		}
		out := make([]interface{}, len(val))
		for i, e := range val {
			out[i] = normalizeForCompare(e)
		}
		return out
	case map[string]interface{}:
		// {"id": X} and "X" are the same node reference; compaction turns the
		// first into the second for @type: @id terms (issuer, holder, credentialSubject).
		if id, ok := val["id"].(string); ok && len(val) == 1 {
			return id
		}
		out := make(map[string]interface{}, len(val))
		for k, e := range val {
			out[k] = normalizeForCompare(e)
		}
		return out
	default:
		return v
	}
}

// presenceCountEqual returns true when both values are nil, or both are
// non-nil with the same element count.
func presenceCountEqual(a, b interface{}) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return elementCount(a) == elementCount(b)
}

func elementCount(v interface{}) int {
	if arr, ok := v.([]interface{}); ok {
		return len(arr)
	}
	return 1
}

// VerifyTermIRIs refuses a document where a second term for the same IRI
// (alias, compact IRI, full IRI, @nest) carries values the short key does not.
// Unlike VerifyCompactedKeys, which compares against a compaction with the
// document's own @context (so the holder can rename a key and its context
// together), VerifyTermIRIs counts the values in the expanded form under each
// key's IRI and requires the raw key to hold the same number.
//
// expanded is the already-expanded body (from CompactDocumentForm); passing it
// avoids a second expansion.
func VerifyTermIRIs(body map[string]interface{}, keys []string, expanded []interface{}) error {
	ctx, ok := body["@context"]
	if !ok || ctx == nil {
		return nil
	}
	if len(expanded) != 1 {
		return fmt.Errorf("%w: expands to %d nodes", ErrNotCompactedForm, len(expanded))
	}
	top, _ := expanded[0].(map[string]interface{})

	// Expand one placeholder per key with the same context and type, to learn
	// which IRI the document's context gives each key.
	probe := map[string]interface{}{"@context": ctx}
	if t, ok := body["type"]; ok {
		probe["type"] = t
	}
	for i, k := range keys {
		if k != "type" {
			probe[k] = map[string]interface{}{"@id": "urn:x-term:" + strconv.Itoa(i)}
		}
	}
	pexp, err := expandPermissive(probe)
	if err != nil {
		return fmt.Errorf("verify term IRIs: probe: %w", err)
	}
	iris := map[string]string{"type": "@type"}
	if len(pexp) == 1 {
		pn, _ := pexp[0].(map[string]interface{})
		for iri, v := range pn {
			if strings.HasPrefix(iri, "@") {
				continue
			}
			if i, ok := findTermProbe(v); ok && i < len(keys) {
				iris[keys[i]] = iri
			}
		}
	}

	for _, k := range keys {
		iri, ok := iris[k]
		if !ok {
			continue
		}
		got := 0
		if arr, ok := top[iri].([]interface{}); ok {
			got = len(arr)
		}
		want := 0
		if body[k] != nil {
			want = elementCount(body[k])
		}
		if got != want {
			return fmt.Errorf("%w: %s", ErrNotCompactedForm, k)
		}
	}
	return nil
}

// findTermProbe finds a "urn:x-term:N" probe value in an expanded JSON-LD
// tree and returns N.
func findTermProbe(v interface{}) (int, bool) {
	switch t := v.(type) {
	case []interface{}:
		for _, e := range t {
			if i, ok := findTermProbe(e); ok {
				return i, true
			}
		}
	case map[string]interface{}:
		if id, ok := t["@id"].(string); ok && strings.HasPrefix(id, "urn:x-term:") {
			i, err := strconv.Atoi(strings.TrimPrefix(id, "urn:x-term:"))
			return i, err == nil
		}
		for _, e := range t {
			if i, ok := findTermProbe(e); ok {
				return i, true
			}
		}
	}
	return 0, false
}

// ToRDFNQuads converts a JSON-LD document to N-Quads (each ending in "\n"),
// in toRDF order (not canonicalized).
func ToRDFNQuads(doc interface{}) (result []string, err error) {
	defer finishJSONLD(&err, "to rdf")
	opts := sdOptions()
	opts.Format = "application/n-quads"
	if err := limitInlineContexts(opts, doc); err != nil {
		return nil, fmt.Errorf("to rdf: %w", err)
	}
	rdf, err := ld.NewJsonLdProcessor().ToRDF(doc, opts)
	if err != nil {
		return nil, fmt.Errorf("to rdf: %w", err)
	}
	s, ok := rdf.(string)
	if !ok {
		return nil, fmt.Errorf("to rdf: unexpected type %T", rdf)
	}
	return splitNQuadsKeepNL(s), nil
}

func sdOptions() *ld.JsonLdOptions {
	opts := ld.NewJsonLdOptions("")
	opts.Algorithm = ld.AlgorithmURDNA2015
	opts.DocumentLoader = newContextBudget()
	// Fail on undefined terms instead of silently dropping them (lossless).
	opts.SafeMode = true
	return opts
}

func nodeAt(q *ld.Quad, idx int) ld.Node {
	switch idx {
	case 0:
		return q.Subject
	case 1:
		return q.Object
	default:
		return q.Graph
	}
}

// splitNQuadsKeepNL splits a serialized N-Quads document into quads, keeping the
// trailing "\n" on each.
func splitNQuadsKeepNL(s string) []string {
	parts := strings.SplitAfter(s, "\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return out
}

// checkExpandedTypes reports `type` values RDF conversion would drop. json-gold's
// SafeMode refuses them too; this check runs first so the error names the type.
func checkExpandedTypes(expanded interface{}) error {
	if dropped := relativeKeywordValues(expanded, "@type", nil); len(dropped) > 0 {
		return fmt.Errorf("json-ld: type %q is not defined by @context and would be dropped, leaving it unsigned", dropped[0])
	}
	return nil
}

// rejectRelativeIDs reports `id` values RDF conversion would drop. Expansion
// resolves @id against the base IRI, and with none set a relative id stays
// relative; ToRDF then skips the node, taking every statement about it (on the
// root: type, issuer, validUntil, ...) out of the signed bytes. json-gold's
// SafeMode refuses such a subject too; this check runs first so the error names
// the id.
func rejectRelativeIDs(expanded interface{}) error {
	if dropped := relativeKeywordValues(expanded, "@id", nil); len(dropped) > 0 {
		return fmt.Errorf("json-ld: id %q is not an absolute IRI and would be dropped, leaving the node unsigned", dropped[0])
	}
	return nil
}

// relativeKeywordValues collects the string values of keyword (@type or @id)
// that RDF conversion would drop: not a keyword, blank node, or absolute IRI,
// the same test json-gold applies before emitting a quad. It walks keys in
// sorted order, so the callers name the same value on every run.
func relativeKeywordValues(v interface{}, keyword string, out []string) []string {
	switch t := v.(type) {
	case map[string]interface{}:
		for _, k := range ld.GetOrderedKeys(t) {
			val := t[k]
			if k != keyword {
				out = relativeKeywordValues(val, keyword, out)
				continue
			}
			for _, kv := range ld.Arrayify(val) {
				if s, ok := kv.(string); ok && ld.IsRelativeIri(s) {
					out = append(out, s)
				}
			}
		}
	case []interface{}:
		for _, e := range t {
			out = relativeKeywordValues(e, keyword, out)
		}
	}
	return out
}
