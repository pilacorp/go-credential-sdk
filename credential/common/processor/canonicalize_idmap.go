package processor

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	ld "github.com/piprate/json-gold/ld"
)

// CanonicalizeWithIdMap canonicalizes a JSON-LD document with URDNA2015 and
// returns the canonical N-Quads (each ending in "\n") plus a map from each
// input blank-node label to its canonical label, e.g. "_:b0" -> "_:c14n0".
func CanonicalizeWithIdMap(doc map[string]interface{}) (nquads []string, idMap map[string]string, err error) {
	if doc == nil {
		return nil, nil, fmt.Errorf("canonicalize: document is nil")
	}
	defer recoverJSONLD(&err, "canonicalize with id map")
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
	nquads, err := canonicalizeNQuads(doc)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize document: %w", err)
	}

	// An empty dataset would make the signature commit to nothing.
	canonical := []byte(strings.Join(nquads, ""))
	if len(canonical) == 0 {
		return nil, fmt.Errorf("canonicalization produced no N-Quads; the document has no @context or no JSON-LD terms")
	}

	return canonical, nil
}

// canonicalizeNQuads is CanonicalizeWithIdMap without the blank-node map, for
// callers that only hash the result (ecdsa-rdfc-2019, proof configurations).
func canonicalizeNQuads(doc map[string]interface{}) (nquads []string, err error) {
	if doc == nil {
		return nil, fmt.Errorf("canonicalize: document is nil")
	}
	defer recoverJSONLD(&err, "canonicalize")
	// toRDFDataset rather than Normalize, which rebuilds options and drops
	// SafeMode.
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
func CanonicalizeNQuadsWithIdMap(nquads []string) ([]string, map[string]string, error) {
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
	opts := sdOptions()
	opts.Format = "application/n-quads"
	res, err := ld.NewNormalisationAlgorithm(ld.AlgorithmURDNA2015).Main(dataset, opts)
	if err != nil {
		return "", fmt.Errorf("normalize: %w", err)
	}
	nquads, ok := res.(string)
	if !ok {
		return "", fmt.Errorf("unexpected normalize type %T", res)
	}
	return nquads, nil
}

// ErrBlankNodeWork is a dataset refused for the search it would take.
var ErrBlankNodeWork = errors.New("too many interchangeable blank nodes")

// maxBlankNodeWork admits every document in this SDK's tests, which score 0, or 4 per pair
// of interchangeable proofs, and refuses anything shaped like the known attacks
// (a clique of 4 scores over 10^7). A cap on the number of blank nodes cannot
// do this: a 1.4 KB clique of 9 takes URDNA2015 half a minute, and a credential
// with 9 anonymous objects is ordinary.
const maxBlankNodeWork = 10000

// blankNodeWork scores the search URDNA2015 will do. json-gold has no limit,
// and it cannot be stopped from outside.
//
// A blank node whose quads, with blank nodes masked, match no other node's is
// labelled at once and costs nothing. The rest are interchangeable: Hash
// N-Degree Quads tries every ordering of each list of nodes related to one the
// same way, and recurses into the unlabelled ones. So a group of interchangeable
// nodes joined by shared quads scores the product of those orderings over its
// members, times its size squared for the walk each member makes through it.
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

	signatures := make(map[string]string, len(lines))
	sharing := make(map[string]int, len(lines))
	for id, l := range lines {
		sort.Strings(l)
		signatures[id] = strings.Join(l, "\n")
		sharing[signatures[id]]++
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
		for i := 0; i < len(group); i++ {
			// Lists can repeat a node, and json-gold's permutator then yields
			// the distinct orderings: the running multinomial of each list.
			counts := make(map[string]int)
			for _, r := range related[group[i]] {
				list := r.how + signatures[r.id]
				counts[list]++
				counts[list+r.id]++
				orderings = orderings * counts[list] / counts[list+r.id]
				if orderings > maxBlankNodeWork {
					return orderings
				}
				if !seen[r.id] && interchangeable(r.id) {
					seen[r.id] = true
					group = append(group, r.id)
				}
			}
		}
		if cost := orderings * len(group) * len(group); cost > 1 {
			if work += cost; work > maxBlankNodeWork {
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
	defer recoverJSONLD(&err, "expand")
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
	defer recoverJSONLD(&err, "compact")
	out, err := ld.NewJsonLdProcessor().Compact(expanded, ctx, sdOptions())
	if err != nil {
		return nil, fmt.Errorf("compact: %w", err)
	}
	return out, nil
}

// ToRDFNQuads converts a JSON-LD document to N-Quads (each ending in "\n"),
// in toRDF order (not canonicalized).
func ToRDFNQuads(doc interface{}) (result []string, err error) {
	defer recoverJSONLD(&err, "to rdf")
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

// checkExpandedTypes reports `type` values RDF conversion would drop.
func checkExpandedTypes(expanded interface{}) error {
	if dropped := relativeKeywordValues(expanded, "@type", nil); len(dropped) > 0 {
		return fmt.Errorf("json-ld: type %q is not defined by @context and would be dropped, leaving it unsigned", dropped[0])
	}
	return nil
}

// rejectRelativeIDs reports `id` values RDF conversion would drop. Expansion
// resolves @id against the base IRI, and with none set a relative id stays
// relative; ToRDF then skips the node, taking every statement about it (on the
// root: type, issuer, validUntil, ...) out of the signed bytes.
func rejectRelativeIDs(expanded interface{}) error {
	if dropped := relativeKeywordValues(expanded, "@id", nil); len(dropped) > 0 {
		return fmt.Errorf("json-ld: id %q is not an absolute IRI and would be dropped, leaving the node unsigned", dropped[0])
	}
	return nil
}

// relativeKeywordValues collects the string values of keyword (@type or @id)
// that RDF conversion would drop: not a keyword, blank node, or absolute IRI,
// the same test json-gold applies before emitting a quad.
func relativeKeywordValues(v interface{}, keyword string, out []string) []string {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
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
