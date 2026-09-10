package processor

import (
	"fmt"
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
	std, err := standardizeForCanonicalization(doc)
	if err != nil {
		return nil, nil, fmt.Errorf("canonicalize: standardize: %w", err)
	}
	// Expanded only to reject input whose terms would be dropped; legacy
	// credentials take the CanonicalizeDocument path instead.
	if _, err := ExpandJSONLD(std); err != nil {
		return nil, nil, err
	}
	opts := sdOptions()
	opts.Format = ""
	rdf, err := ld.NewJsonLdProcessor().ToRDF(std, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("canonicalize: to rdf: %w", err)
	}
	dataset, ok := rdf.(*ld.RDFDataset)
	if !ok {
		return nil, nil, fmt.Errorf("canonicalize: unexpected ToRDF type %T", rdf)
	}
	return canonicalizeDatasetWithIdMap(dataset)
}

// CanonicalizeNative returns doc's canonical N-Quads as a single byte string.
// Unlike CanonicalizeDocument it keeps JSON number types (xsd:integer /
// xsd:double instead of xsd:string), so a signature over the result commits to
// them, and it fails on undefined terms instead of silently returning nothing.
// Both Data Integrity cryptosuites (ecdsa-rdfc-2019 and ecdsa-sd-2023) hash
// their documents and proof configurations through here.
func CanonicalizeNative(doc map[string]interface{}) ([]byte, error) {
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
	std, err := standardizeForCanonicalization(doc)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: standardize: %w", err)
	}
	// Expanded only to reject input whose terms would be dropped; legacy
	// credentials take the CanonicalizeDocument path instead.
	if _, err := ExpandJSONLD(std); err != nil {
		return nil, err
	}
	// ToRDF rather than Normalize, which rebuilds options and drops SafeMode.
	opts := sdOptions()
	opts.Format = ""
	rdf, err := ld.NewJsonLdProcessor().ToRDF(std, opts)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: to rdf: %w", err)
	}
	dataset, ok := rdf.(*ld.RDFDataset)
	if !ok {
		return nil, fmt.Errorf("canonicalize: unexpected ToRDF type %T", rdf)
	}

	na := ld.NewNormalisationAlgorithm(ld.AlgorithmURDNA2015)
	nopts := sdOptions()
	nopts.Format = "application/n-quads"
	res, err := na.Main(dataset, nopts)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: normalize: %w", err)
	}
	nqStr, ok := res.(string)
	if !ok {
		return nil, fmt.Errorf("canonicalize: unexpected normalize type %T", res)
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

	na := ld.NewNormalisationAlgorithm(ld.AlgorithmURDNA2015)
	opts := sdOptions()
	opts.Format = "application/n-quads"
	res, err := na.Main(dataset, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("canonicalize: normalize: %w", err)
	}
	nqStr, ok := res.(string)
	if !ok {
		return nil, nil, fmt.Errorf("canonicalize: unexpected normalize type %T", res)
	}

	idMap := make(map[string]string, len(slots))
	for _, s := range slots {
		if n := nodeAt(s.quad, s.idx); n != nil {
			idMap[s.orig] = n.GetValue()
		}
	}
	return splitNQuadsKeepNL(nqStr), idMap, nil
}

// ExpandJSONLD expands a compact JSON-LD document.
func ExpandJSONLD(doc map[string]interface{}) (result []interface{}, err error) {
	defer recoverJSONLD(&err, "expand")
	std, err := standardizeForCanonicalization(doc)
	if err != nil {
		return nil, fmt.Errorf("expand: standardize: %w", err)
	}
	out, err := ld.NewJsonLdProcessor().Expand(std, sdOptions())
	if err != nil {
		return nil, fmt.Errorf("expand: %w", err)
	}
	// SafeMode above catches dropped properties; this catches dropped types.
	if err := checkExpandedTypes(out); err != nil {
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
	opts.DocumentLoader = defaultDocumentLoader
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
	if dropped := relativeTypes(expanded, nil); len(dropped) > 0 {
		return fmt.Errorf("json-ld: type %q is not defined by @context and would be dropped, leaving it unsigned", dropped[0])
	}
	return nil
}

// relativeTypes collects @type values RDF conversion would drop: not a
// keyword, blank node, or absolute IRI.
func relativeTypes(v interface{}, out []string) []string {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			if k != "@type" {
				out = relativeTypes(val, out)
				continue
			}
			for _, tv := range ld.Arrayify(val) {
				s, ok := tv.(string)
				if !ok || strings.HasPrefix(s, "@") || strings.HasPrefix(s, "_:") || ld.IsAbsoluteIri(s) {
					continue
				}
				out = append(out, s)
			}
		}
	case []interface{}:
		for _, e := range t {
			out = relativeTypes(e, out)
		}
	}
	return out
}
