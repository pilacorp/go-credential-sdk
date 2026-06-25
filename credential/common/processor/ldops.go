package processor

import (
	"fmt"
	"sort"
	"strings"

	"github.com/piprate/json-gold/ld"
)

// ToNQuads serializes a JSON-LD document (compact or expanded) to a sorted slice
// of canonical N-Quad statements. When the document contains no blank nodes the
// sorted N-Quads are already canonical per RDFC-1.0; callers that may have blank
// nodes should canonicalize with an id map instead (see CanonicalizeWithIdMap).
func ToNQuads(input interface{}) ([]string, error) {
	proc, opts := newProcessor()
	opts.Format = "application/n-quads"
	rdf, err := proc.ToRDF(input, opts)
	if err != nil {
		return nil, fmt.Errorf("to nquads: %w", err)
	}
	s, ok := rdf.(string)
	if !ok {
		return nil, fmt.Errorf("to nquads: unexpected RDF output type %T", rdf)
	}
	return SortNQuads(splitNQuads(s)), nil
}

// SortNQuads returns the statements sorted lexicographically (canonical order
// for a blank-node-free dataset).
func SortNQuads(nquads []string) []string {
	out := make([]string, len(nquads))
	copy(out, nquads)
	sort.Strings(out)
	return out
}

func splitNQuads(s string) []string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// newProcessor returns a processor + options pre-wired with the shared caching
// document loader (so embedded W3C contexts resolve offline) and URDNA2015
// (RDFC-1.0) as the canonicalization algorithm.
func newProcessor() (*ld.JsonLdProcessor, *ld.JsonLdOptions) {
	proc := ld.NewJsonLdProcessor()
	opts := ld.NewJsonLdOptions("")
	opts.Algorithm = ld.AlgorithmURDNA2015
	opts.DocumentLoader = defaultDocumentLoader
	// Lossless processing: fail (don't silently drop) on terms that don't
	// expand to an absolute IRI or keyword (W3C VC-DI DATA_LOSS_DETECTION).
	opts.SafeMode = true
	return proc, opts
}
