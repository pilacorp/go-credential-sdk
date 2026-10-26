package sdjwt

// Bounds this package sets; RFC 9901 sets none. Readers bound what an SD-JWT
// from anyone may cost them. Conceal bounds the work of one call for its
// caller; those are not the readers' limits, and Conceal may produce an
// SD-JWT that Split or Recreate refuse (over 1 MiB, or nested deeper than 32).
const (
	maxBytes       = 1 << 20 // bytes of a compact SD-JWT; Split, when reading
	maxDisclosures = 1000    // disclosures of one SD-JWT; Split and Recreate, when reading
	maxDepth       = 32      // nesting of objects and arrays, disclosed values in place; Recreate's recursion
	maxPaths       = 1000    // Conceal's paths, each a walk along its names; checked before generating
	maxMinDigests  = 1000    // ConcealOptions.MinDigests; an array decoy is an insert, so an array costs its length × MinDigests
	maxDigests     = 20000   // objects and arrays × MinDigests, the decoys Conceal may write; checked before generating
)

// nests reports whether v is an object or an array, the values that count
// towards maxDepth.
func nests(v any) bool {
	switch v.(type) {
	case map[string]any, []any:
		return true
	}
	return false
}
