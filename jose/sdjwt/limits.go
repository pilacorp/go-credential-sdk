package sdjwt

// Bounds on the work Split, Recreate and Conceal do. RFC 9901 sets none; they
// keep untrusted input from costing unbounded memory or recursion. Conceal
// applies the same counts, so an issuer never produces what Recreate refuses.
const (
	maxBytes       = 1 << 20 // a whole compact SD-JWT (Split)
	maxDisclosures = 1000    // Split, Recreate, Conceal
	maxDepth       = 32      // nesting of objects and arrays, every disclosed value in place
	maxMinDigests  = 1000    // ConcealOptions.MinDigests
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
