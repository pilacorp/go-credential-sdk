// Package nquads holds the step shared by processor.Canonicalize and the
// jsonmap proof-set cache: turning canonical N-Quads into the bytes a Data
// Integrity proof hashes. One copy keeps the two paths failing alike.
package nquads

import (
	"fmt"
	"strings"
)

// Join turns the result of processor.CanonicalizeNQuads into the bytes
// processor.Canonicalize returns, errors included.
func Join(nquads []string, err error) ([]byte, error) {
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
