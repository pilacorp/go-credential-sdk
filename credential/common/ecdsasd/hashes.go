package ecdsasd

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
)

// hashProofConfig canonicalizes the proof options (with the document @context
// attached, proofValue removed) and returns SHA-256 of the canonical N-Quads.
// The proof config is string-only by construction, so the string-coercing
// CanonicalizeDocument is safe here; a future numeric proof option would need
// the native-type SD canonicalization path instead.
func hashProofConfig(proofConfig map[string]interface{}, context interface{}) ([]byte, error) {
	cfg := deepCopyMap(proofConfig)
	delete(cfg, "proofValue")
	if context != nil {
		cfg["@context"] = deepCopy(context)
	}
	nquads, err := processor.CanonicalizeDocument(cfg)
	if err != nil {
		return nil, fmt.Errorf("ecdsasd: hash proof config: %w", err)
	}
	h := sha256.Sum256(nquads)
	return h[:], nil
}

// hashMandatory returns SHA-256 of the concatenation of the mandatory N-Quads
// (in ascending index order; each quad already ends in "\n").
func hashMandatory(matching map[int]string) []byte {
	var sb strings.Builder
	for _, i := range sortedIndexes(matching) {
		sb.WriteString(matching[i])
	}
	h := sha256.Sum256([]byte(sb.String()))
	return h[:]
}
