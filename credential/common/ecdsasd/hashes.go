package ecdsasd

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
)

// hashProofConfig returns SHA-256 of the canonical N-Quads of proofConfig.
// The caller supplies a complete proof configuration — the proof options
// without proofValue, plus the securing document's @context — so both
// cryptosuites build that configuration from one place and only the hashing
// differs. CanonicalizeNative rejects a configuration whose terms no context
// defines, rather than hashing an empty N-Quads set.
func hashProofConfig(proofConfig map[string]interface{}) ([]byte, error) {
	nquads, err := processor.CanonicalizeNative(proofConfig)
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
