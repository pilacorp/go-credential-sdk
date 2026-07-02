package sd

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	"github.com/pilacorp/go-credential-sdk/credential/common/util"
)

// HashProofConfig canonicalizes proof options and returns SHA-256 of the
// canonical N-Quads.
func HashProofConfig(proofConfig map[string]interface{}, context interface{}) ([]byte, error) {
	cfg := util.DeepCopyMap(proofConfig)
	delete(cfg, "proofValue")
	if context != nil {
		cfg["@context"] = util.DeepCopy(context)
	}
	nquads, err := processor.CanonicalizeDocument(cfg)
	if err != nil {
		return nil, fmt.Errorf("sd: hash proof config: %w", err)
	}
	h := sha256.Sum256(nquads)
	return h[:], nil
}

// HashMandatory returns SHA-256 of the concatenation of mandatory N-Quads.
func HashMandatory(matching map[int]string) []byte {
	var sb strings.Builder
	for _, i := range SortedIndexes(matching) {
		sb.WriteString(matching[i])
	}
	h := sha256.Sum256([]byte(sb.String()))
	return h[:]
}
