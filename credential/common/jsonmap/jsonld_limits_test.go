package jsonmap

import (
	"errors"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
)

// The proof configuration carries every member of the proof, under the
// document's context, so its canonicalization takes the limits too.
func TestProofHashData_LimitsProofMembers(t *testing.T) {
	m := JSONMap{"@context": []interface{}{"https://www.w3.org/ns/credentials/v2", map[string]interface{}{
		"p": map[string]interface{}{"@id": "https://ex.org/p", "@context": map[string]interface{}{"q": "https://ex.org/q"}},
	}}}
	items := make([]interface{}, 20)
	for i := range items {
		items[i] = map[string]interface{}{"q": "v"}
	}
	proof := &dto.Proof{Type: DataIntegrityProof, Cryptosuite: ECDSARDFC2019, ProofPurpose: "assertionMethod",
		VerificationMethod: "did:example:i#key-1", Created: "2026-01-01T00:00:00Z",
		Extra: map[string]interface{}{"p": items}}
	_, err := m.proofHashData(make([]byte, 32), proof, processor.JSONLDLimits{MaxScopedContextUses: 10})
	if !errors.Is(err, processor.ErrTooManyScopedContextUses) {
		t.Fatalf("err = %v, want ErrTooManyScopedContextUses", err)
	}
}
