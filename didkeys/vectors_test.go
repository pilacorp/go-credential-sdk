package didkeys

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// vectorFile holds the shared test vectors both modules read.
type vectorFile struct {
	ReferenceTime string   `json:"reference_time"`
	DID           string   `json:"did"`
	Vectors       []vector `json:"vectors"`
}

type vector struct {
	Name              string                 `json:"name"`
	VM                map[string]interface{} `json:"vm"`
	InAssertionMethod bool                   `json:"in_assertion_method"`
	ExpectAccepted    bool                   `json:"expect_accepted"`
}

// TestSharedVectors reads testdata/did_key_rule_vectors.json and asserts the
// same accept/refuse outcomes as the digitalcredential/didresolver tests do.
func TestSharedVectors(t *testing.T) {
	data, err := os.ReadFile("../testdata/did_key_rule_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatal(err)
	}

	refTime, err := time.Parse(time.RFC3339, vf.ReferenceTime)
	if err != nil {
		t.Fatal(err)
	}

	for _, v := range vf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			vm := vmFromMap(t, v.VM, vf.DID)

			var assertionRefs []string
			if v.InAssertionMethod {
				assertionRefs = []string{vm.ID}
			}
			doc := &verificationmethod.DIDDocument{
				ID:                 vf.DID,
				VerificationMethod: []verificationmethod.VerificationMethodEntry{vm},
				AssertionMethod:    assertionRefs,
			}
			provider := &staticResolver{
				docs: map[string]*verificationmethod.DIDDocument{vf.DID: doc},
			}
			r, err := NewResolver(provider)
			if err != nil {
				t.Fatal(err)
			}
			r.(*resolver).clock = func() time.Time { return refTime }
			keys, err := r.Keys(context.Background(), vf.DID)
			if err != nil {
				t.Fatal(err)
			}
			got := len(keys) > 0
			if got != v.ExpectAccepted {
				t.Errorf("got accepted=%v; want %v", got, v.ExpectAccepted)
			}
		})
	}
}

// vmFromMap converts a JSON map to a VerificationMethodEntry.
func vmFromMap(t *testing.T, m map[string]interface{}, did string) verificationmethod.VerificationMethodEntry {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	// Unmarshal through the struct, but handle revoked/expires times manually
	// since they may be absent.
	var vm verificationmethod.VerificationMethodEntry
	if err := json.Unmarshal(raw, &vm); err != nil {
		t.Fatal(err)
	}
	// json.Unmarshal handles *time.Time fields with RFC3339 format.
	// Let's also parse revoked and expires manually from the map for safety.
	if rs, ok := m["revoked"].(string); ok && rs != "" {
		tt, err := time.Parse(time.RFC3339, rs)
		if err != nil {
			t.Fatal(err)
		}
		vm.Revoked = &tt
	}
	if es, ok := m["expires"].(string); ok && es != "" {
		tt, err := time.Parse(time.RFC3339, es)
		if err != nil {
			t.Fatal(err)
		}
		vm.Expires = &tt
	}
	return vm
}
