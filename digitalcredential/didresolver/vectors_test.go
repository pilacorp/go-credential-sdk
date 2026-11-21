package didresolver

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// vectorFile holds the shared test vectors both modules read.
type vectorFile struct {
	ReferenceTime string   `json:"reference_time"`
	DID           string   `json:"did"`
	Vectors       []vector `json:"vectors"`
}

type vector struct {
	Name              string         `json:"name"`
	VM                map[string]any `json:"vm"`
	InAssertionMethod bool           `json:"in_assertion_method"`
	ExpectAccepted    bool           `json:"expect_accepted"`
}

// TestSharedVectors reads the same testdata/did_key_rule_vectors.json as the
// root module's didkeys tests, ensuring both modules accept and refuse the
// same keys for the same documents.
func TestSharedVectors(t *testing.T) {
	data, err := os.ReadFile("../../testdata/did_key_rule_vectors.json")
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
			// Build a document the DC parser can read.
			var assertionRefs []any
			if v.InAssertionMethod {
				assertionRefs = []any{v.VM["id"]}
			}
			doc := map[string]any{
				"id":                 vf.DID,
				"verificationMethod": []any{v.VM},
			}
			if assertionRefs != nil {
				doc["assertionMethod"] = assertionRefs
			}

			body, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			r, err := New(Config{Resolver: resolverFunc(func(context.Context, string) ([]byte, error) { return body, nil })})
			if err != nil {
				t.Fatal(err)
			}
			r.now = func() time.Time { return refTime }
			keys, err := r.Keys(context.Background(), vf.DID)
			if err != nil {
				t.Fatal(err)
			}
			got := len(keys) > 0
			if got != v.ExpectAccepted {
				t.Errorf("got accepted=%v (keys=%d); want accepted=%v", got, len(keys), v.ExpectAccepted)
			}
		})
	}
}
