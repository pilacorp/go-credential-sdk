package vp

import (
	"strings"
	"testing"
)

// A vp+jwt holds its envelopes to the same VCDM 2.0 §4.13 MUSTs as a JSON
// presentation, through checkEnvelopedCredential.
func TestRequireEnvelopedCredentials_AppliesTheEnvelopeMUSTs(t *testing.T) {
	const token = "eyJhbGciOiJFUzI1NiJ9.e30.c2ln"
	for _, tc := range []struct {
		name  string
		entry map[string]interface{}
		wants string
	}{
		{name: "well formed", entry: map[string]interface{}{
			"@context": "https://www.w3.org/ns/credentials/v2", "type": "EnvelopedVerifiableCredential",
			"id": "data:application/vc+jwt," + token}},
		{name: "no @context", entry: map[string]interface{}{
			"type": "EnvelopedVerifiableCredential", "id": "data:application/vc+jwt," + token}, wants: "@context"},
		{name: "id not a data: URL", entry: map[string]interface{}{
			"@context": "https://www.w3.org/ns/credentials/v2", "type": "EnvelopedVerifiableCredential",
			"id": "https://example.com/credential"}, wants: "data: URL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := requireEnvelopedCredentials(PresentationData{"verifiableCredential": []interface{}{tc.entry}})
			if tc.wants == "" {
				if err != nil {
					t.Fatalf("a well-formed envelope was refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wants) {
				t.Fatalf("err = %v, want one mentioning %q", err, tc.wants)
			}
		})
	}
}
