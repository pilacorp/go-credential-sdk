package processor

import (
	"strings"
	"testing"
)

// #186. credentials/v2 declares verifiableCredential with "@container": "@graph",
// so an embedded credential's statements belong in a named graph whose name is
// a blank node, and the presentation points at that graph (JSON-LD 1.1, W3C
// Recommendation 2020-07-16, §4.9.1 Graph Containers). Signing them in the
// default graph gave signatures other implementations could not verify.
func TestCanonicalize_EmbeddedCredentialIsANamedGraph(t *testing.T) {
	const v2 = "https://www.w3.org/ns/credentials/v2"
	doc := map[string]interface{}{
		"@context": []interface{}{v2},
		"type":     "VerifiablePresentation",
		"verifiableCredential": []interface{}{map[string]interface{}{
			"@context":          []interface{}{v2},
			"id":                "urn:uuid:embedded-vc",
			"type":              "VerifiableCredential",
			"issuer":            "did:example:issuer",
			"credentialSubject": map[string]interface{}{"id": "did:example:subject"},
		}},
	}
	out, err := Canonicalize(doc)
	if err != nil {
		t.Fatal(err)
	}

	var graph string
	for _, q := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.Contains(q, "<https://www.w3.org/2018/credentials#verifiableCredential>") {
			fields := strings.Fields(q)
			graph = fields[2]
		}
	}
	if !strings.HasPrefix(graph, "_:") {
		t.Fatalf("verifiableCredential must point at a blank-node graph name, got %q in:\n%s", graph, out)
	}
	credentialQuads := 0
	for _, q := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if !strings.HasPrefix(q, "<urn:uuid:embedded-vc>") {
			continue
		}
		credentialQuads++
		if !strings.HasSuffix(q, " "+graph+" .") {
			t.Errorf("credential statement outside graph %s: %s", graph, q)
		}
	}
	if credentialQuads != 3 {
		t.Fatalf("%d credential statements, want type, issuer and credentialSubject:\n%s", credentialQuads, out)
	}
}
