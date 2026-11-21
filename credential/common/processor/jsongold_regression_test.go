package processor

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// Regression tests for the pilacorp/json-gold bump (v0.7.0 → v0.9.1-pila.1).
// Each test covers one of the fixed issues and fails on main (piprate v0.7.0).

// TestIssue186_VPv2EmbeddedVCInNamedGraph pins the fix for #186: a VCDM 2.0
// VP's verifiableCredential, declared with @container: @graph, now canonicalizes
// the embedded VC into a named graph. The old json-gold placed the VC triples
// in the default graph, making Go's canonical output differ from every other
// conforming implementation.
//
// On main (piprate v0.7.0) the VC triples land in the default graph (no fourth
// field), so the assertion on named-graph quads fails.
func TestIssue186_VPv2EmbeddedVCInNamedGraph(t *testing.T) {
	vp := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiablePresentation"},
		"id":       "urn:uuid:vp-186",
		"holder":   "did:example:holder",
		"verifiableCredential": []interface{}{
			map[string]interface{}{
				"@context": []interface{}{
					"https://www.w3.org/ns/credentials/v2",
					"https://www.w3.org/ns/credentials/examples/v2",
				},
				"type":   []interface{}{"VerifiableCredential"},
				"id":     "urn:uuid:vc-186",
				"issuer": "did:example:issuer",
				"credentialSubject": map[string]interface{}{
					"id":   "did:example:subject",
					"name": "Alice",
				},
			},
		},
	}

	nquads, err := Canonicalize(vp)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}

	output := string(nquads)
	t.Logf("canonical N-Quads:\n%s", output)

	// The VC triples must be in a named graph (5-field quads: S P O G .)
	vcTripleInNamedGraph := false
	vpLinksToGraph := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// A quad with the VC's id in a named graph
		if strings.Contains(line, "<urn:uuid:vc-186>") && strings.Contains(line, "_:c14n") {
			parts := strings.Fields(line)
			if len(parts) == 5 { // S P O G .
				vcTripleInNamedGraph = true
			}
		}
		// The VP's verifiableCredential link points to the graph, not the VC id
		if strings.Contains(line, "verifiableCredential") && strings.Contains(line, "_:c14n") {
			vpLinksToGraph = true
		}
	}

	if !vcTripleInNamedGraph {
		t.Error("VC triples are not in a named graph — the fix for #186 (@container: @graph) is not active")
	}
	if !vpLinksToGraph {
		t.Error("VP's verifiableCredential does not point to a named graph")
	}

	// The VP triple itself must be in the default graph (4-field quad: S P O .)
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "VerifiablePresentation") {
			parts := strings.Fields(line)
			if len(parts) != 4 {
				t.Errorf("VP type triple should be in the default graph (4 fields), got %d: %s", len(parts), line)
			}
		}
	}
}

// TestIssue189_CanonicalNQuadsEscapesControlCharacters pins the fix for #189:
// canonical N-Quad literals escape control characters as RDFC-1.0 requires.
//
// On main (piprate v0.7.0) the control characters are written raw (or only TAB
// is escaped), so the assertion on \b, \f, and \u00XX fails.
func TestIssue189_CanonicalNQuadsEscapesControlCharacters(t *testing.T) {
	// A literal with backspace (U+0008), form feed (U+000C), and SOH (U+0001).
	doc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2",
		},
		"type":   []interface{}{"VerifiableCredential"},
		"id":     "urn:uuid:vc-189",
		"issuer": "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "a\tb\bc\fd\x01e",
		},
	}

	nquads, err := Canonicalize(doc)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}

	output := string(nquads)
	t.Logf("canonical N-Quads:\n%s", output)

	// Find the name literal line
	var nameLine string
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "schema.org/name") {
			nameLine = line
			break
		}
	}
	if nameLine == "" {
		t.Fatal("no name triple found")
	}

	// RDFC-1.0 escapes: \t for TAB, \b for BS, \f for FF, \u0001 for SOH
	for _, want := range []string{`\t`, `\b`, `\f`, `\u0001`} {
		if !strings.Contains(nameLine, want) {
			t.Errorf("expected %q in the name literal, got: %s", want, nameLine)
		}
	}
}

// TestIssue191_NQuadsBackslashBeforeEscapeLetter pins the fix for #191:
// parsing N-Quads text decodes \\n in one pass so a backslash followed by n
// stays those two characters.
//
// On main (piprate v0.7.0) the sequential ReplaceAll calls turn \\n into a
// real newline, corrupting the value. ecdsa-sd-2023 CreateBaseProof and
// DeriveProof go through this parse; the derived proof then fails to verify.
func TestIssue191_NQuadsBackslashBeforeEscapeLetter(t *testing.T) {
	// N-Quads text with a literal that holds a real backslash followed by n.
	// The escaped form in N-Quads is \\n (two characters: backslash, n).
	input := `<urn:s:1> <https://example.org/note> "a\\nb" .
`
	parsed, err := canonicalizeNQuadsOnly(input)
	if err != nil {
		t.Fatalf("parse + canonicalize: %v", err)
	}

	output := strings.Join(parsed, "")
	t.Logf("round-tripped N-Quads:\n%s", output)

	// The literal must still hold \\n (a real backslash followed by n), not a
	// newline character (which N-Quads writes as \n).
	if strings.Contains(output, "\"a\nb\"") {
		t.Fatal("backslash-n was decoded as a newline — the sequential ReplaceAll bug from #191 is present")
	}
	if !strings.Contains(output, `"a\\nb"`) {
		t.Fatalf("expected the literal to hold a backslash and n, got:\n%s", output)
	}
}

// canonicalizeNQuadsOnly parses N-Quads text and re-serializes it through the
// canonicalizer, exercising the same parse path as ecdsa-sd-2023.
func canonicalizeNQuadsOnly(nquadsText string) ([]string, error) {
	nquads := splitNQuadsKeepNL(nquadsText)
	return CanonicalizeNQuadsWithIdMapLines(nquads)
}

// CanonicalizeNQuadsWithIdMapLines is a test helper that calls
// CanonicalizeNQuadsWithIdMap and returns only the N-Quads.
func CanonicalizeNQuadsWithIdMapLines(nquads []string) ([]string, error) {
	result, _, err := CanonicalizeNQuadsWithIdMap(nquads)
	return result, err
}

// TestIssue192_RelativeImportInRemoteContext pins the fix for #192: a relative
// @import in a remote context now resolves against that context's URL, not the
// document's base.
//
// On main (piprate v0.7.0) the relative @import resolves against the document
// base (empty, so it fails to load), and the test gets a loading error.
func TestIssue192_RelativeImportInRemoteContext(t *testing.T) {
	// Two contexts served from the same path prefix:
	//   /ctx/a.jsonld — imports "b.jsonld" (relative)
	//   /ctx/b.jsonld — defines term "x"
	mux := http.NewServeMux()
	mux.HandleFunc("/ctx/a.jsonld", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/ld+json")
		fmt.Fprint(w, `{"@context": {"@version": 1.1, "@import": "b.jsonld", "y": "https://example.org/y"}}`)
	})
	mux.HandleFunc("/ctx/b.jsonld", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/ld+json")
		fmt.Fprint(w, `{"@context": {"@version": 1.1, "x": "https://example.org/x"}}`)
	})
	srv := contextServer(t, mux.ServeHTTP)
	useTestClient(t, srv)

	doc := map[string]interface{}{
		"@context": srv.URL + "/ctx/a.jsonld",
		"@id":      "urn:s:1",
		"x":        "1",
		"y":        "2",
	}

	nquads, err := ToRDFNQuads(doc)
	if err != nil {
		t.Fatalf("expected relative @import to resolve against the context URL, got error: %v", err)
	}

	output := strings.Join(nquads, "")
	t.Logf("N-Quads:\n%s", output)

	// Both terms must expand: x from b.jsonld (loaded via relative import), y from a.jsonld.
	if !strings.Contains(output, "https://example.org/x") {
		t.Error("term x (from the imported context) did not expand")
	}
	if !strings.Contains(output, "https://example.org/y") {
		t.Error("term y (from the importing context) did not expand")
	}
}
