package processor

import (
	"strings"
	"testing"

	ld "github.com/piprate/json-gold/ld"
)

// docWithUndefinedTerm returns a credential carrying one term that no context
// in @context defines. Everything else expands normally.
func docWithUndefinedTerm() map[string]interface{} {
	return map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			"https://w3id.org/security/data-integrity/v2",
		},
		"type":   []interface{}{"VerifiableCredential"},
		"issuer": "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":            "did:example:subject",
			"myCustomField": "hello",
		},
	}
}

// TestCanonicalizeDocument_SilentlyDropsUndefinedTerm pins current behaviour.
// CanonicalizeDocument sets SafeMode, but json-gold's Normalize builds a fresh
// JsonLdOptions for its internal ToRDF call and copies only ProcessingMode,
// Format and DocumentLoader across, so expansion runs with SafeMode=false and
// falls back to the JSON-LD default of dropping the term.
//
// A credential signed through this path (JsonWebSignature2020) therefore does
// not commit to fields outside its @context. When the forwarding is fixed this
// test fails: replace it with an error assertion.
func TestCanonicalizeDocument_SilentlyDropsUndefinedTerm(t *testing.T) {
	nquads, err := CanonicalizeDocument(docWithUndefinedTerm())
	if err != nil {
		t.Fatalf("expected the undefined term to be dropped silently, got error: %v", err)
	}

	got := string(nquads)
	t.Logf("canonical N-Quads:\n%s", got)

	if strings.Contains(got, "myCustomField") {
		t.Fatalf("expected myCustomField to be absent from the signed bytes, got:\n%s", got)
	}
	// The rest of the document still made it through, so the drop is silent and
	// partial rather than an outright failure.
	for _, want := range []string{"#issuer", "#credentialSubject", "#VerifiableCredential"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in the canonical output, got:\n%s", want, got)
		}
	}
}

// TestCanonicalizeWithIdMap_RejectsUndefinedTerm is the counterpart: the native
// path calls ToRDF directly, so its SafeMode reaches expansion and the same
// document is refused instead of silently truncated.
func TestCanonicalizeWithIdMap_RejectsUndefinedTerm(t *testing.T) {
	_, _, err := CanonicalizeWithIdMap(docWithUndefinedTerm())
	if err == nil {
		t.Fatal("expected an error for a term missing from @context, got nil")
	}
	t.Logf("error: %v", err)

	if !strings.Contains(err.Error(), "invalid property") {
		t.Errorf("expected an invalid-property error, got: %v", err)
	}
}

// TestSafeModeIsLostByNormalize isolates the root cause to a single line. Both
// halves run the same document through the same library with the same SafeMode
// intent; they differ only in how the options handed to ToRDF are built —
// exactly the difference between json-gold's Normalize and a correct forward.
func TestSafeModeIsLostByNormalize(t *testing.T) {
	doc := docWithUndefinedTerm()

	opts := ld.NewJsonLdOptions("")
	opts.Format = "application/n-quads"
	opts.Algorithm = ld.AlgorithmURDNA2015
	opts.DocumentLoader = defaultDocumentLoader
	opts.SafeMode = true

	// (a) What Normalize does internally (json-gold processor.go:572-576).
	whitelisted := ld.NewJsonLdOptions(opts.Base)
	whitelisted.ProcessingMode = opts.ProcessingMode
	whitelisted.Format = ""
	whitelisted.DocumentLoader = opts.DocumentLoader

	if whitelisted.SafeMode {
		t.Fatal("expected the hand-built options to lose SafeMode")
	}
	t.Logf("options built like Normalize does: SafeMode = %v", whitelisted.SafeMode)

	if _, err := ld.NewJsonLdProcessor().ToRDF(doc, whitelisted); err != nil {
		t.Errorf("expected the term to be dropped silently, got error: %v", err)
	}

	// (b) The one-line fix: start from a full copy, then override.
	copied := opts.Copy()
	copied.Format = ""

	if !copied.SafeMode {
		t.Fatal("expected Copy to carry SafeMode across")
	}
	t.Logf("options built with opts.Copy():     SafeMode = %v", copied.SafeMode)

	if _, err := ld.NewJsonLdProcessor().ToRDF(doc, copied); err == nil {
		t.Error("expected an error once SafeMode reaches expansion, got nil")
	} else {
		t.Logf("error: %v", err)
	}
}

// TestCanonicalizeDocument_DefinedTermsSurvive is the control: with every term
// defined, both paths agree and nothing is dropped.
func TestCanonicalizeDocument_DefinedTermsSurvive(t *testing.T) {
	doc := docWithUndefinedTerm()
	doc["@context"] = append(
		doc["@context"].([]interface{}),
		"https://www.w3.org/ns/credentials/examples/v2", // @vocab catch-all
	)

	nquads, err := CanonicalizeDocument(doc)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if !strings.Contains(string(nquads), "myCustomField") {
		t.Errorf("expected myCustomField to survive once a context defines it, got:\n%s", nquads)
	}

	if _, _, err := CanonicalizeWithIdMap(doc); err != nil {
		t.Errorf("native path should accept a fully defined document, got: %v", err)
	}
}
