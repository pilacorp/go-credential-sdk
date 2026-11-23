package processor

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// #189. RDF Dataset Canonicalization (W3C Recommendation 2024-05-21) Appendix A:
// in a literal, BS, HT, LF, FF, CR, " and \ use ECHAR; U+0000-U+0007, VT,
// U+000E-U+001F and DEL use a lowercase \u with four uppercase hex digits.
func TestCanonicalize_EscapesControlCharacters(t *testing.T) {
	doc := map[string]interface{}{
		"@context": map[string]interface{}{"note": "https://example.org/note"},
		"@id":      "urn:ex:1",
		"note":     "a\tb\bc\fd\x01e\x0bf\x1fg\x7fh",
	}
	out, err := Canonicalize(doc)
	if err != nil {
		t.Fatal(err)
	}
	want := `<urn:ex:1> <https://example.org/note> "a\tb\bc\fd\u0001e\u000Bf\u001Fg\u007Fh" .` + "\n"
	if string(out) != want {
		t.Fatalf("got  %q\nwant %q", out, want)
	}
}

// #192. JSON-LD 1.1 API §4.1.2 step 5.6.3 resolves @import against the base
// URL, which for a remote context is that context's own URL (step 5.2.6).
func TestCanonicalize_RelativeImportResolvesAgainstTheContextURL(t *testing.T) {
	srv := contextServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ld+json")
		switch r.URL.Path {
		case "/ctx/a.jsonld":
			_, _ = fmt.Fprint(w, `{"@context": {"@version": 1.1, "@import": "b.jsonld", "x": "https://example.org/x"}}`)
		case "/ctx/b.jsonld":
			_, _ = fmt.Fprint(w, `{"@context": {"y": "https://example.org/y"}}`)
		default:
			http.NotFound(w, r)
		}
	})
	useTestClient(t, srv)

	out, err := Canonicalize(map[string]interface{}{
		"@context": srv.URL + "/ctx/a.jsonld",
		"@id":      "urn:s:1",
		"x":        "1",
		"y":        "2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `<urn:s:1> <https://example.org/y> "2" .`) {
		t.Fatalf("the imported term is missing:\n%s", out)
	}
}

// #193. Using a type whose scoped context imports credentials/v2 many times
// must not count the imported bytes again on every use.
func TestCanonicalize_RepeatedScopedImportFitsTheBudget(t *testing.T) {
	srv := contextServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/ld+json")
		_, _ = fmt.Fprint(w, `{"@context": {"@version": 1.1,
		  "Item": {"@id": "https://example.org/Item", "@context": {"@import": "https://www.w3.org/ns/credentials/v2"}},
		  "items": {"@id": "https://example.org/items", "@container": "@set"}}}`)
	})
	useTestClient(t, srv)

	const uses = 1000 // over 4 MiB if each use counted credentials/v2's bytes
	items := make([]interface{}, uses)
	for i := range items {
		items[i] = map[string]interface{}{"@type": "Item", "name": fmt.Sprintf("i%d", i)}
	}
	if _, err := Canonicalize(map[string]interface{}{
		"@context": srv.URL + "/s.jsonld",
		"@id":      "urn:s:1",
		"items":    items,
	}); err != nil {
		t.Fatal(err)
	}
}
