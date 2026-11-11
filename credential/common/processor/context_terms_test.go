package processor

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// inlineTerms is a context of n unrelated terms, each with an IRI of a real length.
func inlineTerms(n int) map[string]interface{} {
	ctx := make(map[string]interface{}, n)
	for i := 0; i < n; i++ {
		ctx[fmt.Sprintf("t%d", i)] = fmt.Sprintf("https://example.org/vocab#t%d", i)
	}
	return ctx
}

func docWithContext(ctx interface{}, term string) map[string]interface{} {
	return map[string]interface{}{"@context": ctx, "@id": "https://example.org/subject", term: "value"}
}

// prefixChain is t0 and then links terms, each the one before it plus one
// suffix, so that links terms of value bytes each are in use as prefixes.
func prefixChain(links, value int) map[string]interface{} {
	ctx := map[string]interface{}{"t0": "https://example.org/"}
	for i := 1; i <= links; i++ {
		name := fmt.Sprintf("t%d", i-1)
		ctx[fmt.Sprintf("t%d", i)] = name + ":" + strings.Repeat("x", value-len(name)-2) + "/"
	}
	ctx["last"] = fmt.Sprintf("t%d:last", links)
	return ctx
}

func termEntries() map[string]func(map[string]interface{}) error {
	entries := canonicalizers()
	entries["ExpandJSONLD"] = func(d map[string]interface{}) error { _, err := ExpandJSONLD(d); return err }
	entries["ToRDFNQuads"] = func(d map[string]interface{}) error { _, err := ToRDFNQuads(d); return err }
	entries["ToNQuads"] = func(d map[string]interface{}) error { _, err := ToNQuads(d); return err }
	return entries
}

func TestContextTerms_InlineLimit(t *testing.T) {
	for fn, entry := range termEntries() {
		t.Run(fn, func(t *testing.T) {
			if err := entry(docWithContext(inlineTerms(maxInlineContextTerms), "t0")); err != nil {
				t.Fatalf("at the limit: %v", err)
			}
			err := entry(docWithContext(inlineTerms(maxInlineContextTerms+1), "t0"))
			if !errors.Is(err, ErrTooManyContextTerms) {
				t.Fatalf("one past the limit: %v", err)
			}
		})
	}
}

// Contexts inside the document count, wherever they are, as do scoped ones and
// the nested form json-gold reads through.
func TestContextTerms_InlineCountReachesEveryContext(t *testing.T) {
	over := inlineTerms(maxInlineContextTerms + 1)
	for name, doc := range map[string]map[string]interface{}{
		"node": {
			"@context": map[string]interface{}{"knows": "https://example.org/knows"},
			"knows":    []interface{}{map[string]interface{}{"@context": over, "t0": "value"}},
		},
		"array":  {"@context": []interface{}{inlineTerms(1), over}, "t0": "value"},
		"nested": {"@context": []interface{}{map[string]interface{}{"@context": over}}, "t0": "value"},
		"scoped": {"@context": map[string]interface{}{"t0": map[string]interface{}{"@id": "https://example.org/t0", "@context": over}}, "t0": "value"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ExpandJSONLD(doc); !errors.Is(err, ErrTooManyContextTerms) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestContextTerms_RemoteLimit(t *testing.T) {
	bodies := map[string]string{}
	srv := contextServer(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, bodies[r.URL.Path]) })
	useTestClient(t, srv)
	context := func(n int) string {
		var b strings.Builder
		b.WriteString(`{"@context":{"t0":"https://example.org/t0"`)
		for i := 1; i < n; i++ {
			fmt.Fprintf(&b, `,"t%d":"https://example.org/t%d"`, i, i)
		}
		b.WriteString(`}}`)
		return b.String()
	}
	bodies["/at"] = context(maxContextTerms)
	bodies["/past"] = context(maxContextTerms + 1)

	if _, err := CanonicalizeDocument(docUsing(srv.URL+"/at", "t0")); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	if _, err := CanonicalizeDocument(docUsing(srv.URL+"/past", "t0")); !errors.Is(err, ErrTooManyContextTerms) {
		t.Fatalf("one past the limit: %v", err)
	}
}

// A context named many times is many parses of the same terms, not more terms:
// a presentation repeats one context per credential.
func TestContextTerms_RepeatedContextCountsOnce(t *testing.T) {
	srv := contextServer(t, func(w http.ResponseWriter, _ *http.Request) {
		var b strings.Builder
		b.WriteString(`{"@context":{"t0":"https://example.org/t0"`)
		for i := 1; i < maxContextTerms/2; i++ {
			fmt.Fprintf(&b, `,"t%d":"https://example.org/t%d"`, i, i)
		}
		b.WriteString(`}}`)
		fmt.Fprint(w, b.String())
	})
	useTestClient(t, srv)

	doc := docUsing(srv.URL, "t0")
	doc["knows"] = map[string]interface{}{"@context": []interface{}{srv.URL, map[string]interface{}{"knows": "https://example.org/knows"}}, "t0": "value"}
	doc["@context"] = []interface{}{srv.URL, map[string]interface{}{"knows": "https://example.org/knows"}}
	if _, err := Canonicalize(doc); err != nil {
		t.Fatal(err)
	}
}

func TestContextTerms_LengthLimit(t *testing.T) {
	long := func(n int) string {
		prefix := "https://example.org/"
		return prefix + strings.Repeat("x", n-len(prefix))
	}
	base := func(n int) map[string]interface{} {
		return map[string]interface{}{"@context": map[string]interface{}{"@base": long(n), "term": "https://example.org/term"}, "@id": "https://example.org/subject", "term": "value"}
	}
	shapes := map[string]func(n int) map[string]interface{}{
		"term IRI": func(n int) map[string]interface{} {
			return docWithContext(map[string]interface{}{"term": long(n)}, "term")
		},
		"term @id": func(n int) map[string]interface{} {
			return docWithContext(map[string]interface{}{"term": map[string]interface{}{"@id": long(n)}}, "term")
		},
		"term name": func(n int) map[string]interface{} {
			name := strings.Repeat("x", n)
			return docWithContext(map[string]interface{}{"@vocab": "https://example.org/", name: "https://example.org/term"}, name)
		},
		"@vocab": func(n int) map[string]interface{} {
			return docWithContext(map[string]interface{}{"@vocab": long(n)}, "term")
		},
		"@base": base,
	}
	for name, doc := range shapes {
		t.Run(name, func(t *testing.T) {
			if err := termEntries()["Canonicalize"](doc(maxContextTermBytes)); err != nil {
				t.Fatalf("at the limit: %v", err)
			}
			err := termEntries()["Canonicalize"](doc(maxContextTermBytes + 1))
			if !errors.Is(err, ErrContextTermTooLong) {
				t.Fatalf("one past the limit: %v", err)
			}
		})
	}
}

// What a chain adds to an IRI is bounded however it is spread over terms.
func TestContextTerms_ChainLimit(t *testing.T) {
	const value = 100
	links := maxContextTermBytes / value
	spare := maxContextTermBytes % value

	at := prefixChain(links, value)
	at["t0"] = "urn:" + strings.Repeat("x", spare-6) + ":/"
	// A root with no // is a link of the chain too, and so is every suffix.
	if _, err := Canonicalize(docWithContext(at, "last")); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	past := prefixChain(links, value)
	past["t0"] = "urn:" + strings.Repeat("x", spare-5) + ":/"
	if _, err := Canonicalize(docWithContext(past, "last")); !errors.Is(err, ErrContextTermTooLong) {
		t.Fatalf("one past the limit: %v", err)
	}
}

// Every way json-gold joins two strings into an IRI has to count.
func TestContextTerms_ChainShapes(t *testing.T) {
	suffix := strings.Repeat("x", 1000) + "/"
	vocabChain := []interface{}{map[string]interface{}{"@vocab": "https://example.org/"}}
	for i := 0; i < 4; i++ {
		vocabChain = append(vocabChain, map[string]interface{}{"@vocab": suffix})
	}
	aliases := map[string]interface{}{"t0": "https://example.org/"}
	for i := 1; i < 4; i++ {
		// a0 is t0 under another name, so the chain never names t0 as a prefix.
		aliases[fmt.Sprintf("a%d", i-1)] = fmt.Sprintf("t%d", i-1)
		aliases[fmt.Sprintf("t%d", i)] = fmt.Sprintf("a%d:%s", i-1, suffix)
	}
	aliases["last"] = "t3:last"
	twoNames := []interface{}{
		map[string]interface{}{"a": "https://example.org/", "b": "a:" + suffix},
		map[string]interface{}{"a": "b:" + suffix},
		map[string]interface{}{"b": "a:" + suffix},
		map[string]interface{}{"a": "b:" + suffix, "last": "a:last"},
	}
	compactNames := []interface{}{map[string]interface{}{"t0": "https://example.org/"}}
	for i := 1; i < 4; i++ {
		compactNames = append(compactNames, map[string]interface{}{
			"@vocab":            fmt.Sprintf("t%d:%s", i-1, suffix),
			"t" + fmt.Sprint(i): map[string]interface{}{},
		})
	}

	for name, ctx := range map[string]interface{}{
		"@vocab":        vocabChain,
		"aliases":       aliases,
		"two names":     twoNames,
		"compact names": compactNames,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ExpandJSONLD(docWithContext(ctx, "last")); !errors.Is(err, ErrContextTermTooLong) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// A chain that crosses from the document into a remote context and back is one
// chain, whichever of the two the budget reads first.
func TestContextTerms_ChainCrossesInlineAndRemote(t *testing.T) {
	suffix := strings.Repeat("x", 1000) + "/"
	srv := contextServer(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"@context":{"t1":"t0:%[1]s","t3":"t2:%[1]s"}}`, suffix)
	})
	useTestClient(t, srv)

	ctx := []interface{}{
		map[string]interface{}{"t0": "https://example.org/"},
		srv.URL,
		map[string]interface{}{"t2": "t1:" + suffix, "t4": "t3:" + suffix, "last": "t4:last"},
	}
	if _, err := ExpandJSONLD(docWithContext(ctx, "last")); !errors.Is(err, ErrContextTermTooLong) {
		t.Fatalf("got %v", err)
	}
}

// What real contexts look like must pass with room: many terms over a few
// prefixes, and aliases, none of which is a chain.
func TestContextTerms_AcceptsRealShapes(t *testing.T) {
	ctx := map[string]interface{}{
		"schema": "https://schema.org/",
		"xsd":    "http://www.w3.org/2001/XMLSchema#",
		"ex":     "urn:example:",
		"id":     "@id",
		"type":   "@type",
	}
	for i := 0; i < maxInlineContextTerms-len(ctx)-2; i++ {
		ctx[fmt.Sprintf("t%d", i)] = map[string]interface{}{"@id": fmt.Sprintf("schema:t%d", i), "@type": "xsd:string"}
	}
	ctx["alias"] = "t0"
	ctx["self"] = "self"
	ctx["@vocab"] = "https://example.org/vocab#"
	if _, err := Canonicalize(docWithContext(ctx, "alias")); err != nil {
		t.Fatal(err)
	}
}
