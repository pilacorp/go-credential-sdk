package processor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/piprate/json-gold/ld"
)

func contextServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func useTestClient(t *testing.T, srv *httptest.Server) {
	t.Helper()
	SetDocumentLoaderHTTPClient(srv.Client())
	t.Cleanup(func() { SetDocumentLoaderHTTPClient(nil) })
}

func writeContext(w http.ResponseWriter, term string) {
	w.Header().Set("Content-Type", "application/ld+json")
	fmt.Fprintf(w, `{"@context":{%q:"https://example.org/%s"}}`, term, term)
}

func docUsing(contextURL, term string) map[string]interface{} {
	return map[string]interface{}{
		"@context": contextURL,
		"@id":      "https://example.org/subject",
		term:       "value",
	}
}

// Stock json-gold ended this in `fatal error: concurrent map read and map write`.
func TestLoadDocument_ConcurrentCustomContexts(t *testing.T) {
	srv := contextServer(t, func(w http.ResponseWriter, _ *http.Request) { writeContext(w, "term") })
	useTestClient(t, srv)

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				// Half the URLs are shared, so cached documents are read in parallel too.
				url := fmt.Sprintf("%s/%d", srv.URL, i)
				if i%2 == 0 {
					url = fmt.Sprintf("%s/%d-%d", srv.URL, g, i)
				}
				got, err := CanonicalizeDocument(docUsing(url, "term"))
				if err != nil {
					t.Error(err)
					return
				}
				if !strings.Contains(string(got), "https://example.org/term") {
					t.Errorf("term not expanded: %s", got)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestLoadDocument_SlowFetchBlocksNothingElse(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	srv := contextServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			close(started)
			<-release
		}
		writeContext(w, "term")
	})
	useTestClient(t, srv)
	defer close(release)

	if _, err := defaultDocumentLoader.LoadDocument(srv.URL + "/cached"); err != nil {
		t.Fatal(err)
	}

	go func() { _, _ = defaultDocumentLoader.LoadDocument(srv.URL + "/slow") }()
	<-started

	done := make(chan error, 2)
	for _, path := range []string{"/cached", "/other"} {
		go func() {
			_, err := defaultDocumentLoader.LoadDocument(srv.URL + path)
			done <- err
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a slow fetch held up another load")
		}
	}
}

func TestLoadDocument_CachesACopyPerCaller(t *testing.T) {
	var hits atomic.Int32
	srv := contextServer(t, func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		writeContext(w, "term")
	})
	useTestClient(t, srv)

	// The first load returns the fetched document, the later ones the cached one.
	for i := 0; i < 2; i++ {
		doc, err := defaultDocumentLoader.LoadDocument(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		doc.Document.(map[string]interface{})["@context"] = "mutated"
	}

	last, err := defaultDocumentLoader.LoadDocument(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if last.Document.(map[string]interface{})["@context"] == "mutated" {
		t.Fatal("a caller's change reached the cache")
	}
	if hits.Load() != 1 {
		t.Fatalf("expected one fetch, got %d", hits.Load())
	}
}

func TestLoadDocument_CacheIsBounded(t *testing.T) {
	srv := contextServer(t, func(w http.ResponseWriter, _ *http.Request) { writeContext(w, "term") })
	loader := newCachingDocumentLoader(srv.Client())
	if held := maxCachedContexts * maxContextBytes; held > 64<<20 {
		t.Fatalf("the cache can hold %d bytes", held)
	}
	load := func(i int) {
		t.Helper()
		if _, err := loader.LoadDocument(fmt.Sprintf("%s/%d", srv.URL, i)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < maxCachedContexts; i++ {
		load(i)
	}
	if len(loader.docs) != maxCachedContexts {
		t.Fatalf("at the limit the cache holds %d entries", len(loader.docs))
	}
	load(maxCachedContexts)
	if len(loader.docs) != maxCachedContexts {
		t.Fatalf("one past the limit the cache holds %d entries", len(loader.docs))
	}
}

// One MiB of empty objects decodes to about 21 MiB, so the cache must hold the
// bytes. Each caller decodes its own tree, which must be the one fetched.
func TestLoadDocument_CacheHoldsBytes(t *testing.T) {
	body := `{"@context":{"<a>":"https://example.org/é\u2028&"},"n":[1,1.0,1e2,-0.5,12345678901234567890],"x":[` +
		strings.Repeat(`{},`, 1000) + `{}]}`
	srv := contextServer(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body) })
	loader := newCachingDocumentLoader(srv.Client())

	fetched, err := loader.LoadDocument(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	cached, err := loader.LoadDocument(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if held := len(loader.docs[srv.URL].raw); held > len(body)+1 {
		t.Fatalf("the cache holds %d bytes of a %d byte body", held, len(body))
	}
	if !reflect.DeepEqual(fetched, cached) {
		t.Fatalf("fetched %v\ncached  %v", fetched, cached)
	}
}

func TestDefaultClient_RefusesLoopback(t *testing.T) {
	var hits atomic.Int32
	srv := contextServer(t, func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		writeContext(w, "term")
	})
	host := srv.Listener.Addr().String()
	_, port, _ := strings.Cut(host, ":")

	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()

	var messages []string
	// localhost goes through DNS: the refusal has to come after resolution.
	for _, url := range []string{srv.URL, "http://localhost:" + port, closedURL} {
		_, err := CanonicalizeDocument(docUsing(url, "term"))
		if err == nil {
			t.Fatalf("%s: expected a refusal", url)
		}
		messages = append(messages, strings.ReplaceAll(err.Error(), url, "URL"))
	}
	if hits.Load() != 0 {
		t.Fatalf("the server was reached %d times", hits.Load())
	}
	// An answering port and a closed one must read the same.
	if messages[0] != messages[2] {
		t.Fatalf("error text differs:\n%s\n%s", messages[0], messages[2])
	}
	for _, leak := range []string{"refused", "dial", "status", "not public"} {
		if strings.Contains(messages[0], leak) {
			t.Fatalf("error text reveals %q: %s", leak, messages[0])
		}
	}
}

func TestIsPublicAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8":                true,
		"1.1.1.1":                true,
		"2606:4700:4700::1111":   true,
		"127.0.0.1":              false,
		"0.0.0.0":                false,
		"10.0.0.1":               false,
		"100.64.0.1":             false,
		"100.100.100.200":        false, // Alibaba metadata
		"169.254.169.254":        false, // AWS, GCP, Azure metadata
		"172.16.0.1":             false,
		"192.168.1.1":            false,
		"198.18.0.1":             false,
		"224.0.0.1":              false,
		"255.255.255.255":        false,
		"::":                     false,
		"::1":                    false,
		"fe80::1":                false,
		"fe80::1%en0":            false,
		"fc00::1":                false,
		"fd00:ec2::254":          false, // AWS metadata over IPv6
		"ff02::1":                false,
		"::ffff:127.0.0.1":       false,
		"::ffff:169.254.169.254": false,
		"::169.254.169.254":      false,
		"64:ff9b::a9fe:a9fe":     false, // NAT64 of 169.254.169.254
		"2002:a9fe:a9fe::":       false, // 6to4 of 169.254.169.254
	} {
		if got := isPublicAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: got %v", addr, got)
		}
	}
	if refuseNonPublic("tcp", ":443", nil) == nil {
		t.Error("an address without a host must be refused")
	}
}

func TestLoadDocument_RefusesOtherSchemes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "context.json")
	if err := os.WriteFile(path, []byte(`{"@context":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, url := range []string{path, "file://" + path, "ftp://example.org/context"} {
		if _, err := defaultDocumentLoader.LoadDocument(url); err == nil {
			t.Errorf("%s: expected a refusal", url)
		}
	}

	// A file offered as an alternate, which json-gold opens by itself: a name
	// with a scheme reads as a path relative to the working directory.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ftp:context.json"), []byte(`{"@context":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	srv := contextServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Link", `<ftp:context.json>; rel="alternate"; type="application/ld+json"`)
	})
	useTestClient(t, srv)
	if _, err := defaultDocumentLoader.LoadDocument(srv.URL); err == nil {
		t.Error("alternate: expected a refusal")
	}
}

func TestLoadDocument_RefusesOversizedResponse(t *testing.T) {
	srv := contextServer(t, func(w http.ResponseWriter, r *http.Request) {
		pad := maxContextBytes - 100
		if r.URL.Path == "/over" {
			pad = maxContextBytes + 100
		}
		fmt.Fprintf(w, `{"@context":{"pad":"%s"}}`, strings.Repeat("x", pad))
	})
	useTestClient(t, srv)

	if _, err := defaultDocumentLoader.LoadDocument(srv.URL + "/under"); err != nil {
		t.Fatalf("a context under the limit must load: %v", err)
	}
	if _, err := defaultDocumentLoader.LoadDocument(srv.URL + "/over"); err == nil {
		t.Fatal("expected a refusal")
	}
}

func TestLoadDocument_TimesOut(t *testing.T) {
	release := make(chan struct{})
	srv := contextServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		fmt.Fprint(w, `{"@context":`) // headers and part of a body, then a stall
		w.(http.Flusher).Flush()
		<-release
	})
	useTestClient(t, srv)
	defer close(release)

	saved := contextFetchTimeout
	contextFetchTimeout = 100 * time.Millisecond
	t.Cleanup(func() { contextFetchTimeout = saved })

	start := time.Now()
	if _, err := defaultDocumentLoader.LoadDocument(srv.URL); err == nil {
		t.Fatal("expected a timeout")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("took %v", elapsed)
	}
}

// json-gold recurses on rel=alternate, past the client's redirect limit, and
// holds each response open while it does.
func TestLoadDocument_BoundsAlternateChain(t *testing.T) {
	var hits atomic.Int32
	srv := contextServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Link", fmt.Sprintf(`</%d>; rel="alternate"; type="application/ld+json"`, hits.Add(1)))
	})
	useTestClient(t, srv)

	if _, err := defaultDocumentLoader.LoadDocument(srv.URL); err == nil {
		t.Fatal("expected a refusal")
	}
	if hits.Load() != maxContextRequests {
		t.Fatalf("server saw %d requests", hits.Load())
	}
}

// json-gold's recursion check never fires, so without the budget this ends in
// `fatal error: stack overflow`, which recover cannot catch.
func TestCanonicalize_ContextIncludingItself(t *testing.T) {
	srv := contextServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"@context":"http://%s/"}`, r.Host)
	})
	useTestClient(t, srv)

	doc := docUsing(srv.URL+"/", "term")
	if _, err := CanonicalizeDocument(doc); err == nil {
		t.Error("CanonicalizeDocument: expected an error")
	}
	if _, err := Canonicalize(doc); err == nil {
		t.Error("Canonicalize: expected an error")
	}
	if _, err := ToNQuads(doc); err == nil {
		t.Error("ToNQuads: expected an error")
	}
}

func TestContextBudget_StopsAtDeadline(t *testing.T) {
	budget := newContextBudget()
	budget.deadline = time.Now().Add(-time.Second)
	if _, err := budget.LoadDocument("https://example.org/context"); !errors.Is(err, ErrContextOverflow) {
		t.Fatalf("got %v", err)
	}
	if _, err := budget.LoadDocument("https://www.w3.org/ns/credentials/v2"); err != nil {
		t.Fatalf("a bundled context needs no budget: %v", err)
	}
}

func TestCustomContext_LoadsThroughHookOnly(t *testing.T) {
	var hits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/context", func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		writeContext(w, "term")
	})
	// How schema.org answers: a page pointing at its context, behind a redirect.
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/page", http.StatusFound)
	})
	mux.HandleFunc("/page", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Link", `</context>; rel="alternate"; type="application/ld+json"`)
	})
	srv := contextServer(t, mux.ServeHTTP)
	useTestClient(t, srv)

	for _, path := range []string{"/context", "/redirect"} {
		got, err := Canonicalize(docUsing(srv.URL+path, "term"))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if !strings.Contains(string(got), `<https://example.org/term> "value"`) {
			t.Fatalf("%s: term not expanded: %s", path, got)
		}
	}

	SetDocumentLoaderHTTPClient(nil)
	hits.Store(0)
	if _, err := Canonicalize(docUsing(srv.URL+"/context", "term")); err == nil {
		t.Fatal("without the hook the same URL must be refused, cached or not")
	}
	if hits.Load() != 0 {
		t.Fatalf("the server was reached %d times", hits.Load())
	}
}

// A log wants the cause and a caller must not see it: the text stays one, and
// the chain holds what went wrong.
func TestLoadDocument_CauseIsOnTheChainOnly(t *testing.T) {
	srv := contextServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			fmt.Fprintf(w, `{"@context":{"pad":"%s"}}`, strings.Repeat("x", maxContextBytes))
		case "/notjson":
			fmt.Fprint(w, `<html>`)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	useTestClient(t, srv)

	_, big := defaultDocumentLoader.LoadDocument(srv.URL + "/big")
	var tooBig *http.MaxBytesError
	if !errors.As(big, &tooBig) {
		t.Fatalf("the cause is gone: %v", big)
	}
	if !errors.Is(big, ErrContextLoad) {
		t.Fatalf("got %v", big)
	}
	for _, path := range []string{"/notjson", "/500"} {
		if _, err := defaultDocumentLoader.LoadDocument(srv.URL + path); err == nil || err.Error() != big.Error() {
			t.Fatalf("%s reads differently: %v", path, err)
		}
	}
}

// A caller tells the failures apart with errors.Is, through json-gold's wrapping.
func TestContextErrors_AreReachable(t *testing.T) {
	loopback := contextServer(t, func(w http.ResponseWriter, _ *http.Request) { writeContext(w, "term") })

	t.Run("address", func(t *testing.T) {
		if _, err := CanonicalizeDocument(docUsing(loopback.URL, "term")); !errors.Is(err, ErrContextAddress) || !errors.Is(err, ErrContextLoad) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("scheme", func(t *testing.T) {
		if _, err := Canonicalize(docUsing("ftp://example.org/context", "term")); !errors.Is(err, ErrContextScheme) || !errors.Is(err, ErrContextLoad) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("alternate scheme", func(t *testing.T) {
		srv := contextServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Link", `<ftp:context.json>; rel="alternate"; type="application/ld+json"`)
		})
		useTestClient(t, srv)
		if _, err := Canonicalize(docUsing(srv.URL, "term")); !errors.Is(err, ErrContextScheme) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("requests", func(t *testing.T) {
		var hits atomic.Int32
		srv := contextServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Link", fmt.Sprintf(`</%d>; rel="alternate"; type="application/ld+json"`, hits.Add(1)))
		})
		useTestClient(t, srv)
		if _, err := Canonicalize(docUsing(srv.URL, "term")); !errors.Is(err, ErrContextRequests) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		release := make(chan struct{})
		srv := contextServer(t, func(http.ResponseWriter, *http.Request) { <-release })
		useTestClient(t, srv)
		defer close(release)
		saved := contextFetchTimeout
		contextFetchTimeout = 50 * time.Millisecond
		t.Cleanup(func() { contextFetchTimeout = saved })
		if _, err := Canonicalize(docUsing(srv.URL, "term")); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("overflow", func(t *testing.T) {
		srv := contextServer(t, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"@context":"http://%s/"}`, r.Host)
		})
		useTestClient(t, srv)
		if _, err := Canonicalize(docUsing(srv.URL+"/", "term")); !errors.Is(err, ErrContextOverflow) {
			t.Fatalf("got %v", err)
		}
	})
}

// The leaf fast path decodes from a per-operation copy, not the process-wide
// cache. After the cache evicts an entry, a host could serve a different body
// for the same URL. Without the per-operation copy the second body is accepted
// with no load, byte or time charge and no re-classification: a self-cycle
// would recurse until fatal stack overflow (not recoverable).
func TestContextBudget_LeafEvictionSafe(t *testing.T) {
	var mu sync.Mutex
	serveCycle := false
	srv := contextServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ld+json")
		mu.Lock()
		cycle := serveCycle
		mu.Unlock()
		if cycle && r.URL.Path == "/target" {
			_, _ = fmt.Fprintf(w, `{"@context":"http://%s/target"}`, r.Host)
			return
		}
		_, _ = fmt.Fprint(w, `{"@context":{"t":"https://example.org/t"}}`)
	})
	useTestClient(t, srv)

	budget := newContextBudget()
	// First load: classified as leaf, per-operation copy stored.
	if _, err := budget.LoadDocument(srv.URL + "/target"); err != nil {
		t.Fatal(err)
	}
	if !budget.leaf[srv.URL+"/target"] {
		t.Fatal("expected leaf classification")
	}

	// Simulate eviction from the process-wide cache: in production this
	// happens when maxCachedContexts distinct URLs are loaded across any
	// number of concurrent operations.
	loader := defaultDocumentLoader.fallback.Load()
	loader.mu.Lock()
	delete(loader.docs, srv.URL+"/target")
	loader.mu.Unlock()

	// Switch the server to serve a self-cycle for /target.
	mu.Lock()
	serveCycle = true
	mu.Unlock()

	// Leaf fast path: must use the per-operation copy, not re-fetch.
	doc, err := budget.LoadDocument(srv.URL + "/target")
	if err != nil {
		t.Fatalf("leaf fast path failed: %v", err)
	}
	m := doc.Document.(map[string]interface{})
	if contextHasURLRef(m["@context"]) {
		t.Fatal("got the cyclic document instead of the per-operation copy")
	}
	if budget.loads != 1 {
		t.Fatalf("loads = %d, want 1 (leaf fast path should be free)", budget.loads)
	}
}

// The #193 scenario end-to-end: a type whose scoped @import points at the
// bundled credentials/v2 (10,131 bytes) is used N times. Without the fix
// 414 uses overflow the 4 MiB byte budget. This test is acceptance A-1.
func TestExpand_ScopedImportRepeated(t *testing.T) {
	for _, tc := range []struct {
		name  string
		items int
	}{
		{"413_items", 413},
		{"414_items", 414},
		{"5000_items", 5000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			subjects := make([]interface{}, tc.items)
			for i := range subjects {
				subjects[i] = map[string]interface{}{
					"type": "ScopedType",
					"val":  fmt.Sprintf("v%d", i),
				}
			}
			doc := map[string]interface{}{
				"@context": []interface{}{
					"https://www.w3.org/ns/credentials/v2",
					map[string]interface{}{
						"@version": 1.1,
						"ScopedType": map[string]interface{}{
							"@id": "https://example.org/ScopedType",
							"@context": map[string]interface{}{
								"@import": "https://www.w3.org/ns/credentials/v2",
								"val":     "https://example.org/val",
							},
						},
					},
				},
				"type":              "VerifiableCredential",
				"credentialSubject": subjects,
			}
			opts := sdOptions()
			_, err := ld.NewJsonLdProcessor().Expand(doc, opts)
			if err != nil {
				t.Fatalf("%d items: %v", tc.items, err)
			}
		})
	}
}

// A leaf context URL loaded many times in one operation has its bytes counted
// once. A non-leaf URL pays the full cost on every load, so cycles are still
// bounded. This exercises LoadDocument directly (the integration test above
// exercises the full Expand pipeline).
func TestContextBudget_RepeatedURLCountedOnce(t *testing.T) {
	t.Run("remote", func(t *testing.T) {
		// A context whose cached size × 2000 exceeds the byte budget, so
		// without the fix 2000 loads of the same URL overflow. 2000 also
		// exceeds maxContextLoads, proving that sibling reuse is free.
		body := fmt.Sprintf(`{"@context":[{"t":"https://example.org/t"}%s]}`, strings.Repeat(",{}", 2000))
		srv := contextServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/ld+json")
			_, _ = fmt.Fprint(w, body)
		})
		useTestClient(t, srv)

		doc, err := defaultDocumentLoader.LoadDocument(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		size := len(defaultDocumentLoader.fallback.Load().docs[doc.DocumentURL].raw)
		if size*2000 <= maxContextBytesPerOperation {
			t.Fatalf("context too small to trigger the bug: %d × 2000 = %d",
				size, size*2000)
		}

		const loads = 2000
		budget := newContextBudget()
		for i := 0; i < loads; i++ {
			if _, err := budget.LoadDocument(srv.URL); err != nil {
				t.Fatalf("load %d of %d: %v", i+1, loads, err)
			}
		}
		if budget.bytes != size {
			t.Fatalf("bytes = %d, want %d (one URL counted once)", budget.bytes, size)
		}
	})

	t.Run("bundled", func(t *testing.T) {
		const url = "https://www.w3.org/ns/credentials/v2"
		size := len(wellKnownContexts[url])
		// 5000 loads × 10 KB ≈ 50 MiB, which exceeds maxContextBytesPerOperation
		// without the fix. Bundled contexts do not count against maxContextLoads.
		const loads = 5000
		budget := newContextBudget()
		for i := 0; i < loads; i++ {
			if _, err := budget.LoadDocument(url); err != nil {
				t.Fatalf("load %d of %d: %v", i+1, loads, err)
			}
		}
		if budget.bytes != size {
			t.Fatalf("bytes = %d, want %d (one URL counted once)", budget.bytes, size)
		}
	})
}

// Distinct context URLs whose total exceeds the budget are still refused.
func TestContextBudget_DistinctURLsStillBounded(t *testing.T) {
	// Each context must be under maxContextBytes (the per-fetch limit), but
	// enough of them must exceed maxContextBytesPerOperation in total. Bulk
	// is from empty objects so no term exceeds maxContextTermBytes.
	pad := maxContextBytes / 2
	body := fmt.Sprintf(`{"@context":[{"t":"https://example.org/t"}%s]}`, strings.Repeat(",{}", pad/3))
	srv := contextServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/ld+json")
		_, _ = fmt.Fprint(w, body)
	})
	useTestClient(t, srv)

	budget := newContextBudget()
	var loaded int
	for i := 0; i < 20; i++ {
		url := fmt.Sprintf("%s/%d", srv.URL, i)
		if _, err := budget.LoadDocument(url); err != nil {
			if !errors.Is(err, ErrContextOverflow) {
				t.Fatalf("load %d: unexpected error: %v", i, err)
			}
			break
		}
		loaded++
	}
	// maxContextBytesPerOperation / (cached size) ≈ 8, so 20 must overflow.
	if loaded >= 20 {
		t.Fatalf("loaded %d large distinct contexts without overflow", loaded)
	}
}

// One operation may parse maxContextBytesPerOperation and no more: a context
// that includes itself is parsed again on each load. Bundled contexts count.
func TestContextBudget_BytesPerOperation(t *testing.T) {
	srv := contextServer(t, func(w http.ResponseWriter, _ *http.Request) { writeContext(w, "term") })
	useTestClient(t, srv)
	doc, err := defaultDocumentLoader.LoadDocument(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	remote := len(defaultDocumentLoader.fallback.Load().docs[doc.DocumentURL].raw)
	const bundled = "https://www.w3.org/ns/credentials/v2"

	for name, tc := range map[string]struct {
		url  string
		size int
	}{
		"remote":  {srv.URL, remote},
		"bundled": {bundled, len(wellKnownContexts[bundled])},
	} {
		t.Run(name, func(t *testing.T) {
			budget := newContextBudget()
			budget.bytes = maxContextBytesPerOperation - tc.size
			if _, err := budget.LoadDocument(tc.url); err != nil {
				t.Fatalf("at the limit: %v", err)
			}
			budget = newContextBudget()
			budget.bytes = maxContextBytesPerOperation - tc.size + 1
			if _, err := budget.LoadDocument(tc.url); !errors.Is(err, ErrContextOverflow) {
				t.Fatalf("one past the limit: %v", err)
			}
		})
	}
}

// A self-referencing context of about 1 MiB is refused after a few loads, not
// 1024: the byte budget stops the recursion early for large contexts, while
// maxContextLoads is the backstop for small ones.
func TestCanonicalize_ContextIncludingItselfStopsAtTheByteLimit(t *testing.T) {
	pad := maxContextBytes / 2 // well under per-fetch limit, but ~0.5 MiB
	srv := contextServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"@context":["http://%s/"%s]}`,
			r.Host, strings.Repeat(",{}", pad/3))
	})
	useTestClient(t, srv)

	budget := newContextBudget()
	opts := sdOptions()
	opts.DocumentLoader = budget
	_, err := ld.NewJsonLdProcessor().Expand(docUsing(srv.URL+"/", "term"), opts)
	if !errors.Is(err, ErrContextOverflow) {
		t.Fatalf("got %v", err)
	}
	// pad is maxContextBytes/2 ≈ 0.5 MiB. The byte budget should stop it
	// in a handful of loads: 4 MiB / 0.5 MiB ≈ 8—far below maxContextLoads.
	if budget.loads > 50 {
		t.Fatalf("%d loads, expected the byte budget to stop it early", budget.loads)
	}
}

// A mutual cycle (A↔B) or a long cycle (A→B→C→A) is stopped by the budget:
// every URL in a cycle has a URL string in its @context (non-leaf), so every
// load pays the full byte and load cost—matching base behavior exactly.
func TestCanonicalize_MutualAndLongCyclesStoppedByBudget(t *testing.T) {
	t.Run("A↔B", func(t *testing.T) {
		// Two small contexts referencing each other. Both are non-leaf.
		// The load limit catches it at maxContextLoads.
		mux := http.NewServeMux()
		var srvURL string
		mux.HandleFunc("/a", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprintf(w, `{"@context":"%s/b"}`, srvURL)
		})
		mux.HandleFunc("/b", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprintf(w, `{"@context":"%s/a"}`, srvURL)
		})
		srv := contextServer(t, mux.ServeHTTP)
		srvURL = srv.URL
		useTestClient(t, srv)

		budget := newContextBudget()
		opts := sdOptions()
		opts.DocumentLoader = budget
		_, err := ld.NewJsonLdProcessor().Expand(docUsing(srv.URL+"/a", "term"), opts)
		if !errors.Is(err, ErrContextOverflow) {
			t.Fatalf("got %v", err)
		}
		// Must match base: load limit catches small mutual cycles.
		if budget.loads > maxContextLoads+1 {
			t.Fatalf("%d loads exceeds the load limit %d", budget.loads, maxContextLoads)
		}
	})

	t.Run("A→B→C→A_large", func(t *testing.T) {
		// Three contexts in a long cycle, each ~384 KB (maxContextBytes/8
		// repetitions of ",{}" = 131072 × 3 bytes). All are non-leaf.
		// The byte budget catches it early: 4 MiB / 384 KB ≈ 11 loads.
		pad := strings.Repeat(",{}", maxContextBytes/8)
		mux := http.NewServeMux()
		var srvURL string
		mux.HandleFunc("/a", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprintf(w, `{"@context":["%s/b"%s]}`, srvURL, pad)
		})
		mux.HandleFunc("/b", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprintf(w, `{"@context":["%s/c"%s]}`, srvURL, pad)
		})
		mux.HandleFunc("/c", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprintf(w, `{"@context":["%s/a"%s]}`, srvURL, pad)
		})
		srv := contextServer(t, mux.ServeHTTP)
		srvURL = srv.URL
		useTestClient(t, srv)

		budget := newContextBudget()
		opts := sdOptions()
		opts.DocumentLoader = budget
		_, err := ld.NewJsonLdProcessor().Expand(docUsing(srv.URL+"/a", "term"), opts)
		if !errors.Is(err, ErrContextOverflow) {
			t.Fatalf("got %v", err)
		}
		// ~384 KB per load, 4 MiB budget → ~11 loads. Assert far below maxContextLoads.
		if budget.loads > 100 {
			t.Fatalf("%d loads, expected the byte budget to stop it early", budget.loads)
		}
	})
}

func TestAlternateIsHTTP(t *testing.T) {
	const base = "https://example.org/context"
	for target, want := range map[string]bool{
		"/other":                      true,
		"https://example.org/other":   true,
		"ftp://example.org/other":     false,
		"ftp:context.json":            false,
		"%zz":                         false,
		"https://example.org:bad/ctx": false,
	} {
		if got := alternateIsHTTP(base, target); got != want {
			t.Errorf("%q: got %v", target, got)
		}
	}
}

// ld.Resolve dereferences nil on a target it cannot parse, and the server is
// one the document chose.
func TestLoadDocument_RefusesUnparsableAlternate(t *testing.T) {
	srv := contextServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", `<%zz>; rel="alternate"; type="application/ld+json"`)
		writeContext(w, "term")
	})
	useTestClient(t, srv)
	if _, err := ToNQuads(docUsing(srv.URL, "term")); !errors.Is(err, ErrContextScheme) {
		t.Fatalf("got %v", err)
	}
}

// The same nil dereference with no server: every other entry already recovers.
func TestToNQuads_RecoversFromPanic(t *testing.T) {
	doc := map[string]interface{}{
		"@context": []interface{}{map[string]interface{}{"@base": "http://example.org/", "p": "https://example.org/p"}, "%zz"},
		"@id":      "urn:x",
		"p":        "v",
	}
	if _, err := ToNQuads(doc); err == nil || !strings.Contains(err.Error(), "malformed JSON-LD input") {
		t.Fatalf("got %v", err)
	}
}
