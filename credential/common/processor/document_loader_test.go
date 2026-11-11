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

func TestCanonicalize_ContextIncludingItselfStopsAtTheByteLimit(t *testing.T) {
	var body string
	srv := contextServer(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body) })
	useTestClient(t, srv)
	const pad = 64 << 10
	body = fmt.Sprintf(`{"@context":["%s/"%s]}`, srv.URL, strings.Repeat(",{}", pad/3))

	budget := newContextBudget()
	opts := sdOptions()
	opts.DocumentLoader = budget
	_, err := ld.NewJsonLdProcessor().Expand(docUsing(srv.URL+"/", "term"), opts)
	if !errors.Is(err, ErrContextOverflow) {
		t.Fatalf("got %v", err)
	}
	if want := maxContextBytesPerOperation/pad + 1; budget.loads > want {
		t.Fatalf("%d loads, the limit allows %d", budget.loads, want)
	}
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
