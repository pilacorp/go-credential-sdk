package vc

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestResolveJSONPointer(t *testing.T) {
	document := map[string]any{
		"credentialSubject": map[string]any{
			"name/value": "Alice",
			"items":      []any{"first", map[string]any{"value": 2}},
		},
	}
	tests := []struct {
		pointer string
		want    any
	}{
		{"", document},
		{"/credentialSubject/name~1value", "Alice"},
		{"/credentialSubject/items/1/value", float64(2)},
	}
	for _, tt := range tests {
		got, err := resolveJSONPointer(document, tt.pointer)
		if err != nil {
			t.Fatalf("ResolveJSONPointer(%q) error = %v", tt.pointer, err)
		}
		if string(mustJSON(got)) != string(mustJSON(tt.want)) {
			t.Errorf("ResolveJSONPointer(%q) = %v, want %v", tt.pointer, got, tt.want)
		}
	}
	if _, err := resolveJSONPointer(document, "/missing"); err == nil {
		t.Fatal("ResolveJSONPointer() error = nil, want missing pointer error")
	}
}

func TestHTTPFetcherLimitsAndMediaType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	fetcher := HTTPFetcher{Client: server.Client(), MaxResponseSize: 64, MaxRedirects: 2, Timeout: time.Second}
	data, err := fetcher.Fetch(context.Background(), TemplateReference{ID: server.URL, MediaType: "application/json"})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil || got["ok"] != true {
		t.Fatalf("Fetch() data = %s, want JSON response", data)
	}

	tooSmall := HTTPFetcher{Client: server.Client(), MaxResponseSize: 2}
	if _, err := tooSmall.Fetch(context.Background(), TemplateReference{ID: server.URL}); err == nil {
		t.Fatal("Fetch() error = nil, want response size error")
	}
}

func mustJSON(value any) []byte {
	data, _ := json.Marshal(value)
	return data
}

func TestResolveJSONPointerAcceptsOnlyRFC6901ArrayIndexes(t *testing.T) {
	document := map[string]any{"list": []any{"first", "second"}, "object": map[string]any{"2024": "year"}}
	valid := map[string]any{"/list/0": "first", "/list/1": "second", "/object/2024": "year"}
	for pointer, want := range valid {
		got, err := resolveJSONPointer(document, pointer)
		if err != nil || got != want {
			t.Errorf("ResolveJSONPointer(%q) = %v, %v; want %v", pointer, got, err, want)
		}
	}
	for _, pointer := range []string{"/list/null", "/list/ 1", "/list/-0", "/list/01", "/list/+1", "/list/2", "/list/9223372036854775808"} {
		if got, err := resolveJSONPointer(document, pointer); err == nil {
			t.Errorf("ResolveJSONPointer(%q) = %v, want an error", pointer, got)
		}
	}
}

// Type and subtype are case-insensitive (RFC 9110 §8.3.1), and the SDK ignores
// parameters, so these responses match the reference.
func TestHTTPFetcherMatchesMediaTypeByTypeAndSubtype(t *testing.T) {
	for _, tc := range []struct{ header, want string }{
		{"Text/HTML", "text/html"},
		{"text/html; charset=utf-8", "TEXT/html"},
		{"application/json", "application/json; charset=utf-8"},
		{"text/html; charset", "text/html"},
		{"text/html; charset=utf-8; charset=latin1", "text/html"},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", tc.header)
			_, _ = w.Write([]byte("x"))
		}))
		fetcher := HTTPFetcher{Client: server.Client(), MaxResponseSize: 64}
		_, err := fetcher.Fetch(context.Background(), TemplateReference{ID: server.URL, MediaType: tc.want})
		server.Close()
		if err != nil {
			t.Errorf("Content-Type %q against %q: %v", tc.header, tc.want, err)
		}
	}
}

func TestHTTPFetcherRefusesAnotherMediaType(t *testing.T) {
	for _, header := range []string{"text/plain", "", "not a media type"} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header()["Content-Type"] = []string{header}
			_, _ = w.Write([]byte("x"))
		}))
		fetcher := HTTPFetcher{Client: server.Client(), MaxResponseSize: 64}
		_, err := fetcher.Fetch(context.Background(), TemplateReference{ID: server.URL, MediaType: "text/html"})
		server.Close()
		if err == nil {
			t.Errorf("Content-Type %q against text/html: error = nil, want a mismatch", header)
		}
	}
}

// MaxResponseSize at the largest int64 means no limit. Adding one byte for the
// size check overflowed to a negative limit, and the body read as empty.
func TestHTTPFetcherReadsTheBodyAtTheLargestLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	fetcher := HTTPFetcher{Client: server.Client(), MaxResponseSize: math.MaxInt64}
	data, err := fetcher.Fetch(context.Background(), TemplateReference{ID: server.URL})
	if err != nil || string(data) != `{"ok":true}` {
		t.Fatalf("Fetch() = %q, %v; want the body", data, err)
	}
}

// A reference media type that does not parse matches nothing, not even a
// response media type that does not parse either.
func TestHTTPFetcherRefusesAReferenceMediaTypeThatDoesNotParse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Content-Type"] = []string{"also bad"}
		_, _ = w.Write([]byte("x"))
	}))
	defer server.Close()
	fetcher := HTTPFetcher{Client: server.Client(), MaxResponseSize: 64}
	if _, err := fetcher.Fetch(context.Background(), TemplateReference{ID: server.URL, MediaType: "also bad"}); err == nil {
		t.Fatal("Fetch() error = nil, want a mismatch")
	}
}
