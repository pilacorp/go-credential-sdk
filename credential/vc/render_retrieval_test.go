package vc

import (
	"context"
	"encoding/json"
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
