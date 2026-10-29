package vc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type testRenderMethodFetcher struct {
	data []byte
}

func (f testRenderMethodFetcher) FetchRenderMethod(context.Context, string) ([]byte, error) {
	return f.data, nil
}

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
		got, err := ResolveJSONPointer(document, tt.pointer)
		if err != nil {
			t.Fatalf("ResolveJSONPointer(%q) error = %v", tt.pointer, err)
		}
		if string(mustJSON(got)) != string(mustJSON(tt.want)) {
			t.Errorf("ResolveJSONPointer(%q) = %v, want %v", tt.pointer, got, tt.want)
		}
	}
	if _, err := ResolveJSONPointer(document, "/missing"); err == nil {
		t.Fatal("ResolveJSONPointer() error = nil, want missing pointer error")
	}
}

func TestHTTPTemplateFetcherLimitsAndMediaType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	fetcher := HTTPTemplateFetcher{Client: server.Client(), MaxResponseSize: 64, MaxRedirects: 2, Timeout: time.Second}
	data, err := fetcher.Fetch(context.Background(), TemplateReference{ID: server.URL, MediaType: "application/json"})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil || got["ok"] != true {
		t.Fatalf("Fetch() data = %s, want JSON response", data)
	}

	tooSmall := HTTPTemplateFetcher{Client: server.Client(), MaxResponseSize: 2}
	if _, err := tooSmall.Fetch(context.Background(), TemplateReference{ID: server.URL}); err == nil {
		t.Fatal("Fetch() error = nil, want response size error")
	}
}

func TestValidateExternalRenderMethodVerifiesOuterDigest(t *testing.T) {
	data := []byte(`{"type":"SuiteRenderMethod","renderSuite":"summary"}`)
	hash := sha256.Sum256(data)
	multihash := append([]byte{0x12, 0x20}, hash[:]...)
	digest := "u" + base64.RawURLEncoding.EncodeToString(multihash)
	method := RenderMethod{ID: "https://example.com/render-method.json", Type: "SuiteRenderMethod", RenderSuite: "summary", DigestMultibase: digest}
	if err := method.ValidateExternalRenderMethod(context.Background(), testRenderMethodFetcher{data: data}); err != nil {
		t.Fatalf("ValidateExternalRenderMethod() error = %v", err)
	}
	method.DigestMultibase = "uAQ"
	if err := method.ValidateExternalRenderMethod(context.Background(), testRenderMethodFetcher{data: data}); err == nil {
		t.Fatal("ValidateExternalRenderMethod() error = nil, want digest error")
	}
}

func mustJSON(value any) []byte {
	data, _ := json.Marshal(value)
	return data
}
