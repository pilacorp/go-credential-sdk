package vc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

type summaryFetcher struct{ data []byte }

func (f summaryFetcher) Fetch(context.Context, TemplateReference) ([]byte, error) { return f.data, nil }

func TestRenderSummaryResolvesPointers(t *testing.T) {
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Embedded: &EmbeddedTemplate{MediaType: "application/json", Bytes: []byte(`{"name":"/credentialSubject/name","description":"Degree","fields":[{"label":"Name","value":"/credentialSubject/name"}]}`)}}}
	credential := CredentialData{"credentialSubject": map[string]any{"name": "Alice"}}
	got, err := RenderSummary(context.Background(), credential, method, SummaryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Alice" || got.Fields[0].Value != "Alice" {
		t.Fatalf("output = %+v", got)
	}
}

func TestRenderSummaryRejectsMissingPointer(t *testing.T) {
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Embedded: &EmbeddedTemplate{MediaType: "application/json", Bytes: []byte(`{"name":"/credentialSubject/missing","description":"Degree","fields":[{"label":"Name","value":"/credentialSubject/name"}]}`)}}}
	_, err := RenderSummary(context.Background(), CredentialData{"credentialSubject": map[string]any{"name": "Alice"}}, method, SummaryOptions{})
	if err == nil {
		t.Fatal("RenderSummary() error = nil")
	}
}

func TestRenderSummaryResolvesScalarsAndOmitsOptionalPointers(t *testing.T) {
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Embedded: &EmbeddedTemplate{MediaType: "application/json", Bytes: []byte(`{"name":"/credentialSubject/name","description":"Degree","icon":"/credentialSubject/missing","fields":[{"label":"Age","value":"/credentialSubject/age"}]}`)}}}
	got, err := RenderSummary(context.Background(), CredentialData{"credentialSubject": map[string]any{"name": "Alice", "age": 42}}, method, SummaryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Alice" || got.Icon != "" || got.Fields[0].Value != "42" {
		t.Fatalf("output = %+v", got)
	}
}

func TestRenderSummaryVerifiesExternalDigest(t *testing.T) {
	data := []byte(`{"name":"Degree","description":"Summary","fields":[{"label":"Name","value":"/credentialSubject/name"}]}`)
	hash := sha256.Sum256(data)
	multihash := append([]byte{0x12, 0x20}, hash[:]...)
	digest := "u" + base64.RawURLEncoding.EncodeToString(multihash)
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Reference: &TemplateReference{ID: "https://example.com/summary.json", MediaType: "application/json", DigestMultibase: digest}}}
	if _, err := RenderSummary(context.Background(), CredentialData{"credentialSubject": map[string]any{"name": "Alice"}}, method, SummaryOptions{Fetcher: summaryFetcher{data: data}}); err != nil {
		t.Fatal(err)
	}
	method.Template.Reference.DigestMultibase = "uAQ"
	if _, err := RenderSummary(context.Background(), CredentialData{}, method, SummaryOptions{Fetcher: summaryFetcher{data: data}}); err == nil {
		t.Fatal("RenderSummary() error = nil")
	}
}
