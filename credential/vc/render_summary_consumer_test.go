package vc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type summaryFetcher struct{ data []byte }

func (f summaryFetcher) Fetch(context.Context, TemplateReference) ([]byte, error) { return f.data, nil }

func TestRenderSummaryResolvesPointers(t *testing.T) {
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Embedded: &EmbeddedTemplate{MediaType: "application/json", Bytes: []byte(`{"name":"/credentialSubject/name","description":"Degree","fields":[{"label":"Name","value":"/credentialSubject/name"}]}`)}}}
	credential := CredentialData{"credentialSubject": map[string]any{"name": "Alice"}}
	got, err := method.RenderSummary(context.Background(), credential, RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Alice" || got.Fields[0].Value != "Alice" {
		t.Fatalf("output = %+v", got)
	}
}

func TestRenderSummaryRejectsNonSummarySuite(t *testing.T) {
	method := RenderMethod{
		Type:        "SuiteRenderMethod",
		RenderSuite: "html",
		Template: &Template{Reference: &TemplateReference{
			ID:        "https://example.com/template.html",
			MediaType: "text/html",
		}},
	}

	if _, err := method.RenderSummary(context.Background(), CredentialData{"credentialSubject": map[string]any{"name": "Alice"}}, RenderOptions{
		Fetcher: summaryFetcher{data: []byte(`{"name":"Degree","description":"Summary","fields":[{"label":"Name","value":"/credentialSubject/name"}]}`)},
	}); err == nil {
		t.Fatal("RenderSummary() error = nil, want non-summary suite error")
	}
}

func TestRenderSummaryRejectsMissingPointer(t *testing.T) {
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Embedded: &EmbeddedTemplate{MediaType: "application/json", Bytes: []byte(`{"name":"/credentialSubject/missing","description":"Degree","fields":[{"label":"Name","value":"/credentialSubject/name"}]}`)}}}
	_, err := method.RenderSummary(context.Background(), CredentialData{"credentialSubject": map[string]any{"name": "Alice"}}, RenderOptions{})
	if err == nil {
		t.Fatal("RenderSummary() error = nil")
	}
}

func TestRenderSummaryResolvesScalarsAndOmitsOptionalPointers(t *testing.T) {
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Embedded: &EmbeddedTemplate{MediaType: "application/json", Bytes: []byte(`{"name":"/credentialSubject/name","description":"Degree","icon":"/credentialSubject/missing","fields":[{"label":"Age","value":"/credentialSubject/age"}]}`)}}}
	got, err := method.RenderSummary(context.Background(), CredentialData{"credentialSubject": map[string]any{"name": "Alice", "age": 42}}, RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Alice" || got.Icon != "" || got.Fields[0].Value != "42" {
		t.Fatalf("output = %+v", got)
	}
}

func TestRenderSummaryLimitsCopiedOutput(t *testing.T) {
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Embedded: &EmbeddedTemplate{MediaType: "application/json", Bytes: []byte(`{"name":"/credentialSubject/name","description":"Summary","fields":[{"label":"A","value":"/credentialSubject/name"},{"label":"B","value":"/credentialSubject/name"}]}`)}}}
	_, err := method.RenderSummary(context.Background(), CredentialData{"credentialSubject": map[string]any{"name": strings.Repeat("x", 8)}}, RenderOptions{MaxSummaryOutputBytes: 10})
	if err == nil || !strings.Contains(err.Error(), "summary output exceeds the size limit") {
		t.Fatalf("RenderSummary() error = %v, want output size error", err)
	}
}

func TestRenderSummaryDoesNotHTMLEscapeNonStringPointerValues(t *testing.T) {
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Embedded: &EmbeddedTemplate{MediaType: "application/json", Bytes: []byte(`{"name":"Degree","description":"Summary","fields":[{"label":"Details","value":"/credentialSubject/details"}]}`)}}}
	got, err := method.RenderSummary(context.Background(), CredentialData{"credentialSubject": map[string]any{
		"details": map[string]any{"note": "A & B"},
	}}, RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Fields[0].Value != `{"note":"A & B"}` {
		t.Fatalf("field value = %q, want unescaped JSON", got.Fields[0].Value)
	}
}

func TestRenderSummaryVerifiesExternalDigest(t *testing.T) {
	data := []byte(`{"name":"Degree","description":"Summary","fields":[{"label":"Name","value":"/credentialSubject/name"}]}`)
	hash := sha256.Sum256(data)
	multihash := append([]byte{0x12, 0x20}, hash[:]...)
	digest := "u" + base64.RawURLEncoding.EncodeToString(multihash)
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Reference: &TemplateReference{ID: "https://example.com/summary.json", MediaType: "application/json", DigestMultibase: digest}}}
	if _, err := method.RenderSummary(context.Background(), CredentialData{"credentialSubject": map[string]any{"name": "Alice"}}, RenderOptions{Fetcher: summaryFetcher{data: data}}); err != nil {
		t.Fatal(err)
	}
	method.Template.Reference.DigestMultibase = testDigest([]byte("other bytes"))
	if _, err := method.RenderSummary(context.Background(), CredentialData{}, RenderOptions{Fetcher: summaryFetcher{data: data}}); err == nil {
		t.Fatal("RenderSummary() error = nil")
	}
}

func externalSummaryMethod(mediaType string) RenderMethod {
	return RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Reference: &TemplateReference{
		ID: "https://example.com/summary.json", MediaType: mediaType,
	}}}
}

func TestRenderSummaryValidatesExternalTemplateLikeEmbedded(t *testing.T) {
	credential := CredentialData{"credentialSubject": map[string]any{"name": "Alice", "degree": "BSc"}}
	cases := map[string]struct {
		mediaType string
		template  string
	}{
		"literal field value": {"application/json", `{"name":"Degree","description":"Summary","fields":[{"label":"Degree","value":"PhD, summa cum laude"}]}`},
		"pointer field label": {"application/json", `{"name":"Degree","description":"Summary","fields":[{"label":"/credentialSubject/degree","value":"/credentialSubject/degree"}]}`},
		"empty field value":   {"application/json", `{"name":"Degree","description":"Summary","fields":[{"label":"Degree","value":""}]}`},
		"missing fields":      {"application/json", `{"name":"Degree","description":"Summary"}`},
		"missing description": {"application/json", `{"name":"Degree","fields":[{"label":"Degree","value":"/credentialSubject/degree"}]}`},
		"null name":           {"application/json", `{"name":null,"description":"Summary","fields":[{"label":"Degree","value":"/credentialSubject/degree"}]}`},
		"missing field label": {"application/json", `{"name":"Degree","description":"Summary","fields":[{"value":"/credentialSubject/degree"}]}`},
		"unknown member":      {"application/json", `{"name":"Degree","description":"Summary","fields":[{"label":"Degree","value":"/credentialSubject/degree"}],"extra":true}`},
		"wrong media type":    {"text/plain", `{"name":"Degree","description":"Summary","fields":[{"label":"Degree","value":"/credentialSubject/degree"}]}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			opts := RenderOptions{Fetcher: summaryFetcher{data: []byte(tc.template)}}
			if got, err := externalSummaryMethod(tc.mediaType).RenderSummary(context.Background(), credential, opts); err == nil {
				t.Fatalf("RenderSummary() = %+v, want validation error", got)
			}
		})
	}
}

func TestRenderSummaryAcceptsExternalTemplateWithoutMediaType(t *testing.T) {
	credential := CredentialData{"credentialSubject": map[string]any{"degree": "BSc"}}
	data := []byte(`{"name":"Degree","description":"Summary","fields":[{"label":"Degree","value":"/credentialSubject/degree"}]}`)
	got, err := (externalSummaryMethod("")).RenderSummary(context.Background(), credential, RenderOptions{Fetcher: summaryFetcher{data: data}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Fields[0].Value != "BSc" {
		t.Fatalf("output = %+v", got)
	}
}

func TestRenderSummaryAllowsEmptyRequiredMembers(t *testing.T) {
	// The W3C summary object requires name, description, and fields to be
	// present; it does not require them to be non-empty.
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Embedded: &EmbeddedTemplate{
		MediaType: "application/json",
		Bytes:     []byte(`{"name":"Degree","description":"","fields":[{"label":"","value":"/credentialSubject/degree"}]}`),
	}}}
	if err := method.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	got, err := method.RenderSummary(context.Background(), CredentialData{"credentialSubject": map[string]any{"degree": "BSc"}}, RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Description != "" || got.Fields[0].Label != "" || got.Fields[0].Value != "BSc" {
		t.Fatalf("output = %+v", got)
	}

	method.Template.Embedded.Bytes = []byte(`{"name":"Degree","description":"Summary","fields":[]}`)
	got, err = method.RenderSummary(context.Background(), CredentialData{}, RenderOptions{})
	if err != nil {
		t.Fatalf("RenderSummary() with empty fields error = %v", err)
	}
	if got.Fields == nil || len(got.Fields) != 0 {
		t.Fatalf("output fields = %#v, want empty slice", got.Fields)
	}
}

func TestRenderMethodPhase0FixtureConformsToTR(t *testing.T) {
	raw, err := os.ReadFile("../../docs/superpowers/fixtures/vc-render-method-phase0.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	single := map[string]any{}
	for key, value := range fixture["singleObject"] {
		var decoded any
		if err := json.Unmarshal(value, &decoded); err != nil {
			t.Fatal(err)
		}
		single[key] = decoded
	}
	credential := CredentialData(single)

	var methods []RenderMethod
	if err := json.Unmarshal(fixture["multipleArray"]["renderMethod"], &methods); err != nil {
		t.Fatal(err)
	}
	for i, method := range methods {
		if err := method.Validate(); err != nil {
			t.Fatalf("multipleArray.renderMethod[%d].Validate() error = %v", i, err)
		}
		if method.RenderSuite != "summary" {
			continue
		}
		if _, err := method.RenderSummary(context.Background(), credential, RenderOptions{}); err != nil {
			t.Fatalf("RenderSummary(multipleArray.renderMethod[%d]) error = %v", i, err)
		}
	}

	var unsupported RenderMethod
	if err := json.Unmarshal(fixture["unsupportedSuite"]["renderMethod"], &unsupported); err != nil {
		t.Fatal(err)
	}
	if err := unsupported.Validate(); err != nil {
		t.Fatalf("unsupportedSuite.Validate() error = %v", err)
	}
}

func TestRenderSummaryTreatsNullLikeAMissingPointer(t *testing.T) {
	credential := CredentialData{"credentialSubject": map[string]any{"name": "Alice", "middleName": nil, "photo": nil}}
	summary := func(template string) RenderMethod {
		return RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Embedded: &EmbeddedTemplate{
			MediaType: "application/json", Bytes: []byte(template),
		}}}
	}

	// An optional member that lands on null is omitted.
	got, err := (summary(`{"name":"Degree","description":"D","icon":"/credentialSubject/photo","fields":[{"label":"Name","value":"/credentialSubject/name"}]}`)).RenderSummary(context.Background(), credential, RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Icon != "" {
		t.Fatalf("icon = %q, want it omitted", got.Icon)
	}

	// A required member that lands on null fails.
	if got, err := (summary(`{"name":"Degree","description":"D","fields":[{"label":"Middle name","value":"/credentialSubject/middleName"}]}`)).RenderSummary(context.Background(), credential, RenderOptions{}); err == nil {
		t.Fatalf("RenderSummary() = %+v, want a null pointer error", got)
	}
}
