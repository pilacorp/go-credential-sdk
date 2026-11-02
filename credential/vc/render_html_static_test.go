package vc

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestWrapHTMLTemplateFiltersNestedProperties(t *testing.T) {
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "html", RenderProperty: []string{"/credentialSubject/name"}, Template: &Template{Embedded: &EmbeddedTemplate{MediaType: "text/html", Bytes: []byte(`<div>hello</div>`)}}}
	artifact, err := WrapHTMLTemplate(context.Background(), CredentialData{"credentialSubject": map[string]any{"name": "Alice", "secret": "x"}}, method, SummaryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.SrcDoc == "" || !contains(artifact.SrcDoc, "Alice") || contains(artifact.SrcDoc, "secret") {
		t.Fatalf("artifact leaked or empty: %s", artifact.SrcDoc)
	}
}

func TestWrapHTMLTemplateUsesW3CCredentialDataBlock(t *testing.T) {
	method := RenderMethod{
		Type:        "SuiteRenderMethod",
		RenderSuite: "html",
		Template: &Template{Embedded: &EmbeddedTemplate{
			MediaType: "text/html",
			Bytes:     []byte(`<div>hello</div>`),
		}},
	}

	artifact, err := WrapHTMLTemplate(context.Background(), CredentialData{"name": "Alice"}, method, SummaryOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if !contains(artifact.SrcDoc, `<script name="credential" type="application/vc">`) {
		t.Fatalf("artifact does not contain the W3C credential data block: %s", artifact.SrcDoc)
	}
}

func TestWrapHTMLTemplateKeepsCredentialDataValidJSONInScript(t *testing.T) {
	method := RenderMethod{
		Type:        "SuiteRenderMethod",
		RenderSuite: "html",
		Template: &Template{Embedded: &EmbeddedTemplate{
			MediaType: "text/html",
			Bytes:     []byte(`<div>hello</div>`),
		}},
	}
	artifact, err := WrapHTMLTemplate(context.Background(), CredentialData{
		"name": `Alice "The Engineer" </script><script>alert(1)</script>`,
	}, method, SummaryOptions{})
	if err != nil {
		t.Fatal(err)
	}

	const start = `<script name="credential" type="application/vc">`
	startAt := strings.Index(artifact.SrcDoc, start)
	if startAt < 0 {
		t.Fatal("credential data block not found")
	}
	startAt += len(start)
	endAt := strings.Index(artifact.SrcDoc[startAt:], `</script>`)
	if endAt < 0 {
		t.Fatal("credential data block terminator not found")
	}
	rawJSON := artifact.SrcDoc[startAt : startAt+endAt]
	var decoded map[string]string
	if err := json.Unmarshal([]byte(rawJSON), &decoded); err != nil {
		t.Fatalf("credential data block is not valid JSON: %v; raw=%q", err, rawJSON)
	}
	if decoded["name"] == "" || strings.Contains(rawJSON, "</script>") {
		t.Fatalf("credential data block is not safely embedded: %q", rawJSON)
	}
}

func TestWrapHTMLTemplatePreservesArraysWhenFilteringProperties(t *testing.T) {
	method := RenderMethod{
		Type:           "SuiteRenderMethod",
		RenderSuite:    "html",
		RenderProperty: []string{"/credentialSubject/items/0/name"},
		Template: &Template{Embedded: &EmbeddedTemplate{
			MediaType: "text/html",
			Bytes:     []byte(`<div>hello</div>`),
		}},
	}
	artifact, err := WrapHTMLTemplate(context.Background(), CredentialData{
		"credentialSubject": map[string]any{
			"items": []any{
				map[string]any{"name": "Alice"},
				map[string]any{"name": "Bob"},
			},
		},
	}, method, SummaryOptions{})
	if err != nil {
		t.Fatal(err)
	}

	const start = `<script name="credential" type="application/vc">`
	startAt := strings.Index(artifact.SrcDoc, start)
	startAt += len(start)
	endAt := strings.Index(artifact.SrcDoc[startAt:], `</script>`)
	var filtered map[string]any
	if err := json.Unmarshal([]byte(artifact.SrcDoc[startAt:startAt+endAt]), &filtered); err != nil {
		t.Fatal(err)
	}
	credentialSubject := filtered["credentialSubject"].(map[string]any)
	items := credentialSubject["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["name"] != "Alice" {
		t.Fatalf("filtered items = %#v, want one-item array containing Alice", items)
	}
}

func TestWrapHTMLTemplateRejectsDocumentElements(t *testing.T) {
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "html", Template: &Template{Embedded: &EmbeddedTemplate{MediaType: "text/html", Bytes: []byte(`<html>bad</html>`)}}}
	if _, err := WrapHTMLTemplate(context.Background(), CredentialData{}, method, SummaryOptions{}); err == nil {
		t.Fatal("WrapHTMLTemplate() error = nil")
	}
}

func TestResolveStaticReturnsPayloadAndMetadata(t *testing.T) {
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "static", DeliveryMode: "nfc", Template: &Template{Embedded: &EmbeddedTemplate{MediaType: "application/octet-stream", Bytes: []byte{0, 1, 2}}}}
	output, err := ResolveStatic(context.Background(), CredentialData{}, method, SummaryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if output.MediaType != "application/octet-stream" || output.DeliveryMode != "nfc" || len(output.Bytes) != 3 {
		t.Fatalf("output = %+v", output)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
