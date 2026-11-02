package vc

import (
	"context"
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
