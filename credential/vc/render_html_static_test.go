package vc

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestWrapHTMLTemplateFiltersNestedProperties(t *testing.T) {
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "html", RenderProperty: []string{"/credentialSubject/name"}, Template: &Template{Embedded: &EmbeddedTemplate{MediaType: "text/html", Bytes: []byte(`<div>hello</div>`)}}}
	artifact, err := method.WrapHTMLTemplate(context.Background(), CredentialData{"credentialSubject": map[string]any{"name": "Alice", "secret": "x"}}, RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.SrcDoc == "" || !contains(artifact.SrcDoc, "Alice") || contains(artifact.SrcDoc, "secret") {
		t.Fatalf("artifact leaked or empty: %s", artifact.SrcDoc)
	}
}

func TestWrapHTMLTemplateUsesJSONLDSelectionMetadata(t *testing.T) {
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "html", RenderProperty: []string{"/credentialSubject/name"}, Template: &Template{Embedded: &EmbeddedTemplate{MediaType: "text/html", Bytes: []byte(`<div>hello</div>`)}}}
	artifact, err := method.WrapHTMLTemplate(context.Background(), CredentialData{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		"type":     []any{"VerifiableCredential"},
		"credentialSubject": map[string]any{
			"id":     "did:example:subject",
			"type":   []any{"Person"},
			"name":   "Alice",
			"secret": "hidden",
		},
	}, RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	const start = `<script name="credential" type="application/vc">`
	startAt := strings.Index(artifact.SrcDoc, start) + len(start)
	endAt := strings.Index(artifact.SrcDoc[startAt:], `</script>`)
	var filtered map[string]any
	if err := json.Unmarshal([]byte(artifact.SrcDoc[startAt:startAt+endAt]), &filtered); err != nil {
		t.Fatal(err)
	}
	if _, ok := filtered["@context"]; !ok {
		t.Fatalf("filtered credential lost @context: %#v", filtered)
	}
	subject := filtered["credentialSubject"].(map[string]any)
	if subject["id"] != "did:example:subject" || subject["type"].([]any)[0] != "Person" || subject["name"] != "Alice" {
		t.Fatalf("filtered JSON-LD metadata = %#v", subject)
	}
	if _, ok := subject["secret"]; ok {
		t.Fatalf("filtered credential leaked secret: %#v", subject)
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

	artifact, err := method.WrapHTMLTemplate(context.Background(), CredentialData{"name": "Alice"}, RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if !contains(artifact.SrcDoc, `<script name="credential" type="application/vc">`) {
		t.Fatalf("artifact does not contain the W3C credential data block: %s", artifact.SrcDoc)
	}
	// WD-20261013 §2.2.2.2.3: the wrapper receives the port and provides
	// window.renderMethodReady, after the data block and before the template.
	setup := `<script>` + renderMethodReadySetup + `</script>`
	dataBlock := strings.Index(artifact.SrcDoc, `<script name="credential" type="application/vc">`)
	ready := strings.Index(artifact.SrcDoc, setup)
	body := strings.Index(artifact.SrcDoc, `<body>`)
	if ready < 0 || !(dataBlock < ready && ready < body) {
		t.Fatalf("artifact must carry the wrapper script between the data block and <body>: %s", artifact.SrcDoc)
	}
	for _, want := range []string{"window.renderMethodReady = function(err)", "event.data === 'start'", "port.postMessage("} {
		if !contains(artifact.SrcDoc, want) {
			t.Fatalf("wrapper script missing %q", want)
		}
	}
	for _, want := range []string{
		`<html><head>`,
		`<meta http-equiv="Content-Security-Policy" content="default-src data: 'unsafe-inline'">`,
		`</script></head><body><div>hello</div></body></html>`,
	} {
		if !contains(artifact.SrcDoc, want) {
			t.Fatalf("artifact missing wrapper fragment %q: %s", want, artifact.SrcDoc)
		}
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
	artifact, err := method.WrapHTMLTemplate(context.Background(), CredentialData{
		"name": `Alice "The Engineer" </script><script>alert(1)</script>`,
	}, RenderOptions{})
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
	artifact, err := method.WrapHTMLTemplate(context.Background(), CredentialData{
		"credentialSubject": map[string]any{
			"items": []any{
				map[string]any{"name": "Alice"},
				map[string]any{"name": "Bob"},
			},
		},
	}, RenderOptions{})
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
	if _, err := method.WrapHTMLTemplate(context.Background(), CredentialData{}, RenderOptions{}); err == nil {
		t.Fatal("WrapHTMLTemplate() error = nil")
	}
}

func TestWrapHTMLTemplateAcceptsHeaderFragment(t *testing.T) {
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "html", Template: &Template{Embedded: &EmbeddedTemplate{MediaType: "text/html", Bytes: []byte(`<header>ok</header>`)}}}
	if _, err := method.WrapHTMLTemplate(context.Background(), CredentialData{}, RenderOptions{}); err != nil {
		t.Fatalf("WrapHTMLTemplate() rejected header fragment: %v", err)
	}
}

func TestResolveStaticReturnsPayloadAndMetadata(t *testing.T) {
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "static", DeliveryMode: "nfc", Template: &Template{Embedded: &EmbeddedTemplate{MediaType: "application/octet-stream", Bytes: []byte{0, 1, 2}}}}
	output, err := method.ResolveStatic(context.Background(), CredentialData{}, RenderOptions{})
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

func TestWrapHTMLTemplateValidatesExternalMediaType(t *testing.T) {
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "html", Template: &Template{Reference: &TemplateReference{
		ID: "https://example.com/template.html", MediaType: "application/json",
	}}}
	opts := RenderOptions{Fetcher: summaryFetcher{data: []byte(`<div>Hello</div>`)}}
	if _, err := method.WrapHTMLTemplate(context.Background(), CredentialData{}, opts); err == nil {
		t.Fatal("WrapHTMLTemplate() error = nil, want media type error")
	}
	method.Template.Reference.MediaType = ""
	if _, err := method.WrapHTMLTemplate(context.Background(), CredentialData{}, opts); err != nil {
		t.Fatalf("WrapHTMLTemplate() without mediaType error = %v", err)
	}
}

func TestResolveStaticAllowsMissingDeliveryMode(t *testing.T) {
	payload := []byte{0x89, 'P', 'N', 'G'}
	methods := map[string]RenderMethod{
		"embedded": {Type: "SuiteRenderMethod", RenderSuite: "static", Template: &Template{Embedded: &EmbeddedTemplate{
			MediaType: "image/png", Bytes: payload,
		}}},
		"reference": {Type: "SuiteRenderMethod", RenderSuite: "static", Template: &Template{Reference: &TemplateReference{
			ID: "https://example.com/card.png", MediaType: "image/png",
		}}},
	}
	for name, method := range methods {
		t.Run(name, func(t *testing.T) {
			output, err := method.ResolveStatic(context.Background(), CredentialData{}, RenderOptions{Fetcher: summaryFetcher{data: payload}})
			if err != nil {
				t.Fatalf("ResolveStatic() error = %v", err)
			}
			if output.DeliveryMode != "" || len(output.Bytes) != len(payload) {
				t.Fatalf("output = %+v", output)
			}
		})
	}
}

// A fetched template goes through the same fragment rule as an embedded one, in
// templateBytes, so WrapHTMLTemplate needs no check of its own.
func TestWrapHTMLTemplateRejectsFetchedDocument(t *testing.T) {
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "html", Template: &Template{Reference: &TemplateReference{
		ID: "https://example.com/template.html", MediaType: "text/html",
	}}}
	for _, doc := range []string{`<html>bad</html>`, `<head></head>`, `<body>bad</body>`} {
		opts := RenderOptions{Fetcher: summaryFetcher{data: []byte(doc)}}
		if _, err := method.WrapHTMLTemplate(context.Background(), CredentialData{}, opts); err == nil {
			t.Errorf("WrapHTMLTemplate() with fetched %q error = nil, want fragment error", doc)
		}
	}
}
