package vc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

type testTemplateFetcher struct {
	data []byte
}

func (f testTemplateFetcher) Fetch(context.Context, TemplateReference) ([]byte, error) {
	return f.data, nil
}

func baseRenderContents(methods []RenderMethod) CredentialContents {
	return CredentialContents{Context: []interface{}{"https://www.w3.org/ns/credentials/v2"}, Types: []string{"VerifiableCredential"}, Issuer: "did:example:issuer", Subject: []Subject{{ID: "did:example:subject"}}, RenderMethods: methods}
}

func TestSerializeCredentialContentsRenderMethodDoesNotInjectContext(t *testing.T) {
	cred, err := NewJSONCredential(baseRenderContents([]RenderMethod{{Type: "SuiteRenderMethod", RenderSuite: "summary"}}))
	if err != nil {
		t.Fatalf("NewJSONCredential() error = %v", err)
	}
	raw, err := cred.GetContents()
	if err != nil {
		t.Fatalf("GetContents() error = %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal contents: %v", err)
	}
	contexts := doc["@context"].([]interface{})
	if len(contexts) != 1 || contexts[0] != "https://www.w3.org/ns/credentials/v2" {
		t.Fatalf("contexts = %#v, want caller-supplied context only", contexts)
	}
}

func TestSerializeCredentialContentsRenderMethodArray(t *testing.T) {
	contents := baseRenderContents([]RenderMethod{{Type: "SuiteRenderMethod", RenderSuite: "summary"}, {Type: "SuiteRenderMethod", RenderSuite: "html"}})
	doc, err := serializeCredentialContents(&contents)
	if err != nil {
		t.Fatalf("serializeCredentialContents() error = %v", err)
	}
	methods, ok := doc["renderMethod"].([]interface{})
	if !ok || len(methods) != 2 {
		t.Fatalf("renderMethod = %#v, want an array of two methods", doc["renderMethod"])
	}
}

func TestSerializeCredentialContentsRejectsIncompleteRenderMethod(t *testing.T) {
	contents := baseRenderContents([]RenderMethod{{RenderSuite: "summary"}})
	if _, err := serializeCredentialContents(&contents); err == nil {
		t.Fatal("serializeCredentialContents() error = nil, want missing type error")
	}
}

func TestRenderMethodTemplateReferenceRoundTripsBothDigests(t *testing.T) {
	method := RenderMethod{ID: "https://example.com/render-method.jsonld", Type: "SuiteRenderMethod", RenderSuite: "summary", DigestMultibase: testDigest([]byte("render method")), Template: &Template{Reference: &TemplateReference{ID: "https://example.com/template.json", MediaType: "application/json", DigestMultibase: testDigest([]byte("template"))}}}
	b, err := json.Marshal(method)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var got RenderMethod
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got.ID != method.ID || got.DigestMultibase != method.DigestMultibase || got.Template == nil || got.Template.Reference == nil || got.Template.Reference.DigestMultibase != method.Template.Reference.DigestMultibase {
		t.Fatalf("round trip = %#v, want both digest layers preserved", got)
	}
}

func TestRenderMethodRejectsInvalidURLs(t *testing.T) {
	contents := baseRenderContents([]RenderMethod{{Type: "SuiteRenderMethod", RenderSuite: "summary", ID: "not a url"}})
	if _, err := serializeCredentialContents(&contents); err == nil {
		t.Fatal("serializeCredentialContents() error = nil, want invalid render method URL error")
	}

	contents = baseRenderContents([]RenderMethod{{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Reference: &TemplateReference{ID: "//missing-scheme"}}}})
	if _, err := serializeCredentialContents(&contents); err == nil {
		t.Fatal("serializeCredentialContents() error = nil, want invalid template reference URL error")
	}

	for _, scheme := range []string{"file:///tmp/template.json", "ftp://example.com/template.json", "javascript:alert(1)", "http://:8080/template.json", "https://:443"} {
		contents = baseRenderContents([]RenderMethod{{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Reference: &TemplateReference{ID: scheme}}}})
		if _, err := serializeCredentialContents(&contents); err == nil {
			t.Errorf("serializeCredentialContents() error = nil for %q, want unsupported URL scheme error", scheme)
		}
	}
}

func TestRenderMethodValidatesRenderProperties(t *testing.T) {
	valid := []string{"", "/credentialSubject/name", "/a~1b/~0key"}
	for _, pointer := range valid {
		method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "html", RenderProperty: []string{pointer}}
		if err := method.Validate(); err != nil {
			t.Errorf("Validate() for pointer %q error = %v", pointer, err)
		}
	}

	for _, pointer := range []string{"credentialSubject/name", "/a~2b", "/a~"} {
		method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "html", RenderProperty: []string{pointer}}
		if err := method.Validate(); err == nil {
			t.Errorf("Validate() for pointer %q error = nil, want invalid JSON Pointer error", pointer)
		}
	}
}

func TestRenderMethodValidatesEmbeddedSuiteTemplates(t *testing.T) {
	tests := []struct {
		name   string
		method RenderMethod
		wantOK bool
	}{
		{
			name: "summary",
			method: RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Embedded: &EmbeddedTemplate{
				MediaType: "application/json",
				Bytes:     []byte(`{"name":"Degree","description":"Summary","fields":[{"label":"Name","value":"/credentialSubject/name"}]}`),
			}}},
			wantOK: true,
		},
		{
			name: "html fragment",
			method: RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "html", Template: &Template{Embedded: &EmbeddedTemplate{
				MediaType: "text/html",
				Bytes:     []byte("<div>hello</div>"),
			}}},
			wantOK: true,
		},
		{
			name: "static without delivery mode",
			method: RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "static", Template: &Template{Embedded: &EmbeddedTemplate{
				MediaType: "application/octet-stream",
				Bytes:     []byte("payload"),
			}}},
			wantOK: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.method.Validate()
			if (err == nil) != tt.wantOK {
				t.Fatalf("Validate() error = %v, wantOK = %v", err, tt.wantOK)
			}
		})
	}
}

func TestRenderMethodRejectsJSONPointerSummaryLabel(t *testing.T) {
	method := RenderMethod{
		Type:        "SuiteRenderMethod",
		RenderSuite: "summary",
		Template: &Template{Embedded: &EmbeddedTemplate{
			MediaType: "application/json",
			Bytes:     []byte(`{"name":"Degree","description":"Summary","fields":[{"label":"/issuer/name","value":"/credentialSubject/name"}]}`),
		}},
	}

	if err := method.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want JSON Pointer label error")
	}
}

func TestRenderMethodValidatesExternalTemplateOnRequest(t *testing.T) {
	data := []byte(`{"name":"Degree","description":"Summary","fields":[{"label":"Name","value":"/credentialSubject/name"}]}`)
	hash := sha256.Sum256(data)
	multihash := append([]byte{0x12, 0x20}, hash[:]...)
	digest := "u" + base64.RawURLEncoding.EncodeToString(multihash)
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Reference: &TemplateReference{
		ID: "https://example.com/template.json", MediaType: "application/json", DigestMultibase: digest,
	}}}
	if err := method.ValidateExternalTemplate(context.Background(), testTemplateFetcher{data: data}); err != nil {
		t.Fatalf("ValidateExternalTemplate() error = %v", err)
	}

	method.Template.Reference.DigestMultibase = testDigest([]byte("other bytes"))
	if err := method.ValidateExternalTemplate(context.Background(), testTemplateFetcher{data: data}); err == nil {
		t.Fatal("ValidateExternalTemplate() error = nil, want digest verification error")
	}
}

func TestRenderMethodCanonicalizationPreservesPhase15Fields(t *testing.T) {
	contents := CredentialContents{
		Context: []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2",
		},
		Types:   []string{"VerifiableCredential"},
		Issuer:  "did:example:issuer",
		Subject: []Subject{{ID: "did:example:subject"}},
		RenderMethods: []RenderMethod{{
			ID:             "https://example.com/render-method",
			Type:           "SuiteRenderMethod",
			RenderSuite:    "html",
			RenderProperty: []string{"/credentialSubject/name"},
			Template: &Template{Embedded: &EmbeddedTemplate{
				MediaType: "text/html",
				Bytes:     []byte("<p>{{name}}</p>"),
			}},
			DigestMultibase: testDigest([]byte("render method")),
			OutputPreference: &OutputPreference{
				AccessMode: []string{"visual"},
				MediaType:  "text/html",
				Style:      &RenderStyle{Width: "100px", Height: "50px"},
			},
			DeliveryMode: "download",
		}},
	}

	credential, err := NewJSONCredential(contents)
	if err != nil {
		t.Fatalf("NewJSONCredential() error = %v", err)
	}
	if _, err := credential.GetSigningInput(); err != nil {
		t.Fatalf("GetSigningInput() error = %v", err)
	}
}

func TestRenderMethodCanonicalizationRejectsMissingRenderContext(t *testing.T) {
	contents := baseRenderContents([]RenderMethod{{
		Type:        "SuiteRenderMethod",
		RenderSuite: "summary",
	}})

	credential, err := NewJSONCredential(contents)
	if err != nil {
		t.Fatalf("NewJSONCredential() error = %v", err)
	}
	if _, err := credential.GetSigningInput(); err == nil {
		t.Fatal("GetSigningInput() error = nil, want unresolved render-method context error")
	}
}

func TestCredentialWithoutRenderMethodKeepsMainBytes(t *testing.T) {
	credential, err := NewJSONCredential(CredentialContents{Context: []interface{}{"https://www.w3.org/ns/credentials/v2"}, ID: "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5", Types: []string{"VerifiableCredential"}, Issuer: "did:example:issuer", ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Subject: []Subject{{ID: "did:example:subject"}}})
	if err != nil {
		t.Fatalf("NewJSONCredential() error = %v", err)
	}
	contents, err := credential.GetContents()
	if err != nil {
		t.Fatalf("GetContents() error = %v", err)
	}
	signingInput, err := credential.GetSigningInput()
	if err != nil {
		t.Fatalf("GetSigningInput() error = %v", err)
	}
	for name, check := range map[string]struct {
		data []byte
		want string
	}{
		"contents":     {contents, "bc3fdc25b66ae2ad030d8e974dda41788d8b1dcb1b661881ccd790df5d481720"},
		"signingInput": {signingInput, "6b00af56257156342c796b8f11079faf0ab108675dd0706f8cc6aa8f824eef69"},
	} {
		sum := sha256.Sum256(check.data)
		if got := hex.EncodeToString(sum[:]); got != check.want {
			t.Errorf("sha256(%s) = %s, want %s", name, got, check.want)
		}
	}
}

func TestConstructedRenderMethodUsesJSONNativeSnapshot(t *testing.T) {
	template := &Template{Embedded: &EmbeddedTemplate{MediaType: "application/json", Bytes: []byte(`{"name":"Degree","description":"Summary","fields":[{"label":"Name","value":"/credentialSubject/name"}]}`)}}
	credential, err := NewJSONCredential(baseRenderContents([]RenderMethod{{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: template}}))
	if err != nil {
		t.Fatalf("NewJSONCredential() error = %v", err)
	}
	if got := credential.ExtractField("renderMethod.renderSuite"); got != "summary" {
		t.Fatalf("ExtractField() = %#v, want summary", got)
	}
	before, err := credential.GetContents()
	if err != nil {
		t.Fatal(err)
	}
	template.Embedded.Bytes = []byte(`{"name":"changed"}`)
	after, err := credential.GetContents()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("credential contents changed after caller mutation")
	}
}

func TestRenderMethodCredentialRoundTripsObjectAndArray(t *testing.T) {
	for _, methods := range [][]RenderMethod{{{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Embedded: &EmbeddedTemplate{MediaType: "application/json", Bytes: []byte(`{"name":"Degree","description":"Summary","fields":[{"label":"Name","value":"/credentialSubject/name"}]}`)}}}}, {{Type: "SuiteRenderMethod", RenderSuite: "summary"}, {Type: "SuiteRenderMethod", RenderSuite: "html"}}} {
		created, err := NewJSONCredential(baseRenderContents(methods))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := created.GetContents()
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseJSONCredential(raw)
		if err != nil {
			t.Fatal(err)
		}
		parsedRaw, err := parsed.GetContents()
		if err != nil {
			t.Fatal(err)
		}
		var original, roundTripped map[string]interface{}
		if err := json.Unmarshal(raw, &original); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(parsedRaw, &roundTripped); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(original["renderMethod"], roundTripped["renderMethod"]) {
			t.Fatalf("renderMethod changed after parse")
		}
	}
}

func TestRenderMethodTemplatePercentEncodedDataURL(t *testing.T) {
	var got Template
	if err := json.Unmarshal([]byte(`"data:application/json,%7B%22name%22%3A%22Alice%22%7D"`), &got); err != nil {
		t.Fatal(err)
	}
	if got.Embedded == nil || string(got.Embedded.Bytes) != `{"name":"Alice"}` {
		t.Fatalf("embedded template = %#v", got.Embedded)
	}
}

func TestTemplateLargerThanOneMiBRoundTrips(t *testing.T) {
	// The SDK sets no template size limit: what an issuer signs, a consumer reads.
	big := `{"name":"N","description":"` + strings.Repeat("x", 2<<20) + `","fields":[{"label":"L","value":"/id"}]}`
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Embedded: &EmbeddedTemplate{
		MediaType: "application/json", Bytes: []byte(big),
	}}}
	created, err := NewJSONCredential(baseRenderContents([]RenderMethod{method}))
	if err != nil {
		t.Fatalf("NewJSONCredential() error = %v", err)
	}
	raw, err := created.GetContents()
	if err != nil {
		t.Fatal(err)
	}
	var data CredentialData
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	methods, err := ParseRenderMethods(data)
	if err != nil {
		t.Fatalf("ParseRenderMethods() error = %v", err)
	}
	if len(methods) != 1 || string(methods[0].Template.Embedded.Bytes) != big {
		t.Fatal("embedded template changed after the round trip")
	}
}

func TestTemplateUnmarshalReplacesPreviousRepresentation(t *testing.T) {
	var template Template
	if err := json.Unmarshal([]byte(`"data:application/json,%7B%7D"`), &template); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"id":"https://example.com/template.json"}`), &template); err != nil {
		t.Fatal(err)
	}
	if template.Embedded != nil || template.Reference == nil {
		t.Fatalf("template = %+v, want only reference representation", template)
	}
	if _, err := json.Marshal(template); err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
}

func TestValidateExternalTemplateDefaultsMissingMediaType(t *testing.T) {
	data := []byte(`{"name":"Degree","description":"Summary","fields":[{"label":"Name","value":"/credentialSubject/name"}]}`)
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Reference: &TemplateReference{
		ID: "https://example.com/template.json",
	}}}
	if err := method.ValidateExternalTemplate(context.Background(), testTemplateFetcher{data: data}); err != nil {
		t.Fatalf("ValidateExternalTemplate() error = %v", err)
	}
	literal := []byte(`{"name":"Degree","description":"Summary","fields":[{"label":"Name","value":"Alice"}]}`)
	if err := method.ValidateExternalTemplate(context.Background(), testTemplateFetcher{data: literal}); err == nil {
		t.Fatal("ValidateExternalTemplate() error = nil, want literal value error")
	}
}

func testDigest(data []byte) string {
	hash := sha256.Sum256(data)
	return "u" + base64.RawURLEncoding.EncodeToString(append([]byte{0x12, 0x20}, hash[:]...))
}

func TestRenderMethodValidatesDigestMultibaseSyntax(t *testing.T) {
	valid := testDigest([]byte("template"))
	invalid := map[string]string{
		"base58btc prefix":   "z" + valid[1:],
		"no multibase":       valid[1:],
		"not base64url":      "u!!!",
		"short hash":         "u" + base64.RawURLEncoding.EncodeToString(append([]byte{0x12, 0x20}, make([]byte, 31)...)),
		"not sha2-256":       "u" + base64.RawURLEncoding.EncodeToString(append([]byte{0x13, 0x20}, make([]byte, 32)...)),
		"padded base64url":   valid + "=",
		"placeholder suffix": "uInner",
	}
	reference := func(digest string) RenderMethod {
		return RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Reference: &TemplateReference{
			ID: "https://example.com/template.json", MediaType: "application/json", DigestMultibase: digest,
		}}}
	}
	outer := func(digest string) RenderMethod {
		return RenderMethod{ID: "https://example.com/render-method.json", Type: "SuiteRenderMethod", RenderSuite: "summary", DigestMultibase: digest}
	}
	for _, build := range []func(string) RenderMethod{reference, outer} {
		if err := build(valid).Validate(); err != nil {
			t.Fatalf("Validate() with valid digest error = %v", err)
		}
		for name, digest := range invalid {
			if err := build(digest).Validate(); err == nil {
				t.Errorf("%s: Validate() error = nil, want digestMultibase syntax error", name)
			}
		}
	}

	contents := baseRenderContents([]RenderMethod{reference("uInner")})
	if _, err := NewJSONCredential(contents); err == nil {
		t.Fatal("NewJSONCredential() error = nil, want digestMultibase syntax error")
	}
}

func parseRenderMethodsInput(t *testing.T, document string) CredentialData {
	t.Helper()
	var data CredentialData
	if err := json.Unmarshal([]byte(document), &data); err != nil {
		t.Fatal(err)
	}
	return data
}

const testSummaryTemplateDataURL = `data:application/json,%7B%22name%22%3A%22Degree%22%2C%22description%22%3A%22Example%22%2C%22fields%22%3A%5B%5D%7D`

func TestParseRenderMethodsAcceptsSingleObject(t *testing.T) {
	data := parseRenderMethodsInput(t, `{"renderMethod": {"type": "SuiteRenderMethod", "renderSuite": "summary", "template": "`+testSummaryTemplateDataURL+`"}}`)
	methods, err := ParseRenderMethods(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(methods) != 1 || methods[0].RenderSuite != "summary" || methods[0].Template == nil || methods[0].Template.Embedded == nil {
		t.Fatalf("methods = %+v", methods)
	}
}

func TestParseRenderMethodsKeepsDocumentOrder(t *testing.T) {
	data := parseRenderMethodsInput(t, `{"renderMethod": [
		{"type": "SuiteRenderMethod", "renderSuite": "static", "template": "data:application/octet-stream;base64,AA=="},
		{"type": "SuiteRenderMethod", "renderSuite": "summary", "template": "`+testSummaryTemplateDataURL+`"},
		{"type": "SuiteRenderMethod", "renderSuite": "html", "template": "data:text/html,%3Cp%3Ehi%3C%2Fp%3E"}
	]}`)
	methods, err := ParseRenderMethods(data)
	if err != nil {
		t.Fatal(err)
	}
	var suites []string
	for _, method := range methods {
		suites = append(suites, method.RenderSuite)
	}
	if !reflect.DeepEqual(suites, []string{"static", "summary", "html"}) {
		t.Fatalf("suites = %v, want document order", suites)
	}
}

func TestParseRenderMethodsSkipsEntriesTheSDKMustIgnore(t *testing.T) {
	// The unknown suite carries a template no supported suite would accept, so
	// decoding it would fail: it must be skipped before the typed decode.
	data := parseRenderMethodsInput(t, `{"renderMethod": [
		{"type": "SuiteRenderMethod", "renderSuite": "audio", "template": 42},
		{"type": "TemplateRenderMethod", "renderSuite": "summary", "template": "`+testSummaryTemplateDataURL+`"},
		{"type": "SuiteRenderMethod", "renderSuite": "html", "id": "https://example.com/render-method.json"},
		{"type": "SuiteRenderMethod", "renderSuite": "summary", "template": "`+testSummaryTemplateDataURL+`"}
	]}`)
	methods, err := ParseRenderMethods(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(methods) != 1 || methods[0].RenderSuite != "summary" {
		t.Fatalf("methods = %+v, want only the supported summary entry", methods)
	}
}

func TestParseRenderMethodsWithoutRenderMethod(t *testing.T) {
	methods, err := ParseRenderMethods(parseRenderMethodsInput(t, `{"type": ["VerifiableCredential"]}`))
	if err != nil || methods != nil {
		t.Fatalf("ParseRenderMethods() = %v, %v; want nil, nil", methods, err)
	}
}

func TestParseRenderMethodsReportsInvalidSupportedEntry(t *testing.T) {
	cases := map[string]string{
		"not an object":          `{"renderMethod": [{"type": "SuiteRenderMethod", "renderSuite": "summary", "template": "` + testSummaryTemplateDataURL + `"}, "summary"]}`,
		"invalid template":       `{"renderMethod": [{"type": "SuiteRenderMethod", "renderSuite": "summary", "template": "` + testSummaryTemplateDataURL + `"}, {"type": "SuiteRenderMethod", "renderSuite": "summary", "template": "not a url"}]}`,
		"invalid renderProperty": `{"renderMethod": [{"type": "SuiteRenderMethod", "renderSuite": "summary", "template": "` + testSummaryTemplateDataURL + `"}, {"type": "SuiteRenderMethod", "renderSuite": "html", "renderProperty": ["credentialSubject"], "template": "data:text/html,%3Cp%3Ehi%3C%2Fp%3E"}]}`,
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseRenderMethods(parseRenderMethodsInput(t, document))
			if err == nil || !strings.Contains(err.Error(), "renderMethod[1]") {
				t.Fatalf("ParseRenderMethods() error = %v, want an error for renderMethod[1]", err)
			}
		})
	}
}

func TestParseRenderMethodsRefusesUndefinedTermsWithEmbeddedProof(t *testing.T) {
	const credential = `{
		"@context": CONTEXT,
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject"},
		"renderMethod": {"type": "SuiteRenderMethod", "renderSuite": "summary", "template": "` + testSummaryTemplateDataURL + `"},
		"proof": {
			"type": "DataIntegrityProof",
			"cryptosuite": "ecdsa-rdfc-2019",
			"proofPurpose": "assertionMethod",
			"verificationMethod": "did:example:issuer#key-1",
			"proofValue": "z5xcgdyb8ZFV7tN9A8MdkkAjbcZQkDWqgxuxzuq5WtxrGNaTsGdTKw27Uod1Zfaj3SijwkD4HhU1rGWbyGBomZXuR"
		}
	}`

	// The VC 2.0 context defines renderMethod but not renderSuite or template,
	// so those terms would be dropped from what the proof signs.
	undefined := parseRenderMethodsInput(t, strings.Replace(credential, "CONTEXT", `["https://www.w3.org/ns/credentials/v2"]`, 1))
	if _, err := ParseRenderMethods(undefined); err == nil {
		t.Fatal("ParseRenderMethods() error = nil, want undefined-term error")
	}

	// A context that defines the terms makes the same credential readable.
	defined := parseRenderMethodsInput(t, strings.Replace(credential, "CONTEXT", `["https://www.w3.org/ns/credentials/v2", {"@vocab": "https://example.com/vocab#"}]`, 1))
	methods, err := ParseRenderMethods(defined)
	if err != nil {
		t.Fatalf("ParseRenderMethods() error = %v", err)
	}
	if len(methods) != 1 {
		t.Fatalf("methods = %+v", methods)
	}

	// Without an embedded proof (for example a JOSE payload) the expansion is
	// skipped, because the signature covers the bytes rather than the terms.
	delete(undefined, "proof")
	if _, err := ParseRenderMethods(undefined); err != nil {
		t.Fatalf("ParseRenderMethods() without proof error = %v", err)
	}
}

func TestTemplateDecodesEveryValidDataURL(t *testing.T) {
	cases := []struct {
		raw       string
		mediaType string
		bytes     string
	}{
		{`data:,A%20brief%20note`, "", "A brief note"}, // RFC 2397 §4 example
		{`DATA:text/plain,hello`, "text/plain", "hello"},
		{`data:text/plain;BASE64,aGVsbG8=`, "text/plain", "hello"},
		{`data:text/plain;base64,aGVsbG8%3D`, "text/plain", "hello"},
		{`data:text/plain;base64,aGVsbG8=`, "text/plain", "hello"},
		{`data:application/json,%7B%22a%22%3A1%7D`, "application/json", `{"a":1}`},
	}
	for _, tc := range cases {
		var template Template
		if err := json.Unmarshal([]byte(`"`+tc.raw+`"`), &template); err != nil {
			t.Errorf("%s: json.Unmarshal() error = %v", tc.raw, err)
			continue
		}
		if template.Embedded == nil || template.Embedded.MediaType != tc.mediaType || string(template.Embedded.Bytes) != tc.bytes {
			t.Errorf("%s: got %+v, want media type %q and bytes %q", tc.raw, template, tc.mediaType, tc.bytes)
		}
	}
	for _, raw := range []string{`data:text/plain`, `data:text/plain;base64,!!!`, `data:text/plain,%zz`} {
		var template Template
		if err := json.Unmarshal([]byte(`"`+raw+`"`), &template); err == nil {
			t.Errorf("%s: json.Unmarshal() error = nil, want an invalid data URL error", raw)
		}
	}
}

func TestRenderMethodComparesParsedTemplateMediaType(t *testing.T) {
	summary := []byte(`{"name":"Degree","description":"Summary","fields":[{"label":"Name","value":"/credentialSubject/name"}]}`)
	cases := []struct {
		suite, mediaType string
		bytes            []byte
		wantOK           bool
	}{
		{"summary", "application/json", summary, true},
		{"summary", "application/json;charset=utf-8", summary, true},
		{"summary", "Application/JSON; charset=UTF-8", summary, true},
		{"summary", "text/plain", summary, false},
		{"summary", "", summary, false},
		{"html", "text/html", []byte("<p>hi</p>"), true},
		{"html", "text/html; charset=utf-8", []byte("<p>hi</p>"), true},
		{"html", "TEXT/HTML", []byte("<p>hi</p>"), true},
		{"html", "application/xhtml+xml", []byte("<p>hi</p>"), false},
	}
	for _, tc := range cases {
		method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: tc.suite, Template: &Template{Embedded: &EmbeddedTemplate{MediaType: tc.mediaType, Bytes: tc.bytes}}}
		if err := method.Validate(); (err == nil) != tc.wantOK {
			t.Errorf("%s with %q: Validate() error = %v, wantOK = %v", tc.suite, tc.mediaType, err, tc.wantOK)
		}
	}
}

func TestRenderMethodValidatesEveryMediaType(t *testing.T) {
	summary := []byte(`{"name":"Degree","description":"Summary","fields":[{"label":"Name","value":"/credentialSubject/name"}]}`)
	reference := func(mediaType string) RenderMethod {
		return RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Reference: &TemplateReference{
			ID: "https://example.com/template.json", MediaType: mediaType,
		}}}
	}
	output := func(mediaType string) RenderMethod {
		return RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary",
			Template:         &Template{Embedded: &EmbeddedTemplate{MediaType: "application/json", Bytes: summary}},
			OutputPreference: &OutputPreference{MediaType: mediaType},
		}
	}
	for _, build := range []func(string) RenderMethod{reference, output} {
		for _, mediaType := range []string{"", "application/json", "text/html; charset=utf-8"} {
			if err := build(mediaType).Validate(); err != nil {
				t.Errorf("Validate() with mediaType %q error = %v", mediaType, err)
			}
		}
		for _, mediaType := range []string{"not a type", "text/", "/html", "text/html;charset"} {
			if err := build(mediaType).Validate(); err == nil {
				t.Errorf("Validate() with mediaType %q error = nil, want invalid media type", mediaType)
			}
		}
	}
	contents := baseRenderContents([]RenderMethod{reference("not a type")})
	if _, err := NewJSONCredential(contents); err == nil {
		t.Fatal("NewJSONCredential() error = nil, want invalid media type")
	}
}

func TestRenderMethodValidatesOutputPreferenceAccessMode(t *testing.T) {
	summary := []byte(`{"name":"Degree","description":"Summary","fields":[{"label":"Name","value":"/credentialSubject/name"}]}`)
	method := func(accessMode []string) RenderMethod {
		return RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary",
			Template:         &Template{Embedded: &EmbeddedTemplate{MediaType: "application/json", Bytes: summary}},
			OutputPreference: &OutputPreference{AccessMode: accessMode},
		}
	}
	for _, valid := range [][]string{nil, {"visual"}, {"auditory", "tactile", "textual", "visual"}} {
		if err := method(valid).Validate(); err != nil {
			t.Errorf("Validate() with accessMode %v error = %v", valid, err)
		}
	}
	for _, invalid := range [][]string{{}, {"smell"}, {"online"}, {"visual", "Visual"}} {
		if err := method(invalid).Validate(); err == nil {
			t.Errorf("Validate() with accessMode %q error = nil, want invalid accessMode", invalid)
		}
	}
	var decoded RenderMethod
	if err := json.Unmarshal([]byte(`{"type":"SuiteRenderMethod","renderSuite":"summary","outputPreference":{"accessMode":[]}}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err == nil {
		t.Fatal("Validate() of a decoded empty accessMode error = nil, want an error")
	}
}
