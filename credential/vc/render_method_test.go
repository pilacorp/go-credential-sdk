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

type testFetcher struct {
	data []byte
	ref  TemplateReference
}

func (f *testFetcher) Fetch(_ context.Context, ref TemplateReference) ([]byte, error) {
	f.ref = ref
	return f.data, nil
}

func baseRenderContents(methods []RenderMethod) CredentialContents {
	return CredentialContents{Context: []interface{}{"https://www.w3.org/ns/credentials/v2"}, Types: []string{"VerifiableCredential"}, Issuer: "did:example:issuer", Subject: []Subject{{ID: "did:example:subject"}}, RenderMethods: methods}
}

func TestSerializeCredentialContentsRenderMethodDoesNotInjectContext(t *testing.T) {
	cred, err := NewJSONCredential(baseRenderContents([]RenderMethod{{Type: "SuiteRenderMethod", RenderSuite: "summary", ID: "https://example.com/summary.json"}}))
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
	contents := baseRenderContents([]RenderMethod{{Type: "SuiteRenderMethod", RenderSuite: "summary", ID: "https://example.com/summary.json"}, {Type: "SuiteRenderMethod", RenderSuite: "html", ID: "https://example.com/html.json"}})
	doc, err := serializeCredentialContents(&contents)
	if err != nil {
		t.Fatalf("serializeCredentialContents() error = %v", err)
	}
	methods, ok := doc["renderMethod"].([]interface{})
	if !ok || len(methods) != 2 {
		t.Fatalf("renderMethod = %#v, want an array of two methods", doc["renderMethod"])
	}
}

func TestSerializeCredentialContentsPreservesEmptyRenderProperty(t *testing.T) {
	contents := baseRenderContents([]RenderMethod{{Type: "SuiteRenderMethod", RenderSuite: "html", ID: "https://example.com/html.json", RenderProperty: []string{}}})
	doc, err := serializeCredentialContents(&contents)
	if err != nil {
		t.Fatalf("serializeCredentialContents() error = %v", err)
	}
	method := doc["renderMethod"].(map[string]interface{})
	if _, ok := method["renderProperty"]; !ok {
		t.Fatalf("renderMethod = %#v, want empty renderProperty", method)
	}
}

func TestRenderMethodRequiresTemplateOrID(t *testing.T) {
	for _, suite := range []string{"summary", "html", "static"} {
		neither := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: suite}
		if err := neither.Validate(); err == nil {
			t.Errorf("%s: Validate() error = nil, want template or id required", suite)
		}
		if _, err := NewJSONCredential(baseRenderContents([]RenderMethod{neither})); err == nil {
			t.Errorf("%s: NewJSONCredential() error = nil, want template or id required", suite)
		}
		idOnly := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: suite, ID: "https://example.com/render-method.json"}
		if err := idOnly.Validate(); err != nil {
			t.Errorf("%s: Validate() with id error = %v", suite, err)
		}
	}
	// A suite this SDK does not support may define its own rules.
	unknown := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "audio"}
	if err := unknown.Validate(); err != nil {
		t.Errorf("unsupported suite: Validate() error = %v", err)
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

	for _, scheme := range []string{"http://:8080/template.json", "https://:443"} {
		contents = baseRenderContents([]RenderMethod{{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Reference: &TemplateReference{ID: scheme}}}})
		if _, err := serializeCredentialContents(&contents); err == nil {
			t.Errorf("serializeCredentialContents() error = nil for %q, want missing host error", scheme)
		}
	}
}

func TestRenderMethodAcceptsNonHTTPTemplateReferenceURIs(t *testing.T) {
	for _, id := range []string{"data:text/html,hello", "ipfs://bafytemplate/template.html", "file:///tmp/template.html", "javascript:alert(1)"} {
		method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "html", Template: &Template{Reference: &TemplateReference{ID: id}}}
		if err := method.validateFormat(); err != nil {
			t.Errorf("validateFormat(%q) error = %v", id, err)
		}
	}
}

func TestTemplateReferenceDataURLIsDecodedWithoutFetcher(t *testing.T) {
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "html", Template: &Template{Reference: &TemplateReference{
		ID: "data:text/html,%3Cp%3Ehi%3C%2Fp%3E",
	}}}

	data, _, err := templateBytes(context.Background(), method, nil)
	if err != nil {
		t.Fatalf("templateBytes() error = %v", err)
	}
	if string(data) != "<p>hi</p>" {
		t.Fatalf("templateBytes() = %q, want %q", data, "<p>hi</p>")
	}
}

func TestInvalidDataURLReferenceFailsWhenResolved(t *testing.T) {
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "html", Template: &Template{Reference: &TemplateReference{ID: "data:abc"}}}
	if err := method.validateFormat(); err != nil {
		t.Fatalf("validateFormat() error = %v, want format-only validation to pass", err)
	}
	if _, _, err := templateBytes(context.Background(), method, nil); err == nil {
		t.Fatal("templateBytes() error = nil, want data URL decode error")
	}
}

func TestRenderMethodValidatesRenderProperties(t *testing.T) {
	valid := []string{"", "/credentialSubject/name", "/a~1b/~0key"}
	for _, pointer := range valid {
		method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "html", ID: "https://example.com/html.json", RenderProperty: []string{pointer}}
		if err := method.Validate(); err != nil {
			t.Errorf("Validate() for pointer %q error = %v", pointer, err)
		}
	}

	for _, pointer := range []string{"credentialSubject/name", "/a~2b", "/a~"} {
		method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "html", ID: "https://example.com/html.json", RenderProperty: []string{pointer}}
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
	if err := method.ValidateExternalTemplate(context.Background(), &testFetcher{data: data}); err != nil {
		t.Fatalf("ValidateExternalTemplate() error = %v", err)
	}

	method.Template.Reference.DigestMultibase = testDigest([]byte("other bytes"))
	if err := method.ValidateExternalTemplate(context.Background(), &testFetcher{data: data}); err == nil {
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
		ID:          "https://example.com/summary.json",
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
	for _, methods := range [][]RenderMethod{{{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Embedded: &EmbeddedTemplate{MediaType: "application/json", Bytes: []byte(`{"name":"Degree","description":"Summary","fields":[{"label":"Name","value":"/credentialSubject/name"}]}`)}}}}, {{Type: "SuiteRenderMethod", RenderSuite: "summary", ID: "https://example.com/summary.json"}, {Type: "SuiteRenderMethod", RenderSuite: "html", ID: "https://example.com/html.json"}}} {
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
	if err := method.ValidateExternalTemplate(context.Background(), &testFetcher{data: data}); err != nil {
		t.Fatalf("ValidateExternalTemplate() error = %v", err)
	}
	literal := []byte(`{"name":"Degree","description":"Summary","fields":[{"label":"Name","value":"Alice"}]}`)
	if err := method.ValidateExternalTemplate(context.Background(), &testFetcher{data: literal}); err == nil {
		t.Fatal("ValidateExternalTemplate() error = nil, want literal value error")
	}
}

func testDigest(data []byte) string {
	hash := sha256.Sum256(data)
	return "u" + base64.RawURLEncoding.EncodeToString(append([]byte{0x12, 0x20}, hash[:]...))
}

const base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

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
		// RFC 4648 §3.3 refuses characters outside the alphabet, and a strict
		// decoder refuses non-zero pad bits; Go's decoder skips CR and LF.
		"line feed inside":       valid[:10] + "\n" + valid[10:],
		"carriage return inside": valid[:10] + "\r" + valid[10:],
		"non-zero pad bits":      valid[:len(valid)-1] + string(base64URLAlphabet[strings.IndexByte(base64URLAlphabet, valid[len(valid)-1])|1]),
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

func TestValidateURLFollowsURLStandard(t *testing.T) {
	for raw, wantErr := range map[string]bool{
		"https://example.org:70000/t.html": true,
		"https:example.org/t.html":         false,
		"data:text/html,hello":             false,
		"urn:example:rm":                   false,
	} {
		if err := validateURL(raw, "template reference id"); (err != nil) != wantErr {
			t.Errorf("validateURL(%q) error = %v, wantErr %v", raw, err, wantErr)
		}
	}
}

// The fetched body is one JSON value (RFC 8259 §2), as JSON.parse reads it.
func TestRenderMethodDereferenceRefusesDataAfterTheJSONValue(t *testing.T) {
	method := RenderMethod{ID: "https://example.com/render-method.json", Type: "SuiteRenderMethod", RenderSuite: "summary"}
	for _, trailing := range []string{` <script>`, `{"x":1}`, `}`, `]`} {
		fetched := []byte(`{"type":"SuiteRenderMethod","renderSuite":"summary","template":"data:application/json,%7B%22name%22%3A%22N%22,%22description%22%3A%22D%22,%22fields%22:%5B%5D%7D"}` + trailing)
		if _, err := method.Dereference(context.Background(), &testFetcher{data: fetched}); err == nil {
			t.Errorf("%q after the value: Dereference() error = nil", trailing)
		}
	}
}

// json.Unmarshal into a RenderMethod matches member names case-sensitively too.
func TestRenderMethodUnmarshalIgnoresMembersThatDifferOnlyInCase(t *testing.T) {
	var method RenderMethod
	if err := json.Unmarshal([]byte(`{"type":"SuiteRenderMethod","renderSuite":"html","id":"https://example.com/rm","TEMPLATE":"https://example.com/t","RenderSuite":"static"}`), &method); err != nil {
		t.Fatal(err)
	}
	if method.Template != nil || method.RenderSuite != "html" {
		t.Errorf("method = %+v, want no template and suite html", method)
	}
}

func TestRenderMethodDereferenceFetchesAndChecksDigest(t *testing.T) {
	fetched := []byte(`{"type":"SuiteRenderMethod","renderSuite":"summary","template":"data:application/json,%7B%22name%22%3A%22N%22,%22description%22%3A%22D%22,%22fields%22:%5B%5D%7D"}`)
	method := RenderMethod{
		ID:   "https://example.com/render-method.json",
		Type: "SuiteRenderMethod", RenderSuite: "summary",
		DigestMultibase: testDigest(fetched),
	}
	fetcher := &testFetcher{data: fetched}
	got, err := method.Dereference(context.Background(), fetcher)
	if err != nil {
		t.Fatalf("Dereference() error = %v", err)
	}
	if got.Template == nil || fetcher.ref.ID != method.ID || fetcher.ref.DigestMultibase != method.DigestMultibase {
		t.Fatalf("Dereference() got method/ref = %+v/%+v", got, fetcher.ref)
	}
}

func TestRenderMethodDereferenceRefusesAChangedDigestOrSuite(t *testing.T) {
	fetched := []byte(`{"type":"SuiteRenderMethod","renderSuite":"summary","template":"data:application/json,%7B%22name%22%3A%22N%22,%22description%22%3A%22D%22,%22fields%22:%5B%5D%7D"}`)
	method := RenderMethod{ID: "https://example.com/render-method.json", Type: "SuiteRenderMethod", RenderSuite: "summary", DigestMultibase: testDigest(fetched)}
	changed := bytes.Replace(fetched, []byte(`%22N%22`), []byte(`%22M%22`), 1)
	if _, err := method.Dereference(context.Background(), &testFetcher{data: changed}); err == nil || !strings.Contains(err.Error(), "renderMethod.digestMultibase") {
		t.Errorf("changed bytes: Dereference() error = %v, want a digestMultibase error", err)
	}
	html := []byte(`{"type":"SuiteRenderMethod","renderSuite":"html","template":"data:text/html,%3Cp%3Ex%3C/p%3E"}`)
	method.DigestMultibase = ""
	if _, err := method.Dereference(context.Background(), &testFetcher{data: html}); err == nil {
		t.Error("html method for a summary entry: Dereference() error = nil")
	}
}

// The credential's renderProperty limits which claims the template sees; a
// fetched method must not widen or change it.
func TestRenderMethodDereferenceRefusesAnotherRenderProperty(t *testing.T) {
	method := RenderMethod{ID: "https://i.example/rm", Type: "SuiteRenderMethod", RenderSuite: "html", RenderProperty: []string{"/credentialSubject/name"}}
	for _, fetched := range []string{
		`{"type":"SuiteRenderMethod","renderSuite":"html","template":"data:text/html,%3Cp%3Ex%3C/p%3E"}`,
		`{"type":"SuiteRenderMethod","renderSuite":"html","renderProperty":["/credentialSubject"],"template":"data:text/html,%3Cp%3Ex%3C/p%3E"}`,
	} {
		if _, err := method.Dereference(context.Background(), &testFetcher{data: []byte(fetched)}); err == nil {
			t.Errorf("fetched %s: Dereference() error = nil, want a renderProperty mismatch", fetched)
		}
	}
	// [] shares nothing, so a fetched method without renderProperty would share everything.
	nothing := RenderMethod{ID: method.ID, Type: method.Type, RenderSuite: method.RenderSuite, RenderProperty: []string{}}
	if _, err := nothing.Dereference(context.Background(), &testFetcher{data: []byte(`{"type":"SuiteRenderMethod","renderSuite":"html","template":"data:text/html,%3Cp%3Ex%3C/p%3E"}`)}); err == nil {
		t.Error("credential renderProperty [] and fetched without it: Dereference() error = nil")
	}
	same := `{"type":"SuiteRenderMethod","renderSuite":"html","renderProperty":["/credentialSubject/name"],"template":"data:text/html,%3Cp%3Ex%3C/p%3E"}`
	if _, err := method.Dereference(context.Background(), &testFetcher{data: []byte(same)}); err != nil {
		t.Errorf("same renderProperty: Dereference() error = %v", err)
	}
	// Without renderProperty in the credential the whole credential is shared,
	// so the fetched method may narrow it.
	method.RenderProperty = nil
	narrowed := `{"type":"SuiteRenderMethod","renderSuite":"html","renderProperty":["/credentialSubject/name"],"template":"data:text/html,%3Cp%3Ex%3C/p%3E"}`
	if _, err := method.Dereference(context.Background(), &testFetcher{data: []byte(narrowed)}); err != nil {
		t.Errorf("credential without renderProperty: Dereference() error = %v", err)
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

// Each renderMethod value MUST specify its type, and renderSuite is a REQUIRED
// string (WD-20261013 §2.1, §2.2); a processor MUST error on a non-conforming
// document (§1.2). Only a suite it does not recognize is ignored.
func TestParseRenderMethodsRefusesEntriesWithoutTypeOrSuite(t *testing.T) {
	for name, entry := range map[string]string{
		"no type":            `{"renderSuite": "html", "template": "data:text/html,x"}`,
		"null type":          `{"type": null, "renderSuite": "html", "template": "data:text/html,x"}`,
		"number type":        `{"type": 5, "renderSuite": "html", "template": "data:text/html,x"}`,
		"no renderSuite":     `{"type": "SuiteRenderMethod", "template": "data:text/html,x"}`,
		"number renderSuite": `{"type": "SuiteRenderMethod", "renderSuite": 5, "template": "data:text/html,x"}`,
		"null renderSuite":   `{"type": "SuiteRenderMethod", "renderSuite": null, "template": "data:text/html,x"}`,
		"empty type":         `{"type": "", "renderSuite": "html", "template": "data:text/html,x"}`,
		"empty type list":    `{"type": [], "renderSuite": "html", "template": "data:text/html,x"}`,
	} {
		data := parseRenderMethodsInput(t, `{"renderMethod": [`+entry+`]}`)
		if _, err := ParseRenderMethods(data); err == nil || !strings.Contains(err.Error(), "renderMethod[0]") {
			t.Errorf("%s: ParseRenderMethods() error = %v, want an error for renderMethod[0]", name, err)
		}
	}
}

// Member names are case-sensitive (WD-20261013 §2.2); encoding/json alone
// would read "TEMPLATE" as template, which no other processor does.
func TestParseRenderMethodsIgnoresMembersThatDifferOnlyInCase(t *testing.T) {
	data := parseRenderMethodsInput(t, `{"renderMethod": [
		{"type": "SuiteRenderMethod", "renderSuite": "html", "id": "https://example.com/rm", "TEMPLATE": "https://example.com/t"},
		{"type": "SuiteRenderMethod", "renderSuite": "html", "template": {"id": "https://example.com/t", "MediaType": "text/html"}}
	]}`)
	methods, err := ParseRenderMethods(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(methods) != 2 {
		t.Fatalf("methods = %+v, want 2", methods)
	}
	if methods[0].Template != nil {
		t.Errorf("TEMPLATE was read as template: %+v", methods[0].Template.Reference)
	}
	if ref := methods[1].Template.Reference; ref == nil || ref.MediaType != "" {
		t.Errorf("template.MediaType was read as mediaType: %+v", ref)
	}
}

func TestParseRenderMethodsSkipsEntriesTheSDKMustIgnore(t *testing.T) {
	// The unknown suite carries a template no supported suite would accept, so
	// decoding it would fail: it must be skipped before the typed decode.
	data := parseRenderMethodsInput(t, `{"renderMethod": [
		{"type": "SuiteRenderMethod", "renderSuite": "audio", "template": 42},
		{"type": "TemplateRenderMethod", "renderSuite": "summary", "template": "`+testSummaryTemplateDataURL+`"},
		{"type": "SuiteRenderMethod", "renderSuite": "html", "id": "https://example.com/render-method.json"},
		{"type": "SuiteRenderMethod", "renderSuite": "summary", "template": null},
		{"type": "SuiteRenderMethod", "renderSuite": "html"},
		{"type": "SuiteRenderMethod", "renderSuite": "summary", "template": "`+testSummaryTemplateDataURL+`"}
	]}`)
	methods, err := ParseRenderMethods(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(methods) != 2 || methods[0].RenderSuite != "html" || methods[0].ID == "" || methods[1].RenderSuite != "summary" {
		t.Fatalf("methods = %+v, want the id-only html entry and supported summary entry", methods)
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
		{`data:,A%20brief%20note`, "text/plain;charset=US-ASCII", "A brief note"}, // RFC 2397 §4 example
		{`data:;charset=utf-8,hello`, "text/plain;charset=utf-8", "hello"},
		{`DATA:text/plain,hello`, "text/plain", "hello"},
		{`data:text/plain;BASE64,aGVsbG8=`, "text/plain", "hello"},
		{`data:text/plain;base64,aGVsbG8%3D`, "text/plain", "hello"},
		{`data:text/plain;base64,aGVsbG8=`, "text/plain", "hello"},
		{`data:application/json,%7B%22a%22%3A1%7D`, "application/json", `{"a":1}`},
		// Fetch decodes base64 with forgiving-base64 (WHATWG Infra Standard):
		// padding is optional and ASCII whitespace is removed.
		{`data:text/plain;base64,aGVsbG8`, "text/plain", "hello"},
		{`data:text/plain;base64,YQ`, "text/plain", "a"},
		{`data:text/plain;base64,YQ==`, "text/plain", "a"},
		{`data:text/plain;base64,aGVs%20bG8=`, "text/plain", "hello"},
		{`data:text/plain;base64,aGVs bG8=`, "text/plain", "hello"},
		// The rest of the Fetch data: URL processor: the fragment is not data,
		// the media type is trimmed, spaces may come before "base64", a "%" that
		// starts no escape is kept, and a media type that does not parse is
		// text/plain;charset=US-ASCII.
		{`data:text/plain,a#b`, "text/plain", "a"},
		{`data:text/plain;base64,YQ==#frag`, "text/plain", "a"},
		{`data: text/html ,x`, "text/html", "x"},
		{`data:text/html; base64,PHA+PC9wPg==`, "text/html", "<p></p>"},
		{`data:text/html;base64 ,PHA+PC9wPg==`, "text/html", "<p></p>"},
		{`data:text/html ;base64,PHA+PC9wPg==`, "text/html", "<p></p>"},
		{`data: text/html \t ; base64,PHA+PC9wPg==`, "text/html", "<p></p>"},
		{`data:text/plain,100%`, "text/plain", "100%"},
		{`data:text/plain,a%zz`, "text/plain", "a%zz"},
		{`data:foo,abc`, "text/plain;charset=US-ASCII", "abc"},
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
	for _, raw := range []string{`data:text/plain`, `data:text/plain;base64,!!!`, `data:text/plain#a,b`,
		// forgiving-base64 failures: a length of 1 mod 4, and "=" that is not
		// one or two characters closing a length that is a multiple of 4.
		`data:text/plain;base64,Y`, `data:text/plain;base64,YQ=`, `data:text/plain;base64,aGVsbG8==`, `data:text/plain;base64,YQ===`} {
		var template Template
		if err := json.Unmarshal([]byte(`"`+raw+`"`), &template); err == nil {
			t.Errorf("%s: json.Unmarshal() error = nil, want an invalid data URL error", raw)
		}
	}
}

func TestTemplateWritesDataURLWithoutWhitespace(t *testing.T) {
	cases := map[string]string{
		"text/html":                 "data:text/html;base64,eA==",
		"text/html;charset=utf-8":   "data:text/html;charset=utf-8;base64,eA==",
		"text/html; charset=utf-8":  "data:text/html;charset=utf-8;base64,eA==",
		"text/html ; charset=utf-8": "data:text/html;charset=utf-8;base64,eA==",
		"text/html;  charset=utf-8": "data:text/html;charset=utf-8;base64,eA==",
		"text/html;\tcharset=utf-8": "data:text/html;charset=utf-8;base64,eA==",
	}
	for mediaType, want := range cases {
		encoded, err := json.Marshal(Template{Embedded: &EmbeddedTemplate{MediaType: mediaType, Bytes: []byte("x")}})
		if err != nil {
			t.Errorf("%q: json.Marshal() error = %v", mediaType, err)
			continue
		}
		var got string
		if err := json.Unmarshal(encoded, &got); err != nil {
			t.Fatalf("%q: json.Unmarshal() error = %v", mediaType, err)
		}
		if got != want {
			t.Errorf("%q: data URL = %q, want %q", mediaType, got, want)
		}
	}
}

// A quoted parameter keeps its spaces, so the data: URL reads back to the
// issuer's media type; a "#" would start the URL fragment and is refused.
func TestTemplateWritesQuotedMediaTypeParameterUnchanged(t *testing.T) {
	template := Template{Embedded: &EmbeddedTemplate{MediaType: `text/plain; title="a b"`, Bytes: []byte("x")}}
	encoded, err := json.Marshal(template)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if want := `"data:text/plain;title=\"a b\";base64,eA=="`; string(encoded) != want {
		t.Errorf("json.Marshal() = %s, want %s", encoded, want)
	}
	var decoded Template
	if err := json.Unmarshal(encoded, &decoded); err != nil || decoded.Embedded.MediaType != `text/plain;title="a b"` {
		t.Errorf("read back = %+v, %v; want media type %q", decoded.Embedded, err, `text/plain;title="a b"`)
	}

	// "#" starts the fragment; the URL parser removes a tab and percent-encodes
	// other controls and non-ASCII, so none of them reads back unchanged.
	for _, mediaType := range []string{`text/plain; title="a#b"`, "text/plain;title=\"a\tb\"", "text/html;\vcharset=utf-8", "text/html;\u00a0charset=utf-8", `text/plain;title="a,b"`} {
		template.Embedded.MediaType = mediaType
		if _, err := json.Marshal(template); err == nil {
			t.Errorf("json.Marshal() with media type %q: error = nil", mediaType)
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
	// The static suite has no expected media type, so validateMediaType is the
	// only check an embedded static template gets.
	embeddedStatic := func(mediaType string) RenderMethod {
		return RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "static",
			Template: &Template{Embedded: &EmbeddedTemplate{MediaType: mediaType, Bytes: []byte{0x01}}},
		}
	}
	for _, build := range []func(string) RenderMethod{reference, output, embeddedStatic} {
		for _, mediaType := range []string{"", "application/json", "text/html; charset=utf-8", "text/html \t; charset=utf-8", "application/vnd.api+json", "image/svg+xml", "application/x-www_form.1$&^!"} {
			if err := build(mediaType).Validate(); err != nil {
				t.Errorf("Validate() with mediaType %q error = %v", mediaType, err)
			}
		}
		for _, mediaType := range []string{"not a type", "text/", "/html", "text/html;charset", "text", "html", "png", "*/*", "text/*", "*/html",
			// RFC 6838 §4.2 restricted-name: an ALPHA or DIGIT first, then only
			// ALPHA, DIGIT and !#$&-^_.+, at most 127 characters.
			"text/ht%ml", "text/ht'ml", "-x/y", "a{b}/c|d", "x/" + strings.Repeat("a", 128),
			// U+212A KELVIN SIGN lower-cases to "k" but is not ASCII.
			"text/mar\u212Adown", "\u212Aext/plain",
			// RFC 9110 §8.3.1 allows only SP and HTAB, and only before a ";".
			" text/html", "text/html ", "text/html\v", "text/html\v; charset=utf-8"} {
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

func TestNewJSONCredentialChecksDataURLInTemplateID(t *testing.T) {
	summary := `{"name":"/credentialSubject/name","description":"A badge","fields":[{"label":"Name","value":"/credentialSubject/name"}]}`
	valid := "data:application/json;base64," + base64.StdEncoding.EncodeToString([]byte(summary))
	// sha2-256 multihash of the bytes "other", base64url multibase.
	otherDigest := "uEiDZKYoQ0bBzWDfcS9hdrGQbDzzvJ6R-XVOlTy8_Wy_P-g"
	for name, tt := range map[string]struct {
		ref     TemplateReference
		wantErr bool
	}{
		"valid summary template":   {TemplateReference{ID: valid}, false},
		"no comma in data URL":     {TemplateReference{ID: "data:abc"}, true},
		"space before the scheme":  {TemplateReference{ID: " data:abc"}, true},
		"tab inside the scheme":    {TemplateReference{ID: "da\tta:abc"}, true},
		"control before scheme":    {TemplateReference{ID: "\x01data:abc"}, true},
		"not a summary template":   {TemplateReference{ID: `data:application/json,{"x":1}`}, true},
		"digest of other bytes":    {TemplateReference{ID: valid, DigestMultibase: otherDigest}, true},
		"remote id is not fetched": {TemplateReference{ID: "https://example.com/summary.json"}, false},
	} {
		method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Reference: &tt.ref}}
		_, err := NewJSONCredential(baseRenderContents([]RenderMethod{method}))
		if (err != nil) != tt.wantErr {
			t.Errorf("%s: NewJSONCredential() error = %v, wantErr %v", name, err, tt.wantErr)
		}
	}
	// A suite this SDK does not render keeps an opaque template.
	other := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "pdf", Template: &Template{Reference: &TemplateReference{ID: "data:abc"}}}
	if _, err := NewJSONCredential(baseRenderContents([]RenderMethod{other})); err != nil {
		t.Errorf("unsupported suite: NewJSONCredential() error = %v, want nil", err)
	}
}

func TestValidateChecksMediaTypeOfDataURLInTemplateID(t *testing.T) {
	for name, tt := range map[string]struct {
		id      string
		wantErr bool
	}{
		"media type":    {"data:text/plain,abc", false},
		"no media type": {"data:,abc", false},
		// Fetch reads a media type that does not parse as text/plain;charset=US-ASCII.
		"not a media type": {"data:not a media type,abc", false},
		"bad parameter":    {`data:text/plain;x=",abc`, true},
		"1 MiB media type": {"data:text/" + strings.Repeat("a", 1<<20) + `;x=",abc`, true},
	} {
		method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "static", Template: &Template{Reference: &TemplateReference{ID: tt.id}}}
		err := method.Validate()
		if (err != nil) != tt.wantErr {
			t.Errorf("%s: Validate() error = %v, wantErr %v", name, err, tt.wantErr)
		}
		// The media type comes from the credential, so the error quotes its start only.
		if err != nil && len(err.Error()) > 1<<10 {
			t.Errorf("%s: Validate() error is %d bytes", name, len(err.Error()))
		}
	}
}

func TestTemplateStringErrorQuotesStartOfMediaType(t *testing.T) {
	var template Template
	err := json.Unmarshal(mustJSON("data:text/"+strings.Repeat("a", 1<<20)+`;x=",abc`), &template)
	if err == nil {
		t.Fatalf("Unmarshal() error = nil, want an error")
	}
	if n := len(err.Error()); n > 1<<10 {
		t.Errorf("Unmarshal() error is %d bytes, want under 1 KiB", n)
	}
}

func TestValidateURLBoundsURLsThatAreNotDataURLs(t *testing.T) {
	long := strings.Repeat("a", 200<<10)
	for name, tt := range map[string]struct {
		raw     string
		wantErr bool
	}{
		"8 KiB https URL":             {"https://example.org/" + strings.Repeat("a", 8<<10-len("https://example.org/")), false},
		"one byte over 8 KiB":         {"https://example.org/" + strings.Repeat("a", 8<<10+1-len("https://example.org/")), true},
		"https URL over 8 KiB":        {"https://example.org/" + long, true},
		"long userinfo":               {"http://" + long + "@example.org/", true},
		"data URL with an authority":  {"data://" + long + "@example.org/", true},
		"data URL holding a template": {"data:text/html," + long, false},
		"space before a data URL":     {" data:text/html," + long, false},
	} {
		err := validateURL(tt.raw, "template reference id")
		if (err != nil) != tt.wantErr {
			t.Errorf("%s: validateURL() error = %v, wantErr %v", name, err != nil, tt.wantErr)
		}
	}
}

func TestTemplateDataURLReadsTheSameAsStringAndAsID(t *testing.T) {
	dataURL := " data:text/html,<script>// note\nwindow.renderMethodReady()</script>\n"
	var asString, asID Template
	if err := json.Unmarshal(mustJSON(dataURL), &asString); err != nil {
		t.Fatalf("string form: %v", err)
	}
	if err := json.Unmarshal(mustJSON(map[string]any{"id": dataURL}), &asID); err != nil {
		t.Fatalf("id form: %v", err)
	}
	if asString.Embedded == nil {
		t.Fatalf("string form: not read as an embedded template")
	}
	method := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "static", Template: &asID}
	fromID, _, err := templateBytes(context.Background(), method, nil)
	if err != nil {
		t.Fatalf("id form: %v", err)
	}
	want := "<script>// notewindow.renderMethodReady()</script>"
	if string(asString.Embedded.Bytes) != want || string(fromID) != want {
		t.Errorf("string form = %q, id form = %q, want both %q", asString.Embedded.Bytes, fromID, want)
	}
}

type recordingFetcher struct {
	ids  []string
	data []byte
}

func (f *recordingFetcher) Fetch(_ context.Context, ref TemplateReference) ([]byte, error) {
	f.ids = append(f.ids, ref.ID)
	return f.data, nil
}

func TestFetcherGetsTheURLStandardFormOfTheID(t *testing.T) {
	fetcher := &recordingFetcher{data: []byte("<p>hi</p>")}
	template := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "static", Template: &Template{Reference: &TemplateReference{ID: " https:example.org/t.html#v2\n"}}}
	if _, err := template.ResolveStatic(context.Background(), CredentialData{"id": "urn:x"}, RenderOptions{Fetcher: fetcher}); err != nil {
		t.Fatalf("ResolveStatic() error = %v", err)
	}
	remote := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "static", ID: "HTTPS://Example.org:443/m.json"}
	fetcher.data = []byte(`{"type":"SuiteRenderMethod","renderSuite":"static","template":"data:text/plain,hi"}`)
	if _, err := remote.Dereference(context.Background(), fetcher); err != nil {
		t.Fatalf("Dereference() error = %v", err)
	}
	// Validate accepts a data: URL of any size as renderMethod.id, so Dereference does too.
	inData := RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "static", ID: "data:application/json," + strings.Repeat("a", 9<<10)}
	if err := inData.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if _, err := inData.Dereference(context.Background(), fetcher); err != nil {
		t.Fatalf("Dereference() of a 9 KiB data: id error = %v", err)
	}
	want := []string{"https://example.org/t.html#v2", "https://example.org/m.json", inData.ID}
	if !reflect.DeepEqual(fetcher.ids, want) {
		t.Errorf("Fetcher got ids %.200q, want %.200q", fetcher.ids, want)
	}
}

// An empty renderProperty shares nothing and an absent one shares everything,
// so the empty list must survive a round trip instead of becoming nil.
func TestRenderPropertyKeepsAnEmptyListOnTheWire(t *testing.T) {
	data, err := json.Marshal(RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "html", RenderProperty: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"renderProperty":[]`)) {
		t.Fatalf("json.Marshal() = %s, want renderProperty as []", data)
	}
	var method RenderMethod
	if err := json.Unmarshal(data, &method); err != nil || method.RenderProperty == nil {
		t.Fatalf("json.Unmarshal() = %#v, %v; want an empty, non-nil RenderProperty", method.RenderProperty, err)
	}
}

func TestParseRenderMethodsNamesRenderMethodInDecodeErrors(t *testing.T) {
	data := CredentialData{"renderMethod": map[string]any{"type": "SuiteRenderMethod", "renderSuite": "summary", "id": "https://example.com/m", "name": 5}}
	_, err := ParseRenderMethods(data)
	if err == nil || !strings.Contains(err.Error(), "RenderMethod.name") || strings.Contains(err.Error(), "renderMethodFields") {
		t.Fatalf("ParseRenderMethods() error = %v, want it to name RenderMethod.name", err)
	}
	var method RenderMethod
	err = json.Unmarshal([]byte(`{"type":5}`), &method)
	if err == nil || strings.Contains(err.Error(), "renderMethodFields") {
		t.Fatalf("Unmarshal() error = %v, want no unexported type name", err)
	}
}

func TestParseRenderMethodsLeavesTheCredentialUnchanged(t *testing.T) {
	entry := map[string]any{"type": "SuiteRenderMethod", "renderSuite": "summary", "id": "https://example.com/m", "NAME": "x"}
	if _, err := ParseRenderMethods(CredentialData{"renderMethod": entry}); err != nil {
		t.Fatalf("ParseRenderMethods() error = %v", err)
	}
	if entry["NAME"] != "x" {
		t.Fatal("ParseRenderMethods() removed a member from the caller's credential")
	}
}

func TestParseRenderMethodsMatchesNestedMembersCaseSensitivelyInTypedMaps(t *testing.T) {
	data := CredentialData{"renderMethod": map[string]any{"type": "SuiteRenderMethod", "renderSuite": "summary", "id": "https://example.com/m",
		"outputPreference": CredentialData{"MediaType": "text/html"}}}
	methods, err := ParseRenderMethods(data)
	if err != nil {
		t.Fatalf("ParseRenderMethods() error = %v", err)
	}
	if got := methods[0].OutputPreference.MediaType; got != "" {
		t.Fatalf("outputPreference.mediaType = %q, want \"\": MediaType differs in case", got)
	}
}
