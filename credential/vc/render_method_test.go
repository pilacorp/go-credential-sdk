package vc

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

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

func TestRenderMethodCredentialRoundTripsObjectAndArray(t *testing.T) {
	tests := []struct {
		name    string
		methods []RenderMethod
	}{
		{
			name: "object",
			methods: []RenderMethod{{
				Type: "SuiteRenderMethod", RenderSuite: "summary",
				Template: &Template{Embedded: &EmbeddedTemplate{
					MediaType: "application/json",
					Bytes:     []byte(`{"name":"Degree","description":"Summary","fields":[]}`),
				}},
			}},
		},
		{
			name: "array",
			methods: []RenderMethod{
				{Type: "SuiteRenderMethod", RenderSuite: "summary"},
				{Type: "SuiteRenderMethod", RenderSuite: "html", RenderProperty: []string{"/credentialSubject/name"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			created, err := NewJSONCredential(baseRenderContents(tt.methods))
			if err != nil {
				t.Fatalf("NewJSONCredential() error = %v", err)
			}
			raw, err := created.GetContents()
			if err != nil {
				t.Fatalf("GetContents() error = %v", err)
			}
			parsed, err := ParseJSONCredential(raw)
			if err != nil {
				t.Fatalf("ParseJSONCredential() error = %v", err)
			}

			var original, roundTripped map[string]interface{}
			if err := json.Unmarshal(raw, &original); err != nil {
				t.Fatalf("unmarshal original: %v", err)
			}
			parsedRaw, err := parsed.GetContents()
			if err != nil {
				t.Fatalf("parsed GetContents() error = %v", err)
			}
			if err := json.Unmarshal(parsedRaw, &roundTripped); err != nil {
				t.Fatalf("unmarshal round trip: %v", err)
			}
			if !reflect.DeepEqual(roundTripped["renderMethod"], original["renderMethod"]) {
				t.Fatalf("renderMethod changed after parse: got %#v, want %#v", roundTripped["renderMethod"], original["renderMethod"])
			}
		})
	}
}

func TestRenderMethodChangesSigningInput(t *testing.T) {
	contents := baseRenderContents([]RenderMethod{{Type: "SuiteRenderMethod", RenderSuite: "summary"}})
	contents.Context = append(contents.Context, "https://www.w3.org/ns/credentials/examples/v2")
	credential, err := NewJSONCredential(contents)
	if err != nil {
		t.Fatalf("NewJSONCredential() error = %v", err)
	}
	before, err := credential.GetSigningInput()
	if err != nil {
		t.Fatalf("GetSigningInput() before mutation error = %v", err)
	}
	credential.credentialData["renderMethod"] = map[string]interface{}{
		"type":        "SuiteRenderMethod",
		"renderSuite": "html",
	}
	after, err := credential.GetSigningInput()
	if err != nil {
		t.Fatalf("GetSigningInput() after mutation error = %v", err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("GetSigningInput() unchanged after renderMethod mutation")
	}
}

func TestRenderMethodMutationInvalidatesDataIntegrityProof(t *testing.T) {
	contents := baseRenderContents([]RenderMethod{{Type: "SuiteRenderMethod", RenderSuite: "summary"}})
	contents.Context = append(contents.Context, "https://www.w3.org/ns/credentials/examples/v2")
	credential, err := NewJSONCredential(contents)
	if err != nil {
		t.Fatalf("NewJSONCredential() error = %v", err)
	}
	signerProvider, opts := p256TestIssuer(t, "did:example:issuer")
	if err := credential.AddProofByProvider(signerProvider, opts...); err != nil {
		t.Fatalf("AddProofByProvider() error = %v", err)
	}
	if err := credential.Verify(opts...); err != nil {
		t.Fatalf("Verify() before mutation error = %v", err)
	}

	credential.credentialData["renderMethod"] = map[string]interface{}{
		"type":        "SuiteRenderMethod",
		"renderSuite": "html",
	}
	if err := credential.Verify(opts...); err == nil {
		t.Fatal("Verify() after renderMethod mutation = nil, want invalid proof error")
	}
}

func TestSerializeCredentialContentsRejectsIncompleteRenderMethod(t *testing.T) {
	contents := baseRenderContents([]RenderMethod{{RenderSuite: "summary"}})
	if _, err := serializeCredentialContents(&contents); err == nil {
		t.Fatal("serializeCredentialContents() error = nil, want missing type error")
	}
}

func TestRenderMethodTemplateReferenceRoundTripsBothDigests(t *testing.T) {
	method := RenderMethod{ID: "https://example.com/render-method.jsonld", Type: "SuiteRenderMethod", RenderSuite: "summary", DigestMultibase: "uOuter", Template: &Template{Reference: &TemplateReference{ID: "https://example.com/template.json", MediaType: "application/json", DigestMultibase: "uInner"}}}
	b, err := json.Marshal(method)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var got RenderMethod
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got.ID != method.ID || got.DigestMultibase != method.DigestMultibase || got.Template == nil || got.Template.Reference == nil || got.Template.Reference.DigestMultibase != "uInner" {
		t.Fatalf("round trip = %#v, want both digest layers preserved", got)
	}
}

func TestRenderMethodTemplatePercentEncodedDataURL(t *testing.T) {
	var got Template
	if err := json.Unmarshal([]byte(`"data:application/json,%7B%22name%22%3A%22Alice%22%7D"`), &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got.Embedded == nil || string(got.Embedded.Bytes) != `{"name":"Alice"}` {
		t.Fatalf("embedded template = %#v, want percent-decoded JSON", got.Embedded)
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
}
