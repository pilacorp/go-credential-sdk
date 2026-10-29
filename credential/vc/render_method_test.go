package vc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
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
			name: "static requires delivery mode",
			method: RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "static", Template: &Template{Embedded: &EmbeddedTemplate{
				MediaType: "application/octet-stream",
				Bytes:     []byte("payload"),
			}}},
			wantOK: false,
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

	method.Template.Reference.DigestMultibase = "uAQ"
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
			DigestMultibase: "z6Mkouter",
			OutputPreference: &OutputPreference{
				AccessMode: []string{"online"},
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
