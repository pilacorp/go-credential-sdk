package vc

import (
	"encoding/json"
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
