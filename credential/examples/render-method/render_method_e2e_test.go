package main

import (
	"context"
	"encoding/json"
	"testing"

	vc "github.com/pilacorp/go-credential-sdk/credential/vc"
)

// This example exercises the consumer flow against a credential-shaped JSON
// document, as a wallet would after receiving and parsing a VC.
func TestRenderMethodsEndToEndExample(t *testing.T) {
	document := []byte(`{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"credentialSubject":{"name":"Alice"},"renderMethod":[{"type":"SuiteRenderMethod","renderSuite":"summary","template":"data:application/json,%7B%22name%22%3A%22%2FcredentialSubject%2Fname%22%2C%22description%22%3A%22Degree%22%2C%22fields%22%3A%5B%7B%22label%22%3A%22Name%22%2C%22value%22%3A%22%2FcredentialSubject%2Fname%22%7D%5D%7D"},{"type":"SuiteRenderMethod","renderSuite":"html","renderProperty":["/credentialSubject/name"],"template":"data:text/html,%3Cdiv%3EHello%3C%2Fdiv%3E"},{"type":"SuiteRenderMethod","renderSuite":"static","deliveryMode":"nfc","template":"data:application/octet-stream;base64,AAEC"}]}`)
	var raw map[string]any
	if err := json.Unmarshal(document, &raw); err != nil {
		t.Fatal(err)
	}
	var methods []vc.RenderMethod
	if err := json.Unmarshal(mustRenderJSON(t, raw["renderMethod"]), &methods); err != nil {
		t.Fatal(err)
	}
	credential := vc.CredentialData(raw)
	if got, err := vc.RenderSummary(context.Background(), credential, methods[0], vc.SummaryOptions{}); err != nil || got.Fields[0].Value != "Alice" {
		t.Fatalf("summary = %+v, err=%v", got, err)
	}
	if got, err := vc.RenderHTML(context.Background(), credential, methods[1], vc.SummaryOptions{}); err != nil || got.SrcDoc == "" {
		t.Fatalf("html = %+v, err=%v", got, err)
	}
	if got, err := vc.ResolveStatic(context.Background(), credential, methods[2], vc.SummaryOptions{}); err != nil || len(got.Bytes) != 3 {
		t.Fatalf("static = %+v, err=%v", got, err)
	}
}

func mustRenderJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
