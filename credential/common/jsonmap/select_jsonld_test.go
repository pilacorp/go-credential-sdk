package jsonmap

import (
	"reflect"
	"testing"
)

func TestSelectJSONLDPreservesContextAndNodeMetadata(t *testing.T) {
	document := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential"},
		"credentialSubject": map[string]interface{}{
			"id":     "did:example:subject",
			"type":   []interface{}{"Person"},
			"name":   "Alice",
			"secret": "hidden",
		},
	}

	got, err := SelectJSONLD(document, []string{"/credentialSubject/name"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential"},
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"type": []interface{}{"Person"},
			"name": "Alice",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selection = %#v, want %#v", got, want)
	}
}

func TestSelectJSONLDMergesPointersAndHandlesArrays(t *testing.T) {
	document := map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"items": []interface{}{
				map[string]interface{}{"name": "first", "secret": "one"},
				map[string]interface{}{"name": "second", "secret": "two"},
			},
		},
	}

	got, err := SelectJSONLD(document, []string{
		"/credentialSubject/items/0/name",
		"/credentialSubject/items/1/name",
	})
	if err != nil {
		t.Fatal(err)
	}
	items := got["credentialSubject"].(map[string]interface{})["items"].([]interface{})
	if len(items) != 2 || items[0].(map[string]interface{})["name"] != "first" || items[1].(map[string]interface{})["name"] != "second" {
		t.Fatalf("selected items = %#v", items)
	}
	if _, ok := items[0].(map[string]interface{})["secret"]; ok {
		t.Fatalf("selection leaked item secret: %#v", items[0])
	}
}

func TestSelectJSONLDEscapesPointerTokens(t *testing.T) {
	document := map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"a/b": map[string]interface{}{"~key": "value"},
		},
	}

	got, err := SelectJSONLD(document, []string{"/credentialSubject/a~1b/~0key"})
	if err != nil {
		t.Fatal(err)
	}
	subject := got["credentialSubject"].(map[string]interface{})
	if subject["a/b"].(map[string]interface{})["~key"] != "value" {
		t.Fatalf("escaped selection = %#v", got)
	}
}

func TestSelectJSONLDTreatsNumericObjectKeysAsObjectKeys(t *testing.T) {
	document := map[string]interface{}{
		"credentialSubject": map[string]interface{}{"0": "Alice"},
	}
	got, err := SelectJSONLD(document, []string{"/credentialSubject/0"})
	if err != nil {
		t.Fatal(err)
	}
	if got["credentialSubject"].(map[string]interface{})["0"] != "Alice" {
		t.Fatalf("numeric object-key selection = %#v", got)
	}
}

func TestSelectJSONLDHandlesRootAndMissingPointers(t *testing.T) {
	document := map[string]interface{}{"name": "Alice"}
	root, err := SelectJSONLD(document, []string{""})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(root, document) {
		t.Fatalf("root selection = %#v, want %#v", root, document)
	}
	root["name"] = "Changed"
	if document["name"] != "Alice" {
		t.Fatal("root selection mutated the source document")
	}

	if _, err := SelectJSONLD(document, []string{"/missing"}); err == nil {
		t.Fatal("missing pointer error = nil")
	}
}
