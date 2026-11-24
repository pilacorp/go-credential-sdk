package didjwtvc

import (
	"errors"
	"reflect"
	"testing"
)

func TestDecodePresentation_RefusesTypeWithoutVerifiablePresentation(t *testing.T) {
	_, err := DecodePresentation(map[string]interface{}{
		"iss": "did:example:holder",
		"vp": map[string]interface{}{
			"@context": []interface{}{defaultContext},
			"type":     []interface{}{"AuthToken"},
		},
	})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}

// converters.ts keeps vc.issuanceDate nested (it fills the top level from
// nbf), lets the top-level credentialStatus win over vc.credentialStatus, and
// replaces vc.credentialSubject.id with sub: each of those signed values is
// listed beside the member.
func TestDecodeCredential_ListsNestedValuesBeside(t *testing.T) {
	d, err := DecodeCredential(map[string]interface{}{
		"iss": "did:example:issuer", "sub": "did:example:bob", "nbf": 1700000000.0,
		"credentialStatus": map[string]interface{}{"id": "s#5"},
		"vc": map[string]interface{}{
			"@context":          []interface{}{defaultContext},
			"type":              []interface{}{"VerifiableCredential"},
			"issuanceDate":      "2020-01-01T00:00:00Z",
			"credentialStatus":  map[string]interface{}{"id": "s#9"},
			"credentialSubject": map[string]interface{}{"id": "did:example:alice", "name": "Alice"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]interface{}{
		"issuanceDate":         {"2020-01-01T00:00:00Z"},
		"credentialStatus":     {map[string]interface{}{"id": "s#9"}},
		"credentialSubject.id": {"did:example:alice"},
	}
	if !reflect.DeepEqual(d.Nested, want) {
		t.Fatalf("Signed = %v, want %v", d.Nested, want)
	}
	if d.Form["issuanceDate"] != "2023-11-14T22:13:20.000Z" {
		t.Fatalf("issuanceDate = %v, want the nbf date", d.Form["issuanceDate"])
	}
}
