package dto

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestProofFromMap_FillsEveryDataIntegrityProperty(t *testing.T) {
	p := ProofFromMap(map[string]interface{}{
		"id":                 "urn:uuid:p1",
		"type":               "DataIntegrityProof",
		"created":            "2024-01-01T00:00:00Z",
		"expires":            "2030-01-01T00:00:00Z",
		"verificationMethod": "did:example:issuer#key-1",
		"proofPurpose":       "assertionMethod",
		"cryptosuite":        "ecdsa-rdfc-2019",
		"challenge":          "c1",
		"domain":             "d.example",
		"nonce":              "n1",
		"previousProof":      "urn:uuid:p0",
		"proofValue":         "zabc",
	})

	want := Proof{
		Id: "urn:uuid:p1", Type: "DataIntegrityProof", Created: "2024-01-01T00:00:00Z",
		Expires: "2030-01-01T00:00:00Z", VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose: "assertionMethod", Cryptosuite: "ecdsa-rdfc-2019", Challenge: "c1",
		Domain: "d.example", Nonce: "n1", PreviousProof: StringOrStrings{"urn:uuid:p0"}, ProofValue: "zabc",
	}
	if !reflect.DeepEqual(p, want) {
		t.Fatalf("ProofFromMap = %+v, want %+v", p, want)
	}
	if p.Extra != nil {
		t.Fatalf("known properties must not land in Extra: %v", p.Extra)
	}
}

func TestProof_RoundTripKeepsUnknownAndOddlyShapedProperties(t *testing.T) {
	in := map[string]interface{}{
		"type":               "DataIntegrityProof",
		"created":            "2024-01-01T00:00:00Z",
		"verificationMethod": "did:example:issuer#key-1",
		"proofPurpose":       "assertionMethod",
		"cryptosuite":        "ecdsa-rdfc-2019",
		"proofValue":         "zabc",
		// § 2.1 allows a set of strings for domain; the typed field holds
		// only a string, so the array must survive through Extra.
		"domain":        []interface{}{"a.example", "b.example"},
		"previousProof": []interface{}{"urn:uuid:p0", "urn:uuid:p-1"},
		"customTerm":    map[string]interface{}{"nested": []interface{}{"x", 1.0}},
	}

	p := ProofFromMap(in)
	if p.Domain != "" {
		t.Fatalf("array domain must not be coerced into the string field, got %q", p.Domain)
	}
	if !reflect.DeepEqual(p.PreviousProof, StringOrStrings{"urn:uuid:p0", "urn:uuid:p-1"}) {
		t.Fatalf("previousProof = %v", p.PreviousProof)
	}
	if _, ok := p.Extra["customTerm"]; !ok {
		t.Fatalf("customTerm missing from Extra: %v", p.Extra)
	}

	if out := p.ToMap(); !reflect.DeepEqual(out, in) {
		t.Fatalf("round trip changed the proof:\n got %#v\nwant %#v", out, in)
	}
}

func TestProof_ToMapTypedFieldWinsOverExtra(t *testing.T) {
	p := ProofFromMap(map[string]interface{}{
		"type":      "DataIntegrityProof",
		"challenge": "old",
	})
	p.Challenge = "new"
	p.Extra = map[string]interface{}{"challenge": "stale"}

	if got := p.ToMap()["challenge"]; got != "new" {
		t.Fatalf("challenge = %v, want the typed field", got)
	}
}

func TestProof_ToMapOmitsEmptyFieldsAndSignature(t *testing.T) {
	p := Proof{Type: "DataIntegrityProof", Signature: []byte{1, 2, 3}}

	want := map[string]interface{}{"type": "DataIntegrityProof"}
	if got := p.ToMap(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ToMap = %#v, want %#v", got, want)
	}
}

// A previousProof that is not a string or string set (§ 2.1) must not stop
// decoding: the keys after it in alphabetical order still land in their typed
// fields, and the odd value survives in Extra for round-tripping.
func TestProofFromMap_BadPreviousProofDoesNotStopDecoding(t *testing.T) {
	m := map[string]interface{}{
		"created":            "2026-01-01T00:00:00Z",
		"previousProof":      map[string]interface{}{"id": "urn:uuid:prev"},
		"proofPurpose":       "assertionMethod",
		"proofValue":         "zabc",
		"type":               "DataIntegrityProof",
		"verificationMethod": "did:example:issuer#key-1",
	}
	p := ProofFromMap(m)

	if p.Type != "DataIntegrityProof" || p.ProofPurpose != "assertionMethod" ||
		p.ProofValue != "zabc" || p.VerificationMethod != "did:example:issuer#key-1" {
		t.Fatalf("typed fields after previousProof were not decoded: %+v", p)
	}
	if len(p.PreviousProof) != 0 {
		t.Errorf("expected PreviousProof unset, got %v", p.PreviousProof)
	}
	if _, ok := p.Extra["previousProof"]; !ok {
		t.Errorf("expected the object to be kept in Extra, got %v", p.Extra)
	}
	if !reflect.DeepEqual(p.ToMap(), m) {
		t.Errorf("round trip changed the proof:\n got %v\nwant %v", p.ToMap(), m)
	}
}

// previousProof: null is "not set"; it must not come back as "previousProof": "".
func TestProofFromMap_NullPreviousProofIsOmitted(t *testing.T) {
	p := ProofFromMap(map[string]interface{}{
		"type":          "DataIntegrityProof",
		"previousProof": nil,
	})
	if p.PreviousProof != nil {
		t.Errorf("expected nil PreviousProof, got %#v", p.PreviousProof)
	}
	if _, ok := p.ToMap()["previousProof"]; ok {
		t.Errorf("expected previousProof omitted from ToMap, got %v", p.ToMap())
	}

	var s StringOrStrings
	if err := json.Unmarshal([]byte("null"), &s); err != nil || s != nil {
		t.Errorf("StringOrStrings null: err=%v s=%#v", err, s)
	}
}
