package dto

import (
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
