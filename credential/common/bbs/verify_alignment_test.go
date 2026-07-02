package bbs

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
	"github.com/pilacorp/go-credential-sdk/credential/common/sd"
)

type captureSigner struct {
	publicKey []byte
}

func (s *captureSigner) Sign(header []byte, messages [][]byte) ([]byte, error) {
	return []byte("sig"), nil
}

func (s *captureSigner) PublicKey() []byte {
	return append([]byte{}, s.publicKey...)
}

type captureEngine struct {
	messages        [][]byte
	disclosedIndexes []int
}

func (b *captureEngine) Verify(publicKey, signature, header []byte, messages [][]byte) error {
	return nil
}

func (b *captureEngine) ProofGen(publicKey, signature, header, presentationHeader []byte, messages [][]byte, disclosedIndexes []int) ([]byte, error) {
	b.messages = clone2D(messages)
	b.disclosedIndexes = append([]int{}, disclosedIndexes...)
	return []byte("proof"), nil
}

func (b *captureEngine) ProofVerify(publicKey, proof, header, presentationHeader []byte, disclosedMessages [][]byte, disclosedIndexes []int) error {
	return nil
}

func TestDerivedVerifyInputAlignment_ComplexExample(t *testing.T) {
	var document map[string]interface{}
	if err := json.Unmarshal([]byte(`{
	  "@context": [
	    "https://www.w3.org/ns/credentials/v2",
	    "https://www.w3.org/ns/credentials/examples/v2"
	  ],
	  "id": "urn:uuid:bbs-example-001",
	  "type": ["VerifiableCredential", "IdentityCredential"],
	  "issuer": "did:example:bbs-issuer",
	  "validFrom": "2026-01-01T00:00:00Z",
	  "credentialSubject": {
	    "id": "did:example:subject",
	    "name": "Nguyen Van A",
	    "dob": "1990-01-01",
	    "email": "a@example.vn",
	    "nationalID": "0123456789",
	    "address": {
	      "street": "123 Nguyen Trai",
	      "ward": "Ward 1",
	      "district": "District 5",
	      "city": "Ho Chi Minh City",
	      "country": "VN"
	    },
	    "employment": {
	      "company": {
	        "name": "Pila Corp",
	        "taxCode": "0300000000"
	      },
	      "title": "Software Engineer",
	      "startDate": "2024-03-01"
	    },
	    "contacts": {
	      "phones": ["+84-901-000-001", "+84-901-000-002"],
	      "social": {
	        "telegram": "@nguyenvana",
	        "zalo": "nguyenvana"
	      }
	    }
	  }
	}`), &document); err != nil {
		t.Fatalf("unmarshal document: %v", err)
	}

	proofConfig := map[string]interface{}{
		"type":               "DataIntegrityProof",
		"cryptosuite":        Cryptosuite,
		"created":            "2026-06-25T09:41:23Z",
		"verificationMethod": "did:example:bbs-issuer#key-1",
		"proofPurpose":       "assertionMethod",
	}

	signer := &captureSigner{publicKey: []byte("pub")}
	baseProofValue, err := createBaseProof(document, proofConfig, []string{"/issuer", "/validFrom", "/credentialSubject/id"}, signer)
	if err != nil {
		t.Fatalf("create base proof: %v", err)
	}

	engine := &captureEngine{}
	dd, err := createDisclosureData(
		document,
		baseProofValue,
		[]string{
			"/credentialSubject/name",
			"/credentialSubject/dob",
			"/credentialSubject/address/city",
			"/credentialSubject/employment/company/name",
		},
		[]byte("holder-binding-real"),
		engine,
	)
	if err != nil {
		t.Fatalf("create disclosure data: %v", err)
	}

	expected := make([][]byte, 0, len(dd.selectiveIndexes))
	for _, idx := range dd.selectiveIndexes {
		expected = append(expected, append([]byte{}, engine.messages[idx]...))
	}

	proofValue, err := serializeDerivedProofValue(dd)
	if err != nil {
		t.Fatalf("serialize derived proof value: %v", err)
	}
	dp, err := parseDerivedProofValue(proofValue)
	if err != nil {
		t.Fatalf("parse derived proof value: %v", err)
	}

	canonicalNQuads, _, err := processor.CanonicalizeWithIdMap(dd.revealDoc)
	if err != nil {
		t.Fatalf("canonicalize reveal doc: %v", err)
	}
	relabeled := sd.RelabelBlankNodes(canonicalNQuads, dp.labelMap)
	sort.Strings(relabeled)

	mandatorySet := make(map[int]bool, len(dp.mandatoryIndexes))
	for _, i := range dp.mandatoryIndexes {
		mandatorySet[i] = true
	}
	var actual [][]byte
	for i, nq := range relabeled {
		if mandatorySet[i] {
			continue
		}
		actual = append(actual, []byte(nq))
	}

	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("disclosed messages mismatch\nactual=%q\nexpected=%q\nmandatory=%v\nselective=%v", actual, expected, dp.mandatoryIndexes, dp.selectiveIndexes)
	}
}

func clone2D(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = append([]byte{}, in[i]...)
	}
	return out
}
