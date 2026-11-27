package compactform

import (
	"errors"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/processor"
)

// Under the v1 context, which defines the prefix cred, a VCDM 2.0 term comes
// out of the known form as a compact IRI.
func TestCheck_VCDMTermAsCompactIRI(t *testing.T) {
	body := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1", map[string]interface{}{
			"cm": map[string]interface{}{"@id": "https://www.w3.org/2018/credentials#confidenceMethod", "@type": "@id"}}},
		"type":              []interface{}{"VerifiableCredential"},
		"issuer":            "did:example:issuer",
		"issuanceDate":      "2020-01-01T00:00:00Z",
		"credentialSubject": map[string]interface{}{"id": "did:example:holder"},
		"cm":                "urn:x:1",
	}
	err := Check(body, Rules{Single: []string{"issuer"}, Nodes: []string{"credentialSubject"}, NamedVCDMTerms: true}, processor.JSONLDLimits{})
	if !errors.Is(err, processor.ErrNotCompactedForm) {
		t.Fatalf("err = %v, want ErrNotCompactedForm", err)
	}
}
