package vp_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// VCDM 2.0 §4.13: verifiableCredential values MUST NOT be strings. A JWT or
// vc+jwt credential serializes to one, and a JSON presentation's Data
// Integrity proof could not cover it, so building one must be refused.
func TestNewJSONPresentationRefusesEnvelopingCredential(t *testing.T) {
	const issuerDID = "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce"
	_, jwtVC := createTestCredentials(t, issuerDID, "e5c9a597b20e13627a3850d38439b61ec9ee7aefd77c7cb6c01dc3866e1db19a")

	const joseDID = "did:example:json-vp-with-jose-vc"
	resolver, prov := joseVPFixture(t, joseDID)
	joseVC, err := vc.NewJOSECredential(joseVPCredentialContents(joseDID),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new jose cred: %v", err)
	}
	if err := joseVC.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign jose cred: %v", err)
	}

	for name, cred := range map[string]vc.Credential{"JWT": jwtVC, "vc+jwt": joseVC} {
		t.Run(name, func(t *testing.T) {
			_, err := vp.NewJSONPresentation(vp.PresentationContents{
				Context:               []interface{}{"https://www.w3.org/ns/credentials/v2"},
				ID:                    "urn:uuid:json-vp-with-enveloped-vc",
				Types:                 []string{"VerifiablePresentation"},
				Holder:                issuerDID,
				VerifiableCredentials: []vc.Credential{cred},
			})
			if !errors.Is(err, vp.ErrCredentialNotObject) {
				t.Fatalf("err = %v, want ErrCredentialNotObject", err)
			}
			if !strings.Contains(err.Error(), "credential at index 0") || !strings.Contains(err.Error(), "NewJOSEPresentation") {
				t.Fatalf("err = %v, want the index and the presentation type to use", err)
			}
		})
	}
}

// Parsing still accepts such a presentation, but signing it must be refused
// before any DID resolution, whether the value is a list or a single string.
func TestJSONPresentationRefusesToSignEnvelopingCredential(t *testing.T) {
	for name, value := range map[string]string{
		"list":   `["eyJhbGciOiJFUzI1NiJ9.e30.sig"]`,
		"single": `"eyJhbGciOiJFUzI1NiJ9.e30.sig"`,
	} {
		t.Run(name, func(t *testing.T) {
			raw := `{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiablePresentation"],` +
				`"holder":"did:example:holder","verifiableCredential":` + value + `}`
			pres, err := vp.ParseJSONPresentation([]byte(raw))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if _, err := pres.GetSigningInput(); !errors.Is(err, vp.ErrCredentialNotObject) {
				t.Fatalf("GetSigningInput err = %v, want ErrCredentialNotObject", err)
			}
			// No resolver is set: reaching DID resolution would fail with another error.
			err = pres.AddProof("e5c9a597b20e13627a3850d38439b61ec9ee7aefd77c7cb6c01dc3866e1db19a")
			if !errors.Is(err, vp.ErrCredentialNotObject) {
				t.Fatalf("AddProof err = %v, want ErrCredentialNotObject", err)
			}
		})
	}
}
