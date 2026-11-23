package vp_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// #218: a JSON presentation carries a vc+jwt or vc+sd-jwt credential as a
// VCDM 2.0 §4.13 EnvelopedVerifiableCredential, so its Data Integrity proof
// covers the credential.

const envelopeDID = "did:example:json-vp-enveloped"

func signedJOSECredential(t *testing.T, resolver vmpkg.ResolverProvider, prov signer.SignerProvider,
	id string, opts ...vc.CredentialOpt) *vc.JOSECredential {
	t.Helper()
	contents := joseVPCredentialContents(envelopeDID)
	contents.ID = id
	contents.Subject = []vc.Subject{{ID: "did:example:subject", CustomFields: map[string]interface{}{"name": "Alice"}}}
	cred, err := vc.NewJOSECredential(contents,
		append([]vc.CredentialOpt{vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver)}, opts...)...)
	if err != nil {
		t.Fatalf("new jose cred: %v", err)
	}
	if err := cred.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign jose cred: %v", err)
	}
	return cred
}

func envelopedVPContents(creds ...vc.Credential) vp.PresentationContents {
	return vp.PresentationContents{
		Context:               []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:                    "urn:uuid:json-vp-enveloped",
		Types:                 []string{"VerifiablePresentation"},
		Holder:                envelopeDID,
		VerifiableCredentials: creds,
	}
}

// signedJSONVP builds and signs a JSON presentation and returns its JSON form.
func signedJSONVP(t *testing.T, resolver vmpkg.ResolverProvider, prov signer.SignerProvider,
	contents vp.PresentationContents) map[string]interface{} {
	t.Helper()
	pres, err := vp.NewJSONPresentation(contents)
	if err != nil {
		t.Fatalf("NewJSONPresentation: %v", err)
	}
	if err := pres.AddProofByProvider(prov, vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver)); err != nil {
		t.Fatalf("sign VP: %v", err)
	}
	serialized, err := pres.Serialize()
	if err != nil {
		t.Fatalf("serialize VP: %v", err)
	}
	raw, err := json.Marshal(serialized)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestJSONPresentation_EnvelopesJOSECredentials(t *testing.T) {
	resolver, prov := joseVPFixture(t, envelopeDID)
	for _, tc := range []struct {
		name      string
		opts      []vc.CredentialOpt
		mediaType string
	}{
		{name: "vc+jwt", mediaType: "vc+jwt"},
		{name: "vc+sd-jwt", opts: []vc.CredentialOpt{vc.WithSDSelectivePaths([]string{"credentialSubject.name"})},
			mediaType: "vc+sd-jwt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cred := signedJOSECredential(t, resolver, prov, "urn:uuid:enveloped-"+tc.name, tc.opts...)
			token, err := cred.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			doc := signedJSONVP(t, resolver, prov, envelopedVPContents(cred))

			list, ok := doc["verifiableCredential"].([]interface{})
			if !ok || len(list) != 1 {
				t.Fatalf("verifiableCredential = %v, want one entry", doc["verifiableCredential"])
			}
			envelope, ok := list[0].(map[string]interface{})
			if !ok {
				t.Fatalf("verifiableCredential[0] is %T, want an object", list[0])
			}
			if got, want := envelope["id"], "data:application/"+tc.mediaType+","+token.(string); got != want {
				t.Fatalf("envelope id = %v, want %v", got, want)
			}
			if !strings.Contains(string(mustMarshal(t, envelope["type"])), vc.TypeEnvelopedVC) {
				t.Fatalf("envelope type = %v, want %s", envelope["type"], vc.TypeEnvelopedVC)
			}
			if envelope["@context"] == nil {
				t.Fatal("envelope has no @context")
			}

			// The presentation's proof verifies, and so does the enclosed
			// credential, through the parser its media type names.
			if _, err := vp.ParsePresentation(mustMarshal(t, doc), vp.WithResolver(resolver), vp.WithVerifyProof(),
				vp.WithVCValidation(vc.WithResolver(resolver))); err != nil {
				t.Fatalf("parse and verify: %v", err)
			}
		})
	}
}

// The proof covers the envelope: putting another valid credential from the
// same issuer in its place breaks the presentation's signature.
func TestJSONPresentation_ProofCoversTheEnvelope(t *testing.T) {
	resolver, prov := joseVPFixture(t, envelopeDID)
	doc := signedJSONVP(t, resolver, prov, envelopedVPContents(
		signedJOSECredential(t, resolver, prov, "urn:uuid:enveloped-original")))

	other, err := signedJOSECredential(t, resolver, prov, "urn:uuid:enveloped-swapped").Serialize()
	if err != nil {
		t.Fatal(err)
	}
	envelope := doc["verifiableCredential"].([]interface{})[0].(map[string]interface{})
	envelope["id"] = "data:application/vc+jwt," + other.(string)

	if _, err := vp.ParsePresentation(mustMarshal(t, doc), vp.WithResolver(resolver), vp.WithVerifyProof()); err == nil {
		t.Fatal("a presentation whose envelope was swapped still verified")
	}
}

// EnvelopedVerifiableCredential is a VCDM 2.0 term. Under a v1 @context JSON-LD
// does not define it, so the proof could not cover the envelope.
func TestJSONPresentation_EnvelopeNeedsV2Context(t *testing.T) {
	resolver, prov := joseVPFixture(t, envelopeDID)
	contents := envelopedVPContents(signedJOSECredential(t, resolver, prov, "urn:uuid:enveloped-v1"))
	contents.Context = []interface{}{"https://www.w3.org/2018/credentials/v1"}
	_, err := vp.NewJSONPresentation(contents)
	if !errors.Is(err, vp.ErrCredentialNotObject) || !strings.Contains(err.Error(), "credentials/v2") {
		t.Fatalf("err = %v, want ErrCredentialNotObject naming the v2 context", err)
	}
}

// VCDM 2.0 §4.13 MUSTs, checked when the enclosed credentials are verified.
func TestJSONPresentation_EnvelopeMUSTs(t *testing.T) {
	resolver, prov := joseVPFixture(t, envelopeDID)
	token, err := signedJOSECredential(t, resolver, prov, "urn:uuid:enveloped-musts").Serialize()
	if err != nil {
		t.Fatal(err)
	}
	good := func() map[string]interface{} {
		return map[string]interface{}{
			"@context": "https://www.w3.org/ns/credentials/v2",
			"type":     "EnvelopedVerifiableCredential",
			"id":       "data:application/vc+jwt," + token.(string),
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(map[string]interface{})
		wants  string
	}{
		{name: "well formed", mutate: func(map[string]interface{}) {}},
		// The scheme and media type are case-insensitive (RFC 3986, RFC 2045):
		// a spelling the check accepts must also be one the parser opens.
		{name: "media type in another case", mutate: func(e map[string]interface{}) {
			e["id"] = "DATA:Application/VC+JWT," + token.(string)
		}},
		{name: "no @context", mutate: func(e map[string]interface{}) { delete(e, "@context") }, wants: "@context"},
		{name: "v1 @context", mutate: func(e map[string]interface{}) {
			e["@context"] = "https://www.w3.org/2018/credentials/v1"
		}, wants: "@context"},
		{name: "id not a data: URL", mutate: func(e map[string]interface{}) {
			e["id"] = "https://example.com/credential"
		}, wants: "data: URL"},
		{name: "unknown media type", mutate: func(e map[string]interface{}) {
			e["id"] = "data:application/jwt," + token.(string)
		}, wants: "data: URL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			envelope := good()
			tc.mutate(envelope)
			doc := map[string]interface{}{
				"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
				"type":                 []interface{}{"VerifiablePresentation"},
				"holder":               envelopeDID,
				"verifiableCredential": []interface{}{envelope},
			}
			_, err := vp.ParseJSONPresentation(mustMarshal(t, doc), vp.WithResolver(resolver),
				vp.WithVCValidation(vc.WithResolver(resolver)))
			if tc.wants == "" {
				if err != nil {
					t.Fatalf("a well-formed envelope was refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wants) {
				t.Fatalf("err = %v, want one mentioning %q", err, tc.wants)
			}
		})
	}
}
