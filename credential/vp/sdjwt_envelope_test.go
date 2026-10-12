package vp_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// vc-jose-cose § 3.1.2 requires a credential in a presentation to be carried as
// an EnvelopedVerifiableCredential, whose data: URL names the media type that
// secured it. envelopeMediaType reads the token to decide, so a holder revealing
// nothing — whose token had lost its "~" terminator — was enveloped as vc+jwt
// while its own typ header said vc+sd-jwt. A verifier told vc+jwt parses the
// token as plain JWS, and the two labels disagreeing is exactly what the typ
// header exists to prevent.
func TestJOSEPresentation_EnvelopesAnSDJWTByItsOwnMediaType(t *testing.T) {
	const did = "did:example:vp-sd-envelope"
	resolver, prov := joseVPFixture(t, did)

	contents := joseVPCredentialContents(did)
	contents.Subject = []vc.Subject{{ID: "did:example:subject", CustomFields: map[string]interface{}{
		"name": "Alice", "bloodType": "O-",
	}}}
	sd, err := vc.NewJOSECredential(contents,
		vc.WithSDSelectivePaths([]string{"credentialSubject.bloodType"}),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new sd-jwt credential: %v", err)
	}
	if err := sd.AddProofByProvider(prov, vc.WithResolver(resolver)); err != nil {
		t.Fatalf("sign credential: %v", err)
	}
	revealNothing, err := sd.Present(nil)
	if err != nil {
		t.Fatalf("present nothing: %v", err)
	}

	for _, tc := range []struct {
		name string
		held vc.Credential
	}{
		{"every disclosure sent", sd},
		{"nothing revealed", revealNothing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vpContents := joseVPContents(did)
			vpContents.VerifiableCredentials = []vc.Credential{tc.held}

			pres, err := vp.NewJOSEPresentation(vpContents,
				vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
			if err != nil {
				t.Fatalf("new presentation: %v", err)
			}
			if err := pres.AddProofByProvider(prov, vp.WithResolver(resolver)); err != nil {
				t.Fatalf("sign presentation: %v", err)
			}

			raw, err := pres.GetContents()
			if err != nil {
				t.Fatalf("contents: %v", err)
			}
			var m map[string]interface{}
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatalf("unmarshal contents: %v", err)
			}
			items, ok := m["verifiableCredential"].([]interface{})
			if !ok || len(items) != 1 {
				t.Fatalf("verifiableCredential = %v, want one envelope", m["verifiableCredential"])
			}
			envelope, ok := items[0].(map[string]interface{})
			if !ok {
				t.Fatalf("envelope is %T, want an object", items[0])
			}
			id, _ := envelope["id"].(string)
			const want = "data:application/" + vc.TypeVCSDJWT + ","
			if !strings.HasPrefix(id, want) {
				t.Errorf("envelope id = %.60q..., want the %s prefix", id, want)
			}

			// And the presentation still round-trips, credential and all.
			serialized, err := pres.Serialize()
			if err != nil {
				t.Fatalf("serialize: %v", err)
			}
			token, ok := serialized.(string)
			if !ok {
				t.Fatalf("serialized presentation is %T, want string", serialized)
			}
			back, err := vp.ParseJOSEPresentation(token, vp.WithResolver(resolver))
			if err != nil {
				t.Fatalf("reparse: %v", err)
			}
			if err := back.Verify(vp.WithResolver(resolver), vp.WithVCValidation()); err != nil {
				t.Fatalf("verify: %v", err)
			}
		})
	}
}
