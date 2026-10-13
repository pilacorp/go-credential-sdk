package vp_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	jwtpkg "github.com/pilacorp/go-credential-sdk/credential/common/jwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// WithRequireAudience means "bind this presentation to me", so it needs to know
// who "me" is. Alone it used to be worse than a no-op: it refused a presentation
// that named an audience and accepted one that named nobody, which is exactly
// backwards, and left a verifier believing it had closed the replay the aud
// claim exists to prevent.
//
// It is now a configuration error on both data models — the two carry the
// binding in different places, aud on the JWT paths and proof.domain on JSON-LD,
// but neither can bind to a verifier that has not said who it is. This test is
// what keeps the doc honest.
func TestWithRequireAudience_NeedsAVerifierIdentity(t *testing.T) {
	const (
		did       = "did:example:require-aud"
		challenge = "nonce-from-the-verifier"
		domain    = "https://verifier.example"
	)
	resolver, prov := joseVPFixture(t, did)

	t.Run("vp+jwt: alone it is a configuration error, paired it binds", func(t *testing.T) {
		pres, err := vp.NewJOSEPresentation(joseVPContents(did),
			vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
		if err != nil {
			t.Fatalf("new jose vp: %v", err)
		}
		if err := pres.AddProofByProvider(prov,
			vp.WithChallenge(challenge), vp.WithDomain(domain), vp.WithResolver(resolver)); err != nil {
			t.Fatalf("sign: %v", err)
		}
		serialized, err := pres.Serialize()
		if err != nil {
			t.Fatalf("serialize: %v", err)
		}
		token, ok := serialized.(string)
		if !ok {
			t.Fatalf("serialized presentation is %T, want string", serialized)
		}

		parsed, err := vp.ParseJOSEPresentation(token, vp.WithResolver(resolver))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		// No WithExpectedDomain: there is no verifier identity to bind to, so
		// the option cannot be honoured and says so.
		err = parsed.Verify(vp.WithResolver(resolver), vp.WithRequireAudience())
		if !errors.Is(err, vp.ErrAudienceUnbound) {
			t.Fatalf("err = %v, want it to match vp.ErrAudienceUnbound", err)
		}
		// Naming itself is what makes it work.
		if err := parsed.Verify(vp.WithResolver(resolver),
			vp.WithRequireAudience(), vp.WithExpectedDomain(domain)); err != nil {
			t.Fatalf("a verifier that names itself was refused: %v", err)
		}
		// And the binding is real: named as someone else, it fails.
		err = parsed.Verify(vp.WithResolver(resolver),
			vp.WithRequireAudience(), vp.WithExpectedDomain("https://someone-else.example"))
		if err == nil || !strings.Contains(err.Error(), "does not match expected domain") {
			t.Fatalf("err = %v, want a presentation for another verifier refused", err)
		}
	})

	t.Run("JSON-LD is held to the same rule, through proof.domain", func(t *testing.T) {
		contents := joseVPContents(did)
		pres, err := vp.NewJSONPresentation(contents,
			vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
		if err != nil {
			t.Fatalf("new json vp: %v", err)
		}
		if err := pres.AddProofByProvider(prov,
			vp.WithChallenge(challenge), vp.WithDomain(domain),
			vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver)); err != nil {
			t.Fatalf("sign: %v", err)
		}

		// It used to be a silent no-op here, which let a caller pass it and
		// bind nothing. Same configuration error as the JWT path now.
		err = pres.Verify(vp.WithResolver(resolver), vp.WithRequireAudience())
		if !errors.Is(err, vp.ErrAudienceUnbound) {
			t.Fatalf("err = %v, want it to match vp.ErrAudienceUnbound on the JSON-LD path too", err)
		}

		// Paired, it goes through proof.domain, which is where this data model
		// carries the binding.
		if err := pres.Verify(vp.WithResolver(resolver),
			vp.WithRequireAudience(), vp.WithExpectedDomain(domain)); err != nil {
			t.Fatalf("the right domain was refused with the option on: %v", err)
		}
		err = pres.Verify(vp.WithResolver(resolver),
			vp.WithRequireAudience(), vp.WithExpectedDomain("https://someone-else.example"))
		if err == nil || !strings.Contains(err.Error(), "domain") {
			t.Fatalf("err = %v, want the wrong domain refused with the option on", err)
		}

		// WithExpectedDomain is what that path checks, and it does refuse a
		// mismatch.
		err = pres.Verify(vp.WithResolver(resolver),
			vp.WithExpectedDomain("https://someone-else.example"))
		if err == nil || !strings.Contains(err.Error(), "domain") {
			t.Fatalf("err = %v, want the wrong domain to be refused", err)
		}
		if err := pres.Verify(vp.WithResolver(resolver), vp.WithExpectedDomain(domain)); err != nil {
			t.Fatalf("the right domain was refused: %v", err)
		}
	})
}

// The presentation half of the same split. NewJWTPresentation writes exp and nbf
// beside the payload, from ValidUntil and ValidFrom, and WithCheckExpiration only
// read the payload's own window — so a presentation past its exp verified.
//
// The token is hand-built so exp stands alone: the payload carries no validUntil
// for the old check to catch, which is the case it could not see.
func TestJWTPresentation_ChecksExpAndNbf(t *testing.T) {
	const did = "did:example:vp-time"
	resolver, prov := joseVPFixture(t, did)
	now := time.Now()

	for _, tc := range []struct {
		name    string
		claims  map[string]interface{}
		wantErr string
	}{
		{name: "inside the window", claims: map[string]interface{}{
			"nbf": now.Add(-time.Hour).Unix(), "exp": now.Add(time.Hour).Unix()}},
		{name: "exp has passed", claims: map[string]interface{}{
			"exp": now.Add(-time.Hour).Unix()}, wantErr: "expired"},
		{name: "nbf is in the future", claims: map[string]interface{}{
			"nbf": now.Add(time.Hour).Unix()}, wantErr: "not valid before"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]interface{}{
				"iss":    did,
				"holder": did,
				"vp": map[string]interface{}{
					"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
					"type":     []interface{}{"VerifiablePresentation"},
					"holder":   did,
				},
			}
			for k, v := range tc.claims {
				payload[k] = v
			}
			token := signJWT11VP(t, prov, did+"#key-1", payload)

			parsed, err := vp.ParseJWTPresentation(token, vp.WithResolver(resolver))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if err := parsed.Verify(vp.WithResolver(resolver)); err != nil {
				t.Fatalf("a plain Verify must not look at time claims: %v", err)
			}

			err = parsed.Verify(vp.WithResolver(resolver), vp.WithCheckExpiration())
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("a token inside its window was refused: %v", err)
				}

				return
			}
			if err == nil {
				t.Fatal("a token outside its own time claims was accepted")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one mentioning %q", err, tc.wantErr)
			}
		})
	}
}

// signJWT11VP signs payload as a VC 1.1 style presentation token (typ JWT).
func signJWT11VP(t *testing.T, prov signer.SignerProvider, kid string, payload map[string]interface{}) string {
	t.Helper()

	header, err := json.Marshal(map[string]interface{}{"typ": "JWT", "alg": "ES256", "kid": kid})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(body)
	sig, err := jwtpkg.NewJWTSigner(prov).SignString(signingInput)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	return signingInput + "." + sig
}
