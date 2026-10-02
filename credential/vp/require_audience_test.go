package vp_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	jwtpkg "github.com/pilacorp/go-credential-sdk/credential/common/jwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// WithRequireAudience reaches exactly one check — checkAudience, which the JWT
// and vp+jwt paths call. A JSON-LD presentation has no aud claim; it names its
// verifier in proof.domain. The option is therefore a no-op there, and the doc
// now says so. This test is what keeps the doc honest: if the option ever starts
// applying to JSON-LD, or stops applying to the JWT paths, one of these fails.
func TestWithRequireAudience_AppliesOnlyToJWTSecuredPresentations(t *testing.T) {
	const (
		did       = "did:example:require-aud"
		challenge = "nonce-from-the-verifier"
		domain    = "https://verifier.example"
	)
	resolver, prov := joseVPFixture(t, did)

	t.Run("vp+jwt refuses an aud it was not named in", func(t *testing.T) {
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
		// No WithExpectedDomain: this verifier does not name itself, and the
		// presentation is addressed to someone.
		err = parsed.Verify(vp.WithResolver(resolver), vp.WithRequireAudience())
		if err == nil || !strings.Contains(err.Error(), "did not name itself") {
			t.Fatalf("err = %v, want the unaddressed verifier to be refused", err)
		}
		// Naming itself is what makes it pass.
		if err := parsed.Verify(vp.WithResolver(resolver),
			vp.WithRequireAudience(), vp.WithExpectedDomain(domain)); err != nil {
			t.Fatalf("a verifier that names itself was refused: %v", err)
		}
	})

	t.Run("JSON-LD ignores it and relies on proof.domain", func(t *testing.T) {
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

		// The option has no effect: there is no aud to refuse. Documenting the
		// no-op rather than endorsing it — a caller who passes this and nothing
		// else has not bound the presentation to anybody.
		if err := pres.Verify(vp.WithResolver(resolver), vp.WithRequireAudience()); err != nil {
			t.Fatalf("WithRequireAudience changed the JSON-LD outcome: %v", err)
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
