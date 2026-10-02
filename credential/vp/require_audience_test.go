package vp_test

import (
	"strings"
	"testing"

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
