package vp_test

import (
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// Verifying a presentation nobody signed should say so.
//
// Both JWT-secured builders used to reach VerifyJWT through Serialize, which
// returns the two-segment signing input when there is no signature — so the
// complaint came back as "invalid JWT format", about a token whose only problem
// was that AddProofByProvider had not been called. JWTCredential has reported
// this plainly all along; these two now match it.
func TestPresentation_VerifyUnsignedSaysItIsUnsigned(t *testing.T) {
	const did = "did:example:unsigned-vp"
	resolver, _ := joseVPFixture(t, did)

	for name, build := range map[string]func() (vp.Presentation, error){
		"vp+jwt": func() (vp.Presentation, error) {
			return vp.NewJOSEPresentation(joseVPContents(did),
				vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
		},
		"VP-JWT 1.1": func() (vp.Presentation, error) {
			return vp.NewJWTPresentation(joseVPContents(did),
				vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
		},
	} {
		t.Run(name, func(t *testing.T) {
			pres, err := build()
			if err != nil {
				t.Fatalf("build: %v", err)
			}

			err = pres.Verify(vp.WithResolver(resolver))
			if err == nil {
				t.Fatal("an unsigned presentation verified")
			}
			if !strings.Contains(err.Error(), "not signed") {
				t.Fatalf("err = %v, want it to say the presentation is not signed", err)
			}
		})
	}
}
