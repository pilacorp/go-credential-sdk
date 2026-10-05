package vp_test

import (
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// A nil credential in the contents is a caller mistake, and it used to arrive as
// a nil pointer dereference out of Serialize rather than an error — on every
// builder, because all three go through serializePresentationContents. The guard
// NewJOSEPresentation had sat after that call, so it never ran.
//
// Two shapes have to be caught. A nil interface is the obvious one. An interface
// carrying a nil pointer — vc.Credential((*vc.JOSECredential)(nil)) — is not
// == nil, which is how a typed nil slips past a plain nil check and panics on the
// first method call. That shape is what a caller gets from a helper returning
// (*vc.JOSECredential, error) whose error they forgot to check.
func TestPresentationBuilders_RefuseNilCredentials(t *testing.T) {
	const did = "did:example:nil-cred"
	resolver, _ := joseVPFixture(t, did)

	builders := map[string]func(vp.PresentationContents) (vp.Presentation, error){
		"vp+jwt": func(c vp.PresentationContents) (vp.Presentation, error) {
			return vp.NewJOSEPresentation(c, vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
		},
		"JSON-LD": func(c vp.PresentationContents) (vp.Presentation, error) {
			return vp.NewJSONPresentation(c, vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
		},
		"VP-JWT 1.1": func(c vp.PresentationContents) (vp.Presentation, error) {
			return vp.NewJWTPresentation(c, vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
		},
	}

	shapes := map[string]vc.Credential{
		"nil interface":         nil,
		"typed nil JOSE":        (*vc.JOSECredential)(nil),
		"typed nil JWT":         (*vc.JWTCredential)(nil),
		"typed nil JSONCredent": (*vc.JSONCredential)(nil),
	}

	for builderName, build := range builders {
		for shapeName, cred := range shapes {
			t.Run(builderName+"/"+shapeName, func(t *testing.T) {
				// A panic here fails the test by itself; the point is that it must
				// be an error instead.
				contents := joseVPContents(did)
				contents.VerifiableCredentials = []vc.Credential{cred}

				_, err := build(contents)
				if err == nil {
					t.Fatal("a nil credential was accepted")
				}
				if !strings.Contains(err.Error(), "credential at index 0 is nil") {
					t.Fatalf("err = %v, want it to name the nil credential", err)
				}
			})
		}
	}
}
