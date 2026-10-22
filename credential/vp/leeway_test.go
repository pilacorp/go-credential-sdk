package vp_test

import (
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// A presentation is built right before it is sent, with validFrom (and nbf) at
// the holder's clock. When that clock runs ahead of the verifier's, an exact
// comparison refuses the presentation on its first use (#107). WithLeeway
// absorbs that skew on both bounds and on every format.
func TestWithLeeway_Presentation(t *testing.T) {
	const did = "did:example:vp-leeway"
	resolver, prov := joseVPFixture(t, did)

	build := map[string]func(t *testing.T, c vp.PresentationContents) string{
		"vp jwt": func(t *testing.T, c vp.PresentationContents) string {
			pres, err := vp.NewJWTPresentation(c, vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
			if err != nil {
				t.Fatalf("new jwt vp: %v", err)
			}
			if err := pres.AddProofByProvider(prov); err != nil {
				t.Fatalf("sign: %v", err)
			}
			return mustSerializeString(t, pres)
		},
		"vp+jwt": func(t *testing.T, c vp.PresentationContents) string {
			pres, err := vp.NewJOSEPresentation(c, vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
			if err != nil {
				t.Fatalf("new jose vp: %v", err)
			}
			if err := pres.AddProofByProvider(prov); err != nil {
				t.Fatalf("sign: %v", err)
			}
			return mustSerializeString(t, pres)
		},
	}

	now := time.Now()
	cases := []struct {
		name       string
		validFrom  time.Time
		validUntil time.Time
		leeway     time.Duration
		wantErr    string
	}{
		{name: "holder clock ahead, no leeway", validFrom: now.Add(5 * time.Second), wantErr: "not valid yet"},
		{name: "holder clock ahead, within leeway", validFrom: now.Add(5 * time.Second), leeway: 30 * time.Second},
		{name: "holder clock ahead, beyond leeway", validFrom: now.Add(time.Minute), leeway: 30 * time.Second, wantErr: "not valid yet"},
		{name: "just expired, no leeway", validFrom: now.Add(-time.Hour), validUntil: now.Add(-5 * time.Second), wantErr: "expired"},
		{name: "just expired, within leeway", validFrom: now.Add(-time.Hour), validUntil: now.Add(-5 * time.Second), leeway: 30 * time.Second},
		{name: "negative leeway counts as zero", validFrom: now.Add(5 * time.Second), leeway: -time.Hour, wantErr: "not valid yet"},
	}

	for format, buildToken := range build {
		for _, tc := range cases {
			t.Run(format+"/"+tc.name, func(t *testing.T) {
				c := joseVPContents(did)
				c.ValidFrom = tc.validFrom
				c.ValidUntil = tc.validUntil
				token := buildToken(t, c)

				_, err := vp.ParsePresentation([]byte(token),
					vp.WithResolver(resolver), vp.WithVerifyProof(), vp.WithCheckExpiration(), vp.WithLeeway(tc.leeway))
				assertErrContains(t, err, tc.wantErr)
			})
		}
	}
}

// With WithVCValidation the presentation's leeway reaches the embedded
// credentials, so a caller does not have to repeat it; a vc.WithLeeway given
// there still wins.
func TestWithLeeway_ReachesEmbeddedCredentials(t *testing.T) {
	const did = "did:example:vp-leeway-vc"
	resolver, prov := joseVPFixture(t, did)

	credContents := joseVPCredentialContents(did)
	credContents.ValidFrom = time.Now().Add(5 * time.Second) // issuer clock ahead
	cred, err := vc.NewJOSECredential(credContents, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new jose cred: %v", err)
	}
	if err := cred.AddProofByProvider(prov); err != nil {
		t.Fatalf("sign cred: %v", err)
	}

	c := joseVPContents(did)
	c.ValidFrom = time.Now().Add(-time.Hour)
	c.VerifiableCredentials = []vc.Credential{cred}
	pres, err := vp.NewJOSEPresentation(c, vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new jose vp: %v", err)
	}
	if err := pres.AddProofByProvider(prov); err != nil {
		t.Fatalf("sign vp: %v", err)
	}

	cases := []struct {
		name    string
		opts    []vp.PresentationOpt
		wantErr string
	}{
		{
			name:    "no leeway",
			opts:    []vp.PresentationOpt{vp.WithVCValidation(vc.WithCheckExpiration())},
			wantErr: "credential is not valid yet",
		},
		{
			name: "presentation leeway is forwarded",
			opts: []vp.PresentationOpt{vp.WithLeeway(30 * time.Second), vp.WithVCValidation(vc.WithCheckExpiration())},
		},
		{
			name: "credential leeway overrides the forwarded one",
			opts: []vp.PresentationOpt{
				vp.WithLeeway(30 * time.Second),
				vp.WithVCValidation(vc.WithCheckExpiration(), vc.WithLeeway(0)),
			},
			wantErr: "credential is not valid yet",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := pres.Verify(append([]vp.PresentationOpt{vp.WithResolver(resolver)}, tc.opts...)...)
			assertErrContains(t, err, tc.wantErr)
		})
	}
}

func mustSerializeString(t *testing.T, pres vp.Presentation) string {
	t.Helper()
	serialized, err := pres.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	token, ok := serialized.(string)
	if !ok {
		t.Fatalf("serialized presentation is %T, want string", serialized)
	}
	return token
}

func assertErrContains(t *testing.T, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want one mentioning %q", err, want)
	}
}
