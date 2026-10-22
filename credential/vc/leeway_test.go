package vc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// An issuer whose clock runs ahead of the verifier's writes a validFrom (and,
// on VC 1.1 JWT, an nbf) that the verifier sees as the future. WithLeeway
// absorbs that skew on both bounds and on every JWT format (#107).
func TestWithLeeway_Credential(t *testing.T) {
	const did = "did:example:vc-leeway"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, mustP256VM(t, did, "key-1", &priv.PublicKey)))
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	type signable interface {
		AddProofByProvider(signer.SignerProvider, ...vc.CredentialOpt) error
		Serialize() (interface{}, error)
	}
	type builder func(vc.CredentialContents, ...vc.CredentialOpt) (signable, error)
	formats := map[string]struct {
		build builder
		parse func(string, ...vc.CredentialOpt) (vc.Credential, error)
	}{
		"vc jwt": {
			build: func(c vc.CredentialContents, o ...vc.CredentialOpt) (signable, error) {
				return vc.NewJWTCredential(c, o...)
			},
			parse: func(s string, o ...vc.CredentialOpt) (vc.Credential, error) { return vc.ParseJWTCredential(s, o...) },
		},
		"vc+jwt": {
			build: func(c vc.CredentialContents, o ...vc.CredentialOpt) (signable, error) {
				return vc.NewJOSECredential(c, o...)
			},
			parse: func(s string, o ...vc.CredentialOpt) (vc.Credential, error) { return vc.ParseJOSECredential(s, o...) },
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
		{name: "issuer clock ahead, no leeway", validFrom: now.Add(5 * time.Second), wantErr: "not valid yet"},
		{name: "issuer clock ahead, within leeway", validFrom: now.Add(5 * time.Second), leeway: 30 * time.Second},
		{name: "issuer clock ahead, beyond leeway", validFrom: now.Add(time.Minute), leeway: 30 * time.Second, wantErr: "not valid yet"},
		{name: "just expired, no leeway", validFrom: now.Add(-time.Hour), validUntil: now.Add(-5 * time.Second), wantErr: "expired"},
		{name: "just expired, within leeway", validFrom: now.Add(-time.Hour), validUntil: now.Add(-5 * time.Second), leeway: 30 * time.Second},
		{name: "negative leeway counts as zero", validFrom: now.Add(5 * time.Second), leeway: -time.Hour, wantErr: "not valid yet"},
	}

	for format, f := range formats {
		for _, tc := range cases {
			t.Run(format+"/"+tc.name, func(t *testing.T) {
				c := jwtMultikeyContents(did)
				c.ValidFrom = tc.validFrom
				c.ValidUntil = tc.validUntil

				cred, err := f.build(c, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
				if err != nil {
					t.Fatalf("build: %v", err)
				}
				if err := cred.AddProofByProvider(prov); err != nil {
					t.Fatalf("sign: %v", err)
				}
				serialized, err := cred.Serialize()
				if err != nil {
					t.Fatalf("serialize: %v", err)
				}

				_, err = f.parse(serialized.(string),
					vc.WithResolver(resolver), vc.WithVerifyProof(), vc.WithCheckExpiration(), vc.WithLeeway(tc.leeway))
				if tc.wantErr == "" {
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one mentioning %q", err, tc.wantErr)
				}
			})
		}
	}
}
