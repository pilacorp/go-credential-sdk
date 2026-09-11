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

// rotatedVMResolver publishes a revoked #key-1 next to an active #key-2, the
// shape a key rotation leaves behind. Both hold the same key so only the
// revocation differs.
func rotatedVMResolver(t *testing.T, did string, pub *ecdsa.PublicKey) vmpkg.ResolverProvider {
	t.Helper()
	revokedAt := time.Now().Add(-time.Hour)
	old := vmpkg.NewP256VM(did, "key-1", pub)
	old.Revoked = &revokedAt
	return vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(did, old, vmpkg.NewP256VM(did, "key-2", pub)))
}

// Every signing path must refuse a revoked verification method: the verifier
// rejects anything created at or after the revocation, so signing with it would
// produce an unusable credential. Pinning the active key must still work.
func TestVC_RevokedVMRejectedAtSigning(t *testing.T) {
	const did = "did:example:vc-rotated"

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}
	resolver := rotatedVMResolver(t, did, &priv.PublicKey)

	paths := []struct {
		name string
		sign func(t *testing.T, opts ...vc.CredentialOpt) (vc.Credential, error)
	}{
		{
			name: "json",
			sign: func(t *testing.T, opts ...vc.CredentialOpt) (vc.Credential, error) {
				cred, err := vc.ParseJSONCredential(mkCredentialJSON(did))
				if err != nil {
					t.Fatalf("parse credential: %v", err)
				}
				return cred, cred.AddProofByProvider(prov, opts...)
			},
		},
		{
			name: "ecdsa-sd",
			sign: func(t *testing.T, opts ...vc.CredentialOpt) (vc.Credential, error) {
				base, err := vc.ParseECDSASDCredential(mkSDCredentialJSON(did))
				if err != nil {
					t.Fatalf("parse base credential: %v", err)
				}
				mandatory := []string{"issuer", "validFrom", "credentialSubject.id"}
				return base, base.AddProofByProvider(prov, mandatory, opts...)
			},
		},
		{
			name: "jwt",
			sign: func(t *testing.T, opts ...vc.CredentialOpt) (vc.Credential, error) {
				// NewJWTCredential resolves the VM to pick alg and kid, so the
				// revocation is caught before any signing happens.
				cred, err := vc.NewJWTCredential(jwtMultikeyContents(did), opts...)
				if err != nil {
					return nil, err
				}
				return cred, cred.AddProofByProvider(prov)
			},
		},
	}

	for _, p := range paths {
		t.Run(p.name+"/default key-1 is revoked", func(t *testing.T) {
			_, err := p.sign(t, vc.WithResolver(resolver))
			if err == nil || !strings.Contains(err.Error(), "was revoked at") {
				t.Fatalf("sign err = %v, want a revoked-key error", err)
			}
		})

		t.Run(p.name+"/pinned key-2 signs and verifies", func(t *testing.T) {
			cred, err := p.sign(t,
				vc.WithResolver(resolver), vc.WithVerificationMethodKey("key-2"))
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
				t.Fatalf("verify: %v", err)
			}
		})
	}
}
