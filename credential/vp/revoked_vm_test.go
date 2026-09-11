package vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// Signing a presentation must refuse a revoked verification method, and pinning
// the key that replaced it must still work.
func TestVP_RevokedVMRejectedAtSigning(t *testing.T) {
	const did = "did:example:vp-rotated"

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	// A rotation leaves a revoked #key-1 next to an active #key-2.
	revokedAt := time.Now().Add(-time.Hour)
	old := vmpkg.NewP256VM(did, "key-1", &priv.PublicKey)
	old.Revoked = &revokedAt
	resolver := vmpkg.NewStaticResolver(
		vmpkg.NewDIDDocument(did, old, vmpkg.NewP256VM(did, "key-2", &priv.PublicKey)))

	t.Run("default key-1 is revoked", func(t *testing.T) {
		pres, err := vp.ParseJSONPresentation(vpDoc(did))
		if err != nil {
			t.Fatalf("parse vp: %v", err)
		}
		err = pres.AddProofByProvider(prov, vp.WithResolver(resolver))
		if err == nil || !strings.Contains(err.Error(), "was revoked at") {
			t.Fatalf("sign vp err = %v, want a revoked-key error", err)
		}
	})

	t.Run("pinned key-2 signs and verifies", func(t *testing.T) {
		pres, err := vp.ParseJSONPresentation(vpDoc(did))
		if err != nil {
			t.Fatalf("parse vp: %v", err)
		}
		if err := pres.AddProofByProvider(prov,
			vp.WithResolver(resolver), vp.WithVerificationMethodKey("key-2")); err != nil {
			t.Fatalf("sign vp: %v", err)
		}
		if err := pres.Verify(vp.WithResolver(resolver)); err != nil {
			t.Fatalf("verify vp: %v", err)
		}
	})
}
