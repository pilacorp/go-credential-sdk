package vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// The presentation side of the same rule, plus the function that was missing:
// JOSEPresentation had no AddCustomProof at all, so a holder whose key lives in
// an HSM or a wallet could not produce a vp+jwt presentation by any means.
func TestJOSEPresentation_SigningPaths(t *testing.T) {
	const did = "did:example:jose-vp-signing"

	heldKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen held key: %v", err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen other key: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did,
		mustP256VM(t, did, "key-1", &heldKey.PublicKey)))
	heldProv, err := signer.NewP256Provider(heldKey)
	if err != nil {
		t.Fatalf("held provider: %v", err)
	}
	otherProv, err := signer.NewP256Provider(otherKey)
	if err != nil {
		t.Fatalf("other provider: %v", err)
	}

	newPres := func(t *testing.T, opts ...vp.PresentationOpt) *vp.JOSEPresentation {
		t.Helper()
		opts = append(opts, vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
		pres, err := vp.NewJOSEPresentation(joseVPContents(did), opts...)
		if err != nil {
			t.Fatalf("new jose presentation: %v", err)
		}

		return pres
	}
	signOutside := func(t *testing.T, pres *vp.JOSEPresentation, key *ecdsa.PrivateKey) []byte {
		t.Helper()
		input, err := pres.GetSigningInput()
		if err != nil {
			t.Fatalf("signing input: %v", err)
		}
		prov, err := signer.NewP256Provider(key)
		if err != nil {
			t.Fatalf("provider: %v", err)
		}
		digest := sha256.Sum256(input)
		raw, err := prov.Sign(digest[:])
		if err != nil {
			t.Fatalf("sign outside: %v", err)
		}

		return raw
	}

	t.Run("AddProofByProvider with the key the header names", func(t *testing.T) {
		pres := newPres(t)
		if err := pres.AddProofByProvider(heldProv, vp.WithResolver(resolver)); err != nil {
			t.Fatalf("the right key was refused: %v", err)
		}
		if err := pres.Verify(vp.WithResolver(resolver)); err != nil {
			t.Fatalf("verify: %v", err)
		}
	})

	t.Run("AddProofByProvider with another key", func(t *testing.T) {
		err := newPres(t).AddProofByProvider(otherProv, vp.WithResolver(resolver))
		if err == nil || !strings.Contains(err.Error(), "does not verify against verification method") {
			t.Fatalf("err = %v, want the wrong key to be refused at signing time", err)
		}
	})

	// The function that did not exist.
	t.Run("AddCustomProof with the key the header names", func(t *testing.T) {
		pres := newPres(t)
		if err := pres.AddCustomProof(&dto.Proof{Signature: signOutside(t, pres, heldKey)},
			vp.WithResolver(resolver)); err != nil {
			t.Fatalf("an externally made signature by the right key was refused: %v", err)
		}
		if err := pres.Verify(vp.WithResolver(resolver)); err != nil {
			t.Fatalf("verify: %v", err)
		}
	})

	t.Run("AddCustomProof with another key", func(t *testing.T) {
		pres := newPres(t)
		err := pres.AddCustomProof(&dto.Proof{Signature: signOutside(t, pres, otherKey)},
			vp.WithResolver(resolver))
		if err == nil || !strings.Contains(err.Error(), "does not verify against verification method") {
			t.Fatalf("err = %v, want the wrong key to be refused", err)
		}
	})

	t.Run("AddCustomProof with something that is not a JWS signature", func(t *testing.T) {
		err := newPres(t).AddCustomProof(&dto.Proof{Signature: make([]byte, 100)}, vp.WithResolver(resolver))
		if err == nil || !strings.Contains(err.Error(), "64-byte r||s") {
			t.Fatalf("err = %v, want the wrong shape to be refused", err)
		}
	})

	// Challenge and domain rewrite the payload, so they cannot be applied to a
	// signature that already covers it. AddProofByProvider may still take them,
	// because it signs afterwards.
	t.Run("challenge and domain are refused by AddCustomProof", func(t *testing.T) {
		pres := newPres(t)
		err := pres.AddCustomProof(&dto.Proof{Signature: signOutside(t, pres, heldKey)},
			vp.WithChallenge("n0nce"), vp.WithResolver(resolver))
		if err == nil || !strings.Contains(err.Error(), "cannot be applied by AddCustomProof") {
			t.Fatalf("err = %v, want challenge to be refused after the fact", err)
		}
	})

	t.Run("challenge and domain are accepted by AddProofByProvider", func(t *testing.T) {
		pres := newPres(t)
		if err := pres.AddProofByProvider(heldProv,
			vp.WithChallenge("n0nce"), vp.WithDomain("https://verifier.example"),
			vp.WithResolver(resolver)); err != nil {
			t.Fatalf("signing with challenge and domain: %v", err)
		}
		if err := pres.Verify(vp.WithResolver(resolver),
			vp.WithExpectedChallenge("n0nce"), vp.WithExpectedDomain("https://verifier.example")); err != nil {
			t.Fatalf("verify: %v", err)
		}
	})

	t.Run("a build-time option passed at signing time", func(t *testing.T) {
		pres, err := vp.NewJOSEPresentation(joseVPContents(did),
			vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
		if err != nil {
			t.Fatalf("new jose presentation: %v", err)
		}
		err = pres.AddProofByProvider(heldProv,
			vp.WithVerificationMethodKey("key-2"), vp.WithResolver(resolver))
		if err == nil || !strings.Contains(err.Error(), "cannot be applied when signing") {
			t.Fatalf("err = %v, want the build-time option to be refused", err)
		}
	})
}
