package vc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// Every signing path goes through SigningKey.Accept, which holds the signature
// it is handed to being made by the key the header names, over this signing
// input, in the 64-byte r||s shape a JWS carries. Without it a credential could
// be built carrying a signature it could not itself verify, and the error landed
// on whoever received it rather than whoever produced it.
//
// AddCustomProof matters most here: it exists for a key the process never holds
// — an HSM, a wallet — so the signature arrives as opaque bytes, and this is the
// only place they can be checked before they become part of a credential.
func TestJOSECredential_SigningPathsCheckTheSignature(t *testing.T) {
	const did = "did:example:jose-signing"

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

	newCred := func(t *testing.T) *vc.JOSECredential {
		t.Helper()
		cred, err := vc.NewJOSECredential(vc.CredentialContents{
			Context:   []interface{}{"https://www.w3.org/ns/credentials/v2"},
			Types:     []string{"VerifiableCredential"},
			Issuer:    did,
			ValidFrom: time.Now().Add(-time.Hour),
			Subject:   []vc.Subject{{ID: "did:example:subject"}},
		}, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
		if err != nil {
			t.Fatalf("new jose credential: %v", err)
		}

		return cred
	}
	signOutside := func(t *testing.T, cred *vc.JOSECredential, key *ecdsa.PrivateKey) []byte {
		t.Helper()
		input, err := cred.GetSigningInput()
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
		cred := newCred(t)
		if err := cred.AddProofByProvider(heldProv, vc.WithResolver(resolver)); err != nil {
			t.Fatalf("the right key was refused: %v", err)
		}
		if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
			t.Fatalf("verify: %v", err)
		}
	})

	t.Run("AddProofByProvider with another key", func(t *testing.T) {
		err := newCred(t).AddProofByProvider(otherProv, vc.WithResolver(resolver))
		if err == nil || !strings.Contains(err.Error(), "does not verify against verification method") {
			t.Fatalf("err = %v, want the wrong key to be refused at signing time", err)
		}
	})

	t.Run("AddCustomProof with the key the header names", func(t *testing.T) {
		cred := newCred(t)
		if err := cred.AddCustomProof(&dto.Proof{Signature: signOutside(t, cred, heldKey)},
			vc.WithResolver(resolver)); err != nil {
			t.Fatalf("an externally made signature by the right key was refused: %v", err)
		}
		if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
			t.Fatalf("verify: %v", err)
		}
	})

	t.Run("AddCustomProof with another key", func(t *testing.T) {
		cred := newCred(t)
		err := cred.AddCustomProof(&dto.Proof{Signature: signOutside(t, cred, otherKey)},
			vc.WithResolver(resolver))
		if err == nil || !strings.Contains(err.Error(), "does not verify against verification method") {
			t.Fatalf("err = %v, want the wrong key to be refused", err)
		}
	})

	t.Run("AddCustomProof with something that is not a JWS signature", func(t *testing.T) {
		err := newCred(t).AddCustomProof(&dto.Proof{Signature: make([]byte, 100)}, vc.WithResolver(resolver))
		if err == nil || !strings.Contains(err.Error(), "64-byte r||s") {
			t.Fatalf("err = %v, want the wrong shape to be refused", err)
		}
	})

	// WithVerificationMethodKey decides the kid the header carries, which is
	// fixed once the token is built. Passing it at signing time used to be
	// ignored in silence, so a caller could believe they had pinned a key.
	t.Run("a build-time option passed at signing time", func(t *testing.T) {
		err := newCred(t).AddProofByProvider(heldProv,
			vc.WithVerificationMethodKey("key-2"), vc.WithResolver(resolver))
		if err == nil || !strings.Contains(err.Error(), "cannot be applied when signing") {
			t.Fatalf("err = %v, want the build-time option to be refused", err)
		}
	})

	// A failed signing call must not take the signature the credential already
	// had. The old code assigned first and cleared to "" on failure.
	t.Run("a failed call leaves an existing signature alone", func(t *testing.T) {
		cred := newCred(t)
		if err := cred.AddProofByProvider(heldProv, vc.WithResolver(resolver)); err != nil {
			t.Fatalf("first signing: %v", err)
		}
		before, err := cred.Serialize()
		if err != nil {
			t.Fatalf("serialize: %v", err)
		}

		if err := cred.AddProofByProvider(otherProv, vc.WithResolver(resolver)); err == nil {
			t.Fatal("re-signing with the wrong key succeeded")
		}

		after, err := cred.Serialize()
		if err != nil {
			t.Fatalf("serialize: %v", err)
		}
		if before != after {
			t.Fatalf("a failed re-signing changed the credential:\n before %v\n after  %v", before, after)
		}
		if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
			t.Fatalf("the original signature no longer verifies: %v", err)
		}
	})
}
