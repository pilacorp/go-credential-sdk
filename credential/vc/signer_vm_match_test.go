package vc_test

import (
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// A signer bound to the wrong VM must fail at issuance, not at the verifier.
func TestVC_SignerKeyMustMatchVM(t *testing.T) {
	const did = "did:example:vm-match"

	signerPriv := genP256(t)
	prov, err := signer.NewP256Provider(signerPriv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	t.Run("mismatched key rejected at signing", func(t *testing.T) {
		// The DID publishes a different P-256 key.
		vmPriv := genP256(t)
		resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did,
			vmpkg.NewP256VM(did, "key-1", &vmPriv.PublicKey)))

		cred, err := vc.ParseJSONCredential(mkCredentialJSON(did))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		err = cred.AddProofByProvider(prov,
			vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
		if err == nil || !strings.Contains(err.Error(), "does not verify against verification method") {
			t.Fatalf("add proof err = %v, want a signature-mismatch error", err)
		}

		// The failed attempt must not leave a proof behind.
		if _, err := cred.Serialize(); err == nil {
			t.Fatal("credential kept a proof after the check rejected it")
		}
	})

	t.Run("matching key signs and verifies", func(t *testing.T) {
		resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did,
			vmpkg.NewP256VM(did, "key-1", &signerPriv.PublicKey)))

		cred, err := vc.ParseJSONCredential(mkCredentialJSON(did))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := cred.AddProofByProvider(prov,
			vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver)); err != nil {
			t.Fatalf("add proof: %v", err)
		}
		if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
			t.Fatalf("verify: %v", err)
		}
	})

	// ecdsa-sd-2023 checks its base signature the same way.
	t.Run("ecdsa-sd base proof rejected too", func(t *testing.T) {
		vmPriv := genP256(t)
		resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did,
			vmpkg.NewP256VM(did, "key-1", &vmPriv.PublicKey)))

		base, err := vc.ParseECDSASDCredential(mkSDCredentialJSON(did))
		if err != nil {
			t.Fatalf("parse base: %v", err)
		}
		err = base.AddProofByProvider(prov,
			[]string{"issuer", "validFrom"},
			vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
		if err == nil || !strings.Contains(err.Error(), "does not verify against the verification method") {
			t.Fatalf("add base proof err = %v, want a signature-mismatch error", err)
		}
	})

	// The check needs only the signature, so a callback provider is covered too.
	t.Run("callback provider is checked too", func(t *testing.T) {
		vmPriv := genP256(t)
		inner, err := signer.NewP256Provider(vmPriv)
		if err != nil {
			t.Fatalf("inner provider: %v", err)
		}
		fn, err := signer.NewP256Func(inner.Sign)
		if err != nil {
			t.Fatalf("func provider: %v", err)
		}

		// VM publishes signerPriv, the callback signs with vmPriv → mismatch.
		resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did,
			vmpkg.NewP256VM(did, "key-1", &signerPriv.PublicKey)))

		cred, err := vc.ParseJSONCredential(mkCredentialJSON(did))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		err = cred.AddProofByProvider(fn,
			vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
		if err == nil || !strings.Contains(err.Error(), "does not verify against verification method") {
			t.Fatalf("add proof err = %v, want a signature-mismatch error", err)
		}
	})
}
