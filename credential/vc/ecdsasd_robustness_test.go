package vc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// signSDBase issues an ecdsa-sd-2023 base credential and returns its serialized
// JSON. mandatory = issuer/validFrom/credentialSubject.id.
func signSDBase(t *testing.T, did string, provider signer.SignerProvider, resolver vmpkg.ResolverProvider) []byte {
	t.Helper()
	base, err := vc.ParseECDSASDCredential(mkSDCredentialJSON(did))
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	if err := base.AddProofByProvider(
		provider,
		[]string{"issuer", "validFrom", "credentialSubject.id"},
		vc.WithVerificationMethodKey("key-1"),
		vc.WithResolver(resolver),
	); err != nil {
		t.Fatalf("add base proof: %v", err)
	}
	serialized, err := base.Serialize()
	if err != nil {
		t.Fatalf("serialize base: %v", err)
	}
	b, err := json.Marshal(serialized)
	if err != nil {
		t.Fatalf("marshal base: %v", err)
	}
	return b
}

// Gap #1: the standard P-256 issuer published as a publicKeyMultibase Multikey
// (the W3C normative format) must route through the Multibase branch of
// P256PubFromVM and verify end-to-end.
func TestECDSASD_P256Multikey_IssueDeriveVerify(t *testing.T) {
	const did = "did:example:sd-p256-mb"

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	mkVM := vmpkg.VerificationMethodEntry{
		ID:                 did + "#key-1",
		Type:               "Multikey",
		Controller:         did,
		PublicKeyMultibase: vmpkg.EncodeP256PubMultibase(&priv.PublicKey),
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, mkVM))

	prov, err := signer.NewP256Provider(priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}
	baseBytes := signSDBase(t, did, prov, resolver)

	base, err := vc.ParseECDSASDCredential(baseBytes)
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	if err := base.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("verify base via Multikey VM: %v", err)
	}
	derived, err := base.Derive([]string{"credentialSubject.name"})
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if err := derived.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("verify derived via Multikey VM: %v", err)
	}
}

// Gap #2: a tampered revealed claim must fail verification, for both the P-256
// and secp256k1 issuer paths.
func TestECDSASD_Tamper_Rejected(t *testing.T) {
	const secpPriv = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"

	p256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}

	cases := []struct {
		name     string
		did      string
		provider func(t *testing.T) signer.SignerProvider
		vm       vmpkg.VerificationMethodEntry
	}{
		{
			name: "P-256",
			did:  "did:example:sd-tamper-p256",
			provider: func(t *testing.T) signer.SignerProvider {
				p, err := signer.NewP256Provider(p256Priv)
				if err != nil {
					t.Fatalf("p256 provider: %v", err)
				}
				return p
			},
			vm: vmpkg.NewP256VM("did:example:sd-tamper-p256", "key-1", &p256Priv.PublicKey),
		},
		{
			name: "secp256k1",
			did:  "did:example:sd-tamper-secp",
			provider: func(t *testing.T) signer.SignerProvider {
				p, err := signer.NewDefaultProvider(secpPriv)
				if err != nil {
					t.Fatalf("secp provider: %v", err)
				}
				return p
			},
			vm: vmpkg.NewSecp256k1VM("did:example:sd-tamper-secp", "key-1", pubHex(t, secpPriv)),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(tc.did, tc.vm))
			baseBytes := signSDBase(t, tc.did, tc.provider(t), resolver)

			base, err := vc.ParseECDSASDCredential(baseBytes)
			if err != nil {
				t.Fatalf("parse base: %v", err)
			}
			derived, err := base.Derive([]string{"credentialSubject.name"})
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			derivedBytes, err := derived.GetContents()
			if err != nil {
				t.Fatalf("get derived contents: %v", err)
			}

			var doc map[string]interface{}
			if err := json.Unmarshal(derivedBytes, &doc); err != nil {
				t.Fatalf("unmarshal derived: %v", err)
			}
			cs, ok := doc["credentialSubject"].(map[string]interface{})
			if !ok {
				t.Fatalf("derived has no credentialSubject object")
			}
			cs["name"] = "Someone Else"
			tamperedBytes, _ := json.Marshal(doc)

			tampered, err := vc.ParseJSONCredential(tamperedBytes)
			if err != nil {
				t.Fatalf("parse tampered: %v", err)
			}
			if err := tampered.Verify(vc.WithResolver(resolver)); err == nil {
				t.Fatal("tampered derived credential must not verify")
			}
		})
	}
}

// Gap #3: a proof signed with one curve must fail when the resolver advertises a
// verification method on the other curve — the dispatch must reject the
// mismatch rather than mis-verify.
func TestECDSASD_WrongCurveVM_Rejected(t *testing.T) {
	const secpPriv = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"

	p256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	secpProv, err := signer.NewDefaultProvider(secpPriv)
	if err != nil {
		t.Fatalf("secp provider: %v", err)
	}
	p256Prov, err := signer.NewP256Provider(p256Priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	t.Run("secp256k1 proof vs P-256 VM", func(t *testing.T) {
		const did = "did:example:sd-mismatch-1"
		// Sign with the real secp256k1 issuer.
		signResolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did,
			vmpkg.NewSecp256k1VM(did, "key-1", pubHex(t, secpPriv))))
		baseBytes := signSDBase(t, did, secpProv, signResolver)

		// Verify against a resolver that advertises a P-256 VM for the same DID.
		wrongResolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did,
			vmpkg.NewP256VM(did, "key-1", &p256Priv.PublicKey)))
		base, err := vc.ParseECDSASDCredential(baseBytes)
		if err != nil {
			t.Fatalf("parse base: %v", err)
		}
		if err := base.Verify(vc.WithResolver(wrongResolver)); err == nil {
			t.Fatal("secp256k1 proof must not verify against a P-256 VM")
		}
	})

	t.Run("P-256 proof vs secp256k1 VM", func(t *testing.T) {
		const did = "did:example:sd-mismatch-2"
		signResolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did,
			vmpkg.NewP256VM(did, "key-1", &p256Priv.PublicKey)))
		baseBytes := signSDBase(t, did, p256Prov, signResolver)

		wrongResolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did,
			vmpkg.NewSecp256k1VM(did, "key-1", pubHex(t, secpPriv))))
		base, err := vc.ParseECDSASDCredential(baseBytes)
		if err != nil {
			t.Fatalf("parse base: %v", err)
		}
		if err := base.Verify(vc.WithResolver(wrongResolver)); err == nil {
			t.Fatal("P-256 proof must not verify against a secp256k1 VM")
		}
	})
}
