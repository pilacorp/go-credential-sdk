package vc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// mkCredentialJSON builds a VC whose issuer is the given DID. @vocab keeps the
// custom credentialSubject terms defined so canonicalization stays in SafeMode.
func mkCredentialJSON(issuerDID string) []byte {
	return []byte(fmt.Sprintf(`{
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        {"@vocab": "https://example.org/vocab#"}
      ],
      "id": "urn:uuid:multikey-vc-001",
      "type": ["VerifiableCredential", "IdentityCredential"],
      "issuer": %q,
      "validFrom": "2026-01-01T00:00:00Z",
      "credentialSubject": {
        "id": "did:example:subject",
        "name": "Nguyen Van A"
      }
    }`, issuerDID))
}

// TestVC_MultiKey_IssueVerify signs and verifies a plain JSON credential with
// each supported issuer key type: secp256k1 (ecdsa-rdfc-2019), P-256
// (JsonWebSignature2020/ES256) and RSA (JsonWebSignature2020/RS256).
func TestVC_MultiKey_IssueVerify(t *testing.T) {
	// A fixed secp256k1 scalar so the test is deterministic.
	const secpPriv = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

	p256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}

	cases := []struct {
		name     string
		did      string
		provider func(t *testing.T) signer.SignerProvider
		vm       vmpkg.VerificationMethodEntry
	}{
		{
			name: "secp256k1/ecdsa-rdfc-2019",
			did:  "did:example:vc-secp",
			provider: func(t *testing.T) signer.SignerProvider {
				p, err := signer.NewDefaultProvider(secpPriv)
				if err != nil {
					t.Fatalf("secp provider: %v", err)
				}
				return p
			},
			vm: vmpkg.NewSecp256k1VM("did:example:vc-secp", "key-1", pubHex(t, secpPriv)),
		},
		{
			name: "P-256/JsonWebSignature2020",
			did:  "did:example:vc-p256",
			provider: func(t *testing.T) signer.SignerProvider {
				p, err := signer.NewP256Provider(p256Priv)
				if err != nil {
					t.Fatalf("p256 provider: %v", err)
				}
				return p
			},
			vm: vmpkg.NewP256VM("did:example:vc-p256", "key-1", &p256Priv.PublicKey),
		},
		{
			name: "RSA/JsonWebSignature2020",
			did:  "did:example:vc-rsa",
			provider: func(t *testing.T) signer.SignerProvider {
				p, err := signer.NewRSAProvider(rsaKey)
				if err != nil {
					t.Fatalf("rsa provider: %v", err)
				}
				return p
			},
			vm: vmpkg.NewRSAVM("did:example:vc-rsa", "key-1", &rsaKey.PublicKey),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(tc.did, tc.vm))

			cred, err := vc.ParseJSONCredential(mkCredentialJSON(tc.did))
			if err != nil {
				t.Fatalf("parse credential: %v", err)
			}
			if err := cred.AddProofByProvider(
				tc.provider(t),
				vc.WithVerificationMethodKey("key-1"),
				vc.WithResolver(resolver),
			); err != nil {
				t.Fatalf("add proof: %v", err)
			}
			if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if got := cred.ExtractField("credentialSubject.name"); got != "Nguyen Van A" {
				t.Errorf("name = %v, want %q", got, "Nguyen Van A")
			}
		})
	}
}

// TestECDSASD_MultiKey_IssueDeriveVerify exercises ecdsa-sd-2023 with both the
// standard P-256 issuer key and the secp256k1 issuer key (a non-standard
// extension this SDK supports): issue a base proof, derive a selective
// disclosure, and verify the derived proof end-to-end.
func TestECDSASD_MultiKey_IssueDeriveVerify(t *testing.T) {
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
			name: "P-256 issuer (standard)",
			did:  "did:example:sd-p256",
			provider: func(t *testing.T) signer.SignerProvider {
				p, err := signer.NewP256Provider(p256Priv)
				if err != nil {
					t.Fatalf("p256 provider: %v", err)
				}
				return p
			},
			vm: vmpkg.NewP256VM("did:example:sd-p256", "key-1", &p256Priv.PublicKey),
		},
		{
			name: "secp256k1 issuer (extension)",
			did:  "did:example:sd-secp",
			provider: func(t *testing.T) signer.SignerProvider {
				p, err := signer.NewDefaultProvider(secpPriv)
				if err != nil {
					t.Fatalf("secp provider: %v", err)
				}
				return p
			},
			vm: vmpkg.NewSecp256k1VM("did:example:sd-secp", "key-1", pubHex(t, secpPriv)),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(tc.did, tc.vm))

			base, err := vc.ParseECDSASDCredential(mkSDCredentialJSON(tc.did))
			if err != nil {
				t.Fatalf("parse base: %v", err)
			}
			if err := base.AddProofByProvider(
				tc.provider(t),
				[]string{"issuer", "validFrom", "credentialSubject.id"},
				vc.WithVerificationMethodKey("key-1"),
				vc.WithResolver(resolver),
			); err != nil {
				t.Fatalf("add base proof: %v", err)
			}
			if err := base.Verify(vc.WithResolver(resolver)); err != nil {
				t.Fatalf("verify base proof: %v", err)
			}

			derived, err := base.Derive([]string{"credentialSubject.name"})
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			if err := derived.Verify(vc.WithResolver(resolver)); err != nil {
				t.Fatalf("verify derived proof: %v", err)
			}
			if got := derived.ExtractField("credentialSubject.name"); got != "Nguyen Van A" {
				t.Errorf("revealed name = %v, want %q", got, "Nguyen Van A")
			}
			if got := derived.ExtractField("credentialSubject.email"); got != nil {
				t.Errorf("email should be hidden, got %v", got)
			}
		})
	}
}

// mkSDCredentialJSON builds a selective-disclosure VC with a few extra claims to
// exercise mandatory + hidden fields.
func mkSDCredentialJSON(issuerDID string) []byte {
	return []byte(fmt.Sprintf(`{
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        {"@vocab": "https://example.org/vocab#"}
      ],
      "id": "urn:uuid:multikey-sd-001",
      "type": ["VerifiableCredential", "IdentityCredential"],
      "issuer": %q,
      "validFrom": "2026-01-01T00:00:00Z",
      "credentialSubject": {
        "id": "did:example:subject",
        "name": "Nguyen Van A",
        "email": "a@example.vn"
      }
    }`, issuerDID))
}
