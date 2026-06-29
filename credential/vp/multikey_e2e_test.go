package vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// TestVP_MultiKey_SignVerify signs and verifies a presentation with each holder
// key type: secp256k1 (ecdsa-rdfc-2019), P-256 (JsonWebSignature2020/ES256) and
// RSA (JsonWebSignature2020/RS256).
func TestVP_MultiKey_SignVerify(t *testing.T) {
	const holderSecp = "57600b3f2b7e1054094e14cd85c72a40dc74c4ee062bb381cea604b55ce56aec"

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
			did:  "did:example:vp-secp",
			provider: func(t *testing.T) signer.SignerProvider {
				p, err := signer.NewDefaultProvider(holderSecp)
				if err != nil {
					t.Fatalf("secp provider: %v", err)
				}
				return p
			},
			vm: vmpkg.NewSecp256k1VM("did:example:vp-secp", "key-1", secpPubHex(t, holderSecp)),
		},
		{
			name: "P-256/JsonWebSignature2020",
			did:  "did:example:vp-p256",
			provider: func(t *testing.T) signer.SignerProvider {
				p, err := signer.NewP256Provider(p256Priv)
				if err != nil {
					t.Fatalf("p256 provider: %v", err)
				}
				return p
			},
			vm: vmpkg.NewP256VM("did:example:vp-p256", "key-1", &p256Priv.PublicKey),
		},
		{
			name: "RSA/JsonWebSignature2020",
			did:  "did:example:vp-rsa",
			provider: func(t *testing.T) signer.SignerProvider {
				p, err := signer.NewRSAProvider(rsaKey)
				if err != nil {
					t.Fatalf("rsa provider: %v", err)
				}
				return p
			},
			vm: vmpkg.NewRSAVM("did:example:vp-rsa", "key-1", &rsaKey.PublicKey),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(tc.did, tc.vm))

			pres, err := vp.ParseJSONPresentation(vpDoc(tc.did))
			if err != nil {
				t.Fatalf("parse vp: %v", err)
			}
			if err := pres.AddProofByProvider(tc.provider(t), vp.WithResolver(resolver)); err != nil {
				t.Fatalf("sign vp: %v", err)
			}
			if err := pres.Verify(vp.WithResolver(resolver)); err != nil {
				t.Fatalf("verify vp: %v", err)
			}
		})
	}
}
