package vc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// A DID as authen-service publishes it once #key-3 is added: one scalar as
// #key-1 (secp256k1 hex), #key-2 (P-256 Multikey) and #key-3 (the secp256k1 key
// again, as a JsonWebKey). Adding #key-3 must not move a VC JOSE signed with no
// key pinned off #key-2; pinning #key-3 gives the ES256K token a VC-JOSE-COSE
// verifier accepts, and it verifies.
func TestJOSECredential_JsonWebKeyMethodOnlyWhenPinned(t *testing.T) {
	const did = "did:example:jose-jwk"

	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The P-256 order is below the secp256k1 order, so the scalar is valid on both.
	scalar := p256Key.D.FillBytes(make([]byte, 32))
	k1Key, err := crypto.ToECDSA(scalar)
	if err != nil {
		t.Fatal(err)
	}

	key2, err := vmpkg.NewP256MultikeyVM(did, "key-2", &p256Key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	key3 := vmpkg.VerificationMethodEntry{
		ID: did + "#key-3", Type: "JsonWebKey", Controller: did,
		PublicKeyJwk: &vmpkg.JWK{
			Kty: "EC", Crv: "secp256k1",
			X: base64.RawURLEncoding.EncodeToString(k1Key.X.FillBytes(make([]byte, 32))),
			Y: base64.RawURLEncoding.EncodeToString(k1Key.Y.FillBytes(make([]byte, 32))),
		},
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did,
		vmpkg.NewSecp256k1VM(did, "key-1", hex.EncodeToString(crypto.FromECDSAPub(&k1Key.PublicKey))),
		key2, key3))

	p256Prov, err := signer.NewP256Provider(p256Key)
	if err != nil {
		t.Fatal(err)
	}
	k1Prov, err := signer.NewDefaultProvider(hex.EncodeToString(scalar))
	if err != nil {
		t.Fatal(err)
	}

	issue := func(t *testing.T, prov signer.SignerProvider, opts ...vc.CredentialOpt) string {
		t.Helper()
		cred, err := vc.NewJOSECredential(vc.CredentialContents{
			Context:   []interface{}{"https://www.w3.org/ns/credentials/v2"},
			Types:     []string{"VerifiableCredential"},
			Issuer:    did,
			ValidFrom: time.Now().Add(-time.Hour),
			Subject:   []vc.Subject{{ID: "did:example:subject"}},
		}, append(opts, vc.WithResolver(resolver))...)
		if err != nil {
			t.Fatalf("NewJOSECredential: %v", err)
		}
		if err := cred.AddProofByProvider(prov); err != nil {
			t.Fatalf("AddProofByProvider: %v", err)
		}
		token, err := cred.Serialize()
		if err != nil {
			t.Fatal(err)
		}

		return token.(string)
	}

	t.Run("no key pinned stays on #key-2", func(t *testing.T) {
		kid, alg := tokenKidAlg(t, issue(t, p256Prov))
		if kid != did+"#key-2" || alg != "ES256" {
			t.Fatalf("kid %q alg %q, want %s#key-2 ES256", kid, alg, did)
		}
	})

	t.Run("#key-3 pinned signs ES256K and verifies", func(t *testing.T) {
		token := issue(t, k1Prov, vc.WithVerificationMethodKey("key-3"))
		kid, alg := tokenKidAlg(t, token)
		if kid != did+"#key-3" || alg != "ES256K" {
			t.Fatalf("kid %q alg %q, want %s#key-3 ES256K", kid, alg, did)
		}

		parsed, err := vc.ParseJOSECredential(token)
		if err != nil {
			t.Fatalf("ParseJOSECredential: %v", err)
		}
		if err := parsed.Verify(vc.WithResolver(resolver)); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})
}

func tokenKidAlg(t *testing.T, token string) (kid, alg string) {
	t.Helper()

	raw, err := base64.RawURLEncoding.DecodeString(strings.SplitN(token, ".", 2)[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var h struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatalf("header JSON: %v", err)
	}

	return h.Kid, h.Alg
}
