package jws

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// TC-38 (REQ-54): DigestSigner hands sign the SHA-256 of the JWS Signing
// Input (RFC 7518 §3.4) and returns its answer as the signature.
func TestDigestSigner(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	s, err := DigestSigner(AlgES256, func(_ context.Context, digest []byte) ([]byte, error) {
		got = append([]byte{}, digest...)
		r, sv, err := ecdsa.Sign(rand.Reader, priv, digest)
		if err != nil {
			return nil, err
		}
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		sv.FillBytes(out[32:])
		return out, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	token := mustSign(t, s, &priv.PublicKey, nil, `{"a":1}`)
	if _, _, err := Verify(token, &priv.PublicKey, nil); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(token[:strings.LastIndex(token, ".")]))
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("sign got %x, want SHA-256 of the signing input %x", got, want)
	}

	_, err = DigestSigner("RS256", func(context.Context, []byte) ([]byte, error) { return nil, nil })
	wantErr(t, err, jose.ErrUnsupportedAlg)
	_, err = DigestSigner(AlgES256, nil)
	wantErr(t, err, jose.ErrInvalidArgument)
}

// TC-39 (REQ-55): PrivateKeySigner signs ES256 on P-256 and ES256K on
// secp256k1, and refuses other keys and keys whose halves disagree.
func TestPrivateKeySigner(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k1, _ := secp256k1.GeneratePrivateKey()
	for _, tc := range []struct {
		name string
		priv *ecdsa.PrivateKey
		alg  string
	}{
		{"P-256", p256, AlgES256},
		{"secp256k1", k1.ToECDSA(), AlgES256K},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := mustPrivateKeySigner(t, tc.priv)
			if s.Alg() != tc.alg {
				t.Fatalf("Alg %q, want %q", s.Alg(), tc.alg)
			}
			h, _, err := Verify(mustSign(t, s, &tc.priv.PublicKey, nil, `{}`), &tc.priv.PublicKey, nil)
			if err != nil {
				t.Fatal(err)
			}
			if h.Alg() != tc.alg {
				t.Fatalf("header alg %q, want %q", h.Alg(), tc.alg)
			}
		})
	}

	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	zeroD := &ecdsa.PrivateKey{PublicKey: p256.PublicKey, D: new(big.Int)}
	mismatched := &ecdsa.PrivateKey{PublicKey: other.PublicKey, D: p256.D}
	for _, tc := range []struct {
		name string
		priv any
		want error
	}{
		{"Ed25519", edPriv, jose.ErrUnsupportedKey},
		{"P-384", p384, jose.ErrUnsupportedKey},
		{"d = 0", zeroD, ErrBadKey},
		{"public key of another key", mismatched, ErrBadKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := PrivateKeySigner(tc.priv)
			wantErr(t, err, tc.want)
		})
	}
}
