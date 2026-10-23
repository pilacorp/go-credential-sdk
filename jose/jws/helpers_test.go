package jws

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// p256Signer signs in memory and returns r||s, as a P-256 provider does.
type p256Signer struct{ priv *ecdsa.PrivateKey }

func newP256Signer(t *testing.T) (*p256Signer, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &p256Signer{priv: priv}, &priv.PublicKey
}

func (s *p256Signer) Sign(digest []byte) ([]byte, error) {
	r, sv, err := ecdsa.Sign(rand.Reader, s.priv, digest)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	sv.FillBytes(out[32:])
	return out, nil
}

// secpSigner signs with secp256k1. withRecovery makes it answer r||s||v (65
// bytes): r||s followed by a recovery id.
type secpSigner struct {
	priv         *secp256k1.PrivateKey
	withRecovery bool
}

func newSecpSigner(t *testing.T, withRecovery bool) (*secpSigner, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return &secpSigner{priv: priv, withRecovery: withRecovery}, priv.PubKey().ToECDSA()
}

func (s *secpSigner) Sign(digest []byte) ([]byte, error) {
	sig := decredecdsa.Sign(s.priv, digest)
	r, sv := sig.R(), sig.S()
	rb, sb := r.Bytes(), sv.Bytes()
	out := append(rb[:], sb[:]...)
	if s.withRecovery {
		out = append(out, 1)
	}
	return out, nil
}

// funcSigner answers whatever its function returns.
type funcSigner func(digest []byte) ([]byte, error)

func (f funcSigner) Sign(digest []byte) ([]byte, error) { return f(digest) }

// countingSigner counts the calls to Sign.
type countingSigner struct {
	Signer
	calls int
}

func (c *countingSigner) Sign(digest []byte) ([]byte, error) {
	c.calls++
	return c.Signer.Sign(digest)
}

// highS wraps a signer and flips its s to n-s, the other valid encoding.
func highS(inner Signer, curve elliptic.Curve) Signer {
	return funcSigner(func(digest []byte) ([]byte, error) {
		raw, err := inner.Sign(digest)
		if err != nil {
			return nil, err
		}
		n := curve.Params().N
		s := new(big.Int).SetBytes(raw[32:64])
		if s.Cmp(new(big.Int).Rsh(n, 1)) <= 0 {
			s = new(big.Int).Sub(n, s)
		}
		out := append([]byte{}, raw[:32]...)
		sb := make([]byte, 32)
		s.FillBytes(sb)
		return append(out, sb...), nil
	})
}

func mustSign(t *testing.T, s Signer, pub *ecdsa.PublicKey, header map[string]any, payload string) string {
	t.Helper()
	token, err := Sign(s, pub, header, []byte(payload))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return token
}

func wantErr(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("got error %v, want %v", err, target)
	}
}
