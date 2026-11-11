package jws

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// newP256Signer returns a PrivateKeySigner on a fresh P-256 key.
func newP256Signer(t *testing.T) (Signer, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return mustPrivateKeySigner(t, priv), &priv.PublicKey
}

// newSecpSigner returns a PrivateKeySigner on a fresh secp256k1 key.
// withRecovery makes it answer r||s||v (65 bytes): r||s followed by a
// recovery id, as an Ethereum-style signer does.
func newSecpSigner(t *testing.T, withRecovery bool) (Signer, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	s := mustPrivateKeySigner(t, priv.ToECDSA())
	if withRecovery {
		inner := s
		s = funcSigner{AlgES256K, func(in []byte) ([]byte, error) {
			raw, err := inner.Sign(context.Background(), in)
			return append(raw, 1), err
		}}
	}
	return s, priv.PubKey().ToECDSA()
}

func mustPrivateKeySigner(t *testing.T, priv *ecdsa.PrivateKey) Signer {
	t.Helper()
	s, err := PrivateKeySigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// funcSigner signs as alg and answers whatever f returns for the signing
// input.
type funcSigner struct {
	alg string
	f   func(signingInput []byte) ([]byte, error)
}

func (s funcSigner) Alg() string { return s.alg }

// Sign ignores ctx: the tests that need it use DigestSigner.
func (s funcSigner) Sign(_ context.Context, in []byte) ([]byte, error) { return s.f(in) }

// countingSigner counts the calls to Sign.
type countingSigner struct {
	Signer
	calls int
}

func (c *countingSigner) Sign(ctx context.Context, in []byte) ([]byte, error) {
	c.calls++
	return c.Signer.Sign(ctx, in)
}

// highS wraps a signer and flips its s to n-s, the other valid encoding.
func highS(inner Signer, curve elliptic.Curve) Signer {
	return funcSigner{inner.Alg(), func(in []byte) ([]byte, error) {
		raw, err := inner.Sign(context.Background(), in)
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
	}}
}

func mustSign(t *testing.T, s Signer, pub *ecdsa.PublicKey, header map[string]any, payload string) string {
	t.Helper()
	token, err := Sign(context.Background(), s, pub, header, []byte(payload))
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
