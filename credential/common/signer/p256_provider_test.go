package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"
)

// halfOrder returns floor(n/2) for P-256.
func halfOrder() *big.Int {
	return new(big.Int).Rsh(elliptic.P256().Params().N, 1)
}

func TestNormalizeLowS(t *testing.T) {
	curve := elliptic.P256()
	n := curve.Params().N
	half := halfOrder()

	cases := []struct {
		name string
		in   *big.Int
		want *big.Int
	}{
		{"one", big.NewInt(1), big.NewInt(1)},
		{"half", new(big.Int).Set(half), new(big.Int).Set(half)},
		{"half+1", new(big.Int).Add(half, big.NewInt(1)), new(big.Int).Sub(n, new(big.Int).Add(half, big.NewInt(1)))},
		{"n-1", new(big.Int).Sub(n, big.NewInt(1)), big.NewInt(1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeLowS(curve, new(big.Int).Set(tc.in))
			if got.Cmp(tc.want) != 0 {
				t.Fatalf("NormalizeLowS(%s) = %s, want %s", tc.in, got, tc.want)
			}
			if got.Cmp(half) > 0 {
				t.Fatalf("result %s is high-S", got)
			}
		})
	}
}

// TestP256Provider_AlwaysLowS signs many digests and asserts every s <= n/2.
// Without normalization ~50% would be high-S, so 500 iterations make an
// accidental pass astronomically unlikely.
func TestP256Provider_AlwaysLowS(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewP256Provider(priv)
	if err != nil {
		t.Fatal(err)
	}
	half := halfOrder()
	for i := 0; i < 500; i++ {
		digest := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		sig, err := p.Sign(digest[:])
		if err != nil {
			t.Fatal(err)
		}
		if len(sig) != 64 {
			t.Fatalf("sig len = %d, want 64", len(sig))
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if s.Cmp(half) > 0 {
			t.Fatalf("iteration %d: high-S signature emitted: s=%x", i, s)
		}
		if !ecdsa.Verify(&priv.PublicKey, digest[:], r, s) {
			t.Fatalf("iteration %d: normalized signature does not verify", i)
		}
	}
}

// TestP256_VerifyAcceptsHighS locks in lenient verification: a high-S
// signature (as produced by OpenSSL/Java/unpatched Go) must still verify, per
// FIPS 186-5 §6.4.2. Only the signer side is normalized.
func TestP256_VerifyAcceptsHighS(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewP256Provider(priv)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("high-s"))
	sig, err := p.Sign(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	n := elliptic.P256().Params().N
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	highS := new(big.Int).Sub(n, s)
	if highS.Cmp(halfOrder()) <= 0 {
		t.Fatal("expected flipped s to be high-S")
	}
	if !ecdsa.Verify(&priv.PublicKey, digest[:], r, highS) {
		t.Fatal("verify must accept high-S signatures")
	}
}
