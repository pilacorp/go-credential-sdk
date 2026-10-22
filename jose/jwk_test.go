package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestJWKRoundTrip(t *testing.T) {
	_, p256 := newP256Signer(t)
	_, k1 := newSecpSigner(t, false)
	for name, key := range map[string]*ecdsa.PublicKey{"P-256": p256, "secp256k1": k1} {
		t.Run(name, func(t *testing.T) {
			jwk, err := JWKFromPublicKey(key)
			if err != nil {
				t.Fatal(err)
			}
			if len(jwk) != 4 || jwk["kty"] != "EC" || jwk["crv"] != name {
				t.Fatalf("got %v, want kty, crv=%s, x, y only", jwk, name)
			}
			back, err := PublicKeyFromJWK(jwk)
			if err != nil {
				t.Fatal(err)
			}
			if back.X.Cmp(key.X) != 0 || back.Y.Cmp(key.Y) != 0 {
				t.Fatal("round trip changed the key")
			}
		})
	}
}

func TestPublicKeyFromJWKSecp256k1UsesDecredCurve(t *testing.T) {
	_, k1 := newSecpSigner(t, false)
	jwk, _ := JWKFromPublicKey(k1)
	back, err := PublicKeyFromJWK(jwk)
	if err != nil {
		t.Fatal(err)
	}
	if back.Curve != secp256k1.S256() {
		t.Fatalf("curve %T, want secp256k1.S256()", back.Curve)
	}
}

// keyWithLeadingZeroX returns a P-256 key whose x starts with a zero byte, so
// a JWK writer that strips it produces a 31-byte x for the same point.
func keyWithLeadingZeroX(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	for range 20000 {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if priv.X.BitLen() <= 248 {
			return &priv.PublicKey
		}
	}
	t.Fatal("no key with a leading zero byte in x")
	return nil
}

func TestPublicKeyFromJWKRejectsStrippedLeadingZero(t *testing.T) {
	key := keyWithLeadingZeroX(t)
	jwk, err := JWKFromPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if x, _ := DecodeSegment(jwk["x"].(string)); len(x) != 32 {
		t.Fatalf("JWKFromPublicKey wrote %d-byte x, want 32 (left-padded)", len(x))
	}
	jwk["x"] = EncodeSegment(key.X.Bytes()) // 31 bytes, same point
	_, err = PublicKeyFromJWK(jwk)
	wantErr(t, err, ErrBadKey)
}

func TestPublicKeyFromJWKRejectsPointNotOnCurve(t *testing.T) {
	_, p256 := newP256Signer(t)
	_, k1 := newSecpSigner(t, false)
	for _, key := range []*ecdsa.PublicKey{p256, k1} {
		jwk, _ := JWKFromPublicKey(key)
		y := new(big.Int).Add(key.Y, big.NewInt(1))
		yb := make([]byte, 32)
		y.FillBytes(yb)
		jwk["y"] = EncodeSegment(yb)
		_, err := PublicKeyFromJWK(jwk)
		wantErr(t, err, ErrBadKey)
	}
}

func TestPublicKeyFromJWKRejects(t *testing.T) {
	_, p256 := newP256Signer(t)
	base, _ := JWKFromPublicKey(p256)
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for kk, vv := range base {
			m[kk] = vv
		}
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	for name, jwk := range map[string]map[string]any{
		"private key d": with("d", "AAAA"),
		"kty RSA":       with("kty", "RSA"),
		"kty missing":   with("kty", nil),
		"crv P-384":     with("crv", "P-384"),
		"x not string":  with("x", 1),
		"x bad base64":  with("x", "QR"),
		"y missing":     with("y", nil),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := PublicKeyFromJWK(jwk)
			wantErr(t, err, ErrBadKey)
		})
	}
	_, err := PublicKeyFromJWK(nil)
	wantErr(t, err, ErrBadKey)
}

func TestJWKFromPublicKeyRejectsBadKeys(t *testing.T) {
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, p256 := newP256Signer(t)
	off := &ecdsa.PublicKey{Curve: p256.Curve, X: p256.X, Y: new(big.Int).Add(p256.Y, big.NewInt(1))}
	for name, key := range map[string]*ecdsa.PublicKey{"nil": nil, "P-384": &p384.PublicKey, "off curve": off} {
		t.Run(name, func(t *testing.T) {
			_, err := JWKFromPublicKey(key)
			wantErr(t, err, ErrBadKey)
		})
	}
}

// A secp256k1 key built on another implementation of the curve (go-ethereum's,
// here a copy of the parameters) is recognised by its parameters.
func TestCurveRecognisedByParameters(t *testing.T) {
	_, k1 := newSecpSigner(t, false)
	params := *secp256k1.S256().Params()
	foreign := &ecdsa.PublicKey{Curve: &params, X: k1.X, Y: k1.Y}
	jwk, err := JWKFromPublicKey(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if jwk["crv"] != "secp256k1" {
		t.Fatalf("crv %v, want secp256k1", jwk["crv"])
	}
}
