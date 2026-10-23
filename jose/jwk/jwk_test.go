package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/pilacorp/go-credential-sdk/jose"
)

func TestJWKRoundTrip(t *testing.T) {
	p256 := newP256Key(t)
	k1 := newSecpKey(t)
	for name, key := range map[string]*ecdsa.PublicKey{"P-256": p256, "secp256k1": k1} {
		t.Run(name, func(t *testing.T) {
			jwk, err := FromPublicKey(key)
			if err != nil {
				t.Fatal(err)
			}
			if len(jwk) != 4 || jwk["kty"] != "EC" || jwk["crv"] != name {
				t.Fatalf("got %v, want kty, crv=%s, x, y only", jwk, name)
			}
			back, err := ToPublicKey(jwk)
			if err != nil {
				t.Fatal(err)
			}
			if back.X.Cmp(key.X) != 0 || back.Y.Cmp(key.Y) != 0 {
				t.Fatal("round trip changed the key")
			}
		})
	}
}

func TestToPublicKeySecp256k1UsesDecredCurve(t *testing.T) {
	k1 := newSecpKey(t)
	jwk, _ := FromPublicKey(k1)
	back, err := ToPublicKey(jwk)
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

func TestToPublicKeyRejectsStrippedLeadingZero(t *testing.T) {
	key := keyWithLeadingZeroX(t)
	jwk, err := FromPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if x, _ := jose.DecodeSegment(jwk["x"].(string)); len(x) != 32 {
		t.Fatalf("FromPublicKey wrote %d-byte x, want 32 (left-padded)", len(x))
	}
	jwk["x"] = jose.EncodeSegment(key.X.Bytes()) // 31 bytes, same point
	_, err = ToPublicKey(jwk)
	wantErr(t, err, ErrBadKey)
}

func TestToPublicKeyRejectsPointNotOnCurve(t *testing.T) {
	p256 := newP256Key(t)
	k1 := newSecpKey(t)
	for _, key := range []*ecdsa.PublicKey{p256, k1} {
		jwk, _ := FromPublicKey(key)
		y := new(big.Int).Add(key.Y, big.NewInt(1))
		yb := make([]byte, 32)
		y.FillBytes(yb)
		jwk["y"] = jose.EncodeSegment(yb)
		_, err := ToPublicKey(jwk)
		wantErr(t, err, ErrBadKey)
	}
}

func TestToPublicKeyRejects(t *testing.T) {
	p256 := newP256Key(t)
	base, _ := FromPublicKey(p256)
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
			_, err := ToPublicKey(jwk)
			wantErr(t, err, ErrBadKey)
		})
	}
	_, err := ToPublicKey(nil)
	wantErr(t, err, ErrBadKey)
}

func TestFromPublicKeyRejectsBadKeys(t *testing.T) {
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p256 := newP256Key(t)
	off := &ecdsa.PublicKey{Curve: p256.Curve, X: p256.X, Y: new(big.Int).Add(p256.Y, big.NewInt(1))}
	for name, key := range map[string]*ecdsa.PublicKey{"nil": nil, "P-384": &p384.PublicKey, "off curve": off} {
		t.Run(name, func(t *testing.T) {
			_, err := FromPublicKey(key)
			wantErr(t, err, ErrBadKey)
		})
	}
}

// A secp256k1 key built on another implementation of the curve (go-ethereum's,
// here a copy of the parameters) is recognised by its parameters.
func TestCurveRecognisedByParameters(t *testing.T) {
	k1 := newSecpKey(t)
	params := *secp256k1.S256().Params()
	foreign := &ecdsa.PublicKey{Curve: &params, X: k1.X, Y: k1.Y}
	jwk, err := FromPublicKey(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if jwk["crv"] != "secp256k1" {
		t.Fatalf("crv %v, want secp256k1", jwk["crv"])
	}
}

func TestCrvOfInvalidKindPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic for an invalid curve kind")
		}
	}()
	crvOf(0)
}
