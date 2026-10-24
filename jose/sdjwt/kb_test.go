package sdjwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jwk"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
)

// The SD-JWT+KB of RFC 9901 §5.2: SDHash of everything up to the last ~ is
// the sd_hash printed there, and the KB-JWT verifies with the cnf.jwk of the
// Issuer-signed JWT, the printed aud and nonce, and Now at the printed iat.
func TestKBJWTRFCExample(t *testing.T) {
	raw, err := os.ReadFile("testdata/rfc9901-examples.json")
	if err != nil {
		t.Fatal(err)
	}
	examples, err := jose.DecodeJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	var presentation string
	for _, e := range examples.([]any) {
		if ex := e.(map[string]any); ex["source"] == "RFC 9901 Section 5.2" {
			presentation = ex["presentation"].(string)
		}
	}
	cut := strings.LastIndex(presentation, "~") + 1
	sdJWT, kb := presentation[:cut], presentation[cut:]

	const sdHash = "0_Af-2B-EhLWX5ydh_w2xzwmO6iM66B_2QCEanI4fUY"
	if got := SDHash(sdJWT); got != sdHash {
		t.Fatalf("SDHash = %s, want %s", got, sdHash)
	}
	cnf := decodePayload(t, sdJWT[:strings.Index(sdJWT, "~")])["cnf"].(map[string]any)
	holder, err := jwk.ToPublicKey(cnf["jwk"].(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	want := KBWant{
		Audience: "https://verifier.example.org",
		Nonce:    "1234567890",
		SDHash:   sdHash,
		Now:      time.Unix(1748537244, 0),
	}
	if err := VerifyKBJWT(kb, holder, want); err != nil {
		t.Fatal(err)
	}
}

// NewKBJWT then VerifyKBJWT, on both curves. The payload holds the four
// claims of RFC 9901 §4.3 and nothing else, with iat in whole seconds.
func TestKBJWTRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name  string
		curve elliptic.Curve
	}{
		{"ES256", elliptic.P256()},
		{"ES256K", secp256k1.S256()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newMemSigner(t, tc.curve)
			holder := &s.PublicKey
			c := KBClaims{
				Audience: "https://verifier.example",
				Nonce:    "n-0S6_WzA2Mj",
				IssuedAt: time.Unix(1748537244, 900_000_000),
				SDHash:   "0_Af-2B-EhLWX5ydh_w2xzwmO6iM66B_2QCEanI4fUY",
			}
			kb, err := NewKBJWT(s, holder, c)
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]any{
				"iat":     json.Number("1748537244"),
				"aud":     "https://verifier.example",
				"nonce":   "n-0S6_WzA2Mj",
				"sd_hash": "0_Af-2B-EhLWX5ydh_w2xzwmO6iM66B_2QCEanI4fUY",
			}
			if got := decodePayload(t, kb); !reflect.DeepEqual(got, want) {
				t.Fatalf("payload %v, want %v", got, want)
			}
			err = VerifyKBJWT(kb, holder, KBWant{Audience: c.Audience, Nonce: c.Nonce, SDHash: c.SDHash, Now: c.IssuedAt})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// One row per check of RFC 9901 §7.3 step 5 that guards against a forged,
// replayed or stale KB-JWT, and one caller mistake. Now is fixed and MaxAge
// and ClockSkew are the defaults, 5 and 1 minutes.
func TestKBJWTRejects(t *testing.T) {
	now := time.Unix(1748537244, 0)
	holderSigner, otherSigner := newMemSigner(t, elliptic.P256()), newMemSigner(t, elliptic.P256())
	holder := &holderSigner.PublicKey
	want := KBWant{Audience: "https://verifier.example", Nonce: "n-0S6_WzA2Mj", SDHash: "0_Af-2B-EhLWX5ydh_w2xzwmO6iM66B_2QCEanI4fUY", Now: now}

	for _, tc := range []struct {
		name   string
		other  bool // signed by a key other than holder
		edit   func(h jws.Header, c map[string]any)
		caller func(w *KBWant)
		err    error
	}{
		{name: "signed by another key", other: true, err: ErrKBInvalid},
		{name: "typ jwt", edit: func(h jws.Header, _ map[string]any) { h["typ"] = "jwt" }, err: ErrKBInvalid},
		{name: "iat older than MaxAge plus skew", edit: func(_ jws.Header, c map[string]any) { c["iat"] = now.Add(-6*time.Minute - time.Second).Unix() }, err: ErrKBInvalid},
		{name: "iat later than skew", edit: func(_ jws.Header, c map[string]any) { c["iat"] = now.Add(time.Minute + time.Second).Unix() }, err: ErrKBInvalid},
		{name: "aud differs", edit: func(_ jws.Header, c map[string]any) { c["aud"] = "https://other.example" }, err: ErrKBAudience},
		{name: "aud array holding the verifier", edit: func(_ jws.Header, c map[string]any) { c["aud"] = []any{want.Audience} }, err: ErrKBAudience},
		{name: "nonce differs", edit: func(_ jws.Header, c map[string]any) { c["nonce"] = "replayed" }, err: ErrKBNonce},
		{name: "sd_hash differs", edit: func(_ jws.Header, c map[string]any) { c["sd_hash"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }, err: ErrKBSDHash},
		// RFC 7519 §4.1.4: refused on or after exp, here exactly exp + skew.
		{name: "exp passed", edit: func(_ jws.Header, c map[string]any) { c["exp"] = now.Add(-time.Minute).Unix() }, err: ErrKBInvalid},
		{name: "nbf later than skew", edit: func(_ jws.Header, c map[string]any) { c["nbf"] = now.Add(time.Minute + time.Second).Unix() }, err: ErrKBInvalid},
		// An empty expected nonce must not match a KB-JWT whose nonce is empty.
		{name: "caller: empty Nonce", edit: func(_ jws.Header, c map[string]any) { c["nonce"] = "" }, caller: func(w *KBWant) { w.Nonce = "" }, err: jose.ErrInvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := jws.Header{"typ": "kb+jwt"}
			c := map[string]any{"iat": now.Unix(), "aud": want.Audience, "nonce": want.Nonce, "sd_hash": want.SDHash}
			if tc.edit != nil {
				tc.edit(h, c)
			}
			s := holderSigner
			if tc.other {
				s = otherSigner
			}
			payload, err := jose.EncodeJSON(c)
			if err != nil {
				t.Fatal(err)
			}
			kb, err := jws.Sign(s, &s.PublicKey, h, payload)
			if err != nil {
				t.Fatal(err)
			}
			w := want
			if tc.caller != nil {
				tc.caller(&w)
			}
			if err := VerifyKBJWT(kb, holder, w); !errors.Is(err, tc.err) {
				t.Fatalf("got %v, want %v", err, tc.err)
			}
		})
	}
}

// memSigner signs in memory and answers 64-byte r||s.
type memSigner struct{ *ecdsa.PrivateKey }

func newMemSigner(t *testing.T, curve elliptic.Curve) memSigner {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return memSigner{priv}
}

func (s memSigner) Sign(digest []byte) ([]byte, error) {
	r, sv, err := ecdsa.Sign(rand.Reader, s.PrivateKey, digest)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	sv.FillBytes(out[32:])
	return out, nil
}
