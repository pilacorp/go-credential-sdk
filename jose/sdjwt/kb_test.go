package sdjwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
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
	want := KBVerifyParams{
		Audience: "https://verifier.example.org",
		Nonce:    "1234567890",
		SDHash:   sdHash,
		Now:      time.Unix(1748537244, 0),
		MaxAge:   5 * time.Minute,
	}
	if _, err := VerifyKBJWT(kb, holder, want); err != nil {
		t.Fatal(err)
	}
}

// NewKBJWT then VerifyKBJWT, on both curves. The payload holds the four
// claims of RFC 9901 §4.3 and the Extra claim, with iat in whole seconds, and
// VerifyKBJWT returns all of them.
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
			holder := s.pub
			c := KBClaims{
				Audience: "https://verifier.example",
				Nonce:    "n-0S6_WzA2Mj",
				IssuedAt: time.Unix(1748537244, 900_000_000),
				SDHash:   "0_Af-2B-EhLWX5ydh_w2xzwmO6iM66B_2QCEanI4fUY",
				// OpenID4VP 1.0 Appendix B.3.3.1, from its KB-JWT example.
				Extra: map[string]any{"transaction_data_hashes": []any{"fOBUSQvo46yQO-wRwXBcGqvnbKIueISEL961_Sjd4do"}},
			}
			kb, err := NewKBJWT(context.Background(), s, holder, c)
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]any{
				"iat":     json.Number("1748537244"),
				"aud":     "https://verifier.example",
				"nonce":   "n-0S6_WzA2Mj",
				"sd_hash": "0_Af-2B-EhLWX5ydh_w2xzwmO6iM66B_2QCEanI4fUY",

				"transaction_data_hashes": []any{"fOBUSQvo46yQO-wRwXBcGqvnbKIueISEL961_Sjd4do"},
			}
			if got := decodePayload(t, kb); !reflect.DeepEqual(got, want) {
				t.Fatalf("payload %v, want %v", got, want)
			}
			got, err := VerifyKBJWT(kb, holder, KBVerifyParams{Audience: c.Audience, Nonce: c.Nonce, SDHash: c.SDHash, Now: c.IssuedAt, MaxAge: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("VerifyKBJWT returned %v, want %v", got, want)
			}
		})
	}
}

// One row per check of RFC 9901 §7.3 step 5 that guards against a forged,
// replayed or stale KB-JWT, and the caller mistakes REQ-20 step 1 and 2
// return as they are. Now is fixed, MaxAge is 5 minutes, ClockSkew 1 minute.
func TestKBJWTRejects(t *testing.T) {
	now := time.Unix(1748537244, 0)
	holderSigner, otherSigner := newMemSigner(t, elliptic.P256()), newMemSigner(t, elliptic.P256())
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	want := KBVerifyParams{Audience: "https://verifier.example", Nonce: "n-0S6_WzA2Mj", SDHash: "0_Af-2B-EhLWX5ydh_w2xzwmO6iM66B_2QCEanI4fUY", Now: now, MaxAge: 5 * time.Minute, ClockSkew: time.Minute}

	for _, tc := range []struct {
		name   string
		other  bool // signed by a key other than holder
		edit   func(h jws.Header, c map[string]any)
		caller func(w *KBVerifyParams)
		holder crypto.PublicKey // nil: the key of holderSigner
		err    error
		not    error // must not match either
	}{
		{name: "signed by another key", other: true, err: ErrKBInvalid},
		{name: "typ jwt", edit: func(h jws.Header, _ map[string]any) { h["typ"] = "jwt" }, err: ErrKBInvalid},
		{name: "iat older than MaxAge plus skew", edit: func(_ jws.Header, c map[string]any) { c["iat"] = now.Add(-6*time.Minute - time.Second).Unix() }, err: ErrKBInvalid},
		{name: "iat later than skew", edit: func(_ jws.Header, c map[string]any) { c["iat"] = now.Add(time.Minute + time.Second).Unix() }, err: ErrKBInvalid},
		// RFC 9901 §7.3 step 5e leaves the window to the Verifier: a zero
		// ClockSkew is no skew, never a default.
		{name: "iat a second ahead with ClockSkew 0", edit: func(_ jws.Header, c map[string]any) { c["iat"] = now.Add(time.Second).Unix() }, caller: func(w *KBVerifyParams) { w.ClockSkew = 0 }, err: ErrKBInvalid},
		{name: "aud differs", edit: func(_ jws.Header, c map[string]any) { c["aud"] = "https://other.example" }, err: ErrKBAudience},
		// RFC 9901 §4.3: aud is a single string; an array is malformed, not
		// a KB-JWT made for another verifier.
		{name: "aud array holding the verifier", edit: func(_ jws.Header, c map[string]any) { c["aud"] = []any{want.Audience} }, err: ErrKBInvalid, not: ErrKBAudience},
		{name: "nonce differs", edit: func(_ jws.Header, c map[string]any) { c["nonce"] = "replayed" }, err: ErrKBNonce},
		{name: "sd_hash differs", edit: func(_ jws.Header, c map[string]any) { c["sd_hash"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }, err: ErrKBSDHash},
		// RFC 7519 §4.1.4: refused on or after exp, here exactly exp + skew.
		{name: "exp passed", edit: func(_ jws.Header, c map[string]any) { c["exp"] = now.Add(-time.Minute).Unix() }, err: ErrKBInvalid},
		{name: "nbf later than skew", edit: func(_ jws.Header, c map[string]any) { c["nbf"] = now.Add(time.Minute + time.Second).Unix() }, err: ErrKBInvalid},
		// RFC 9901 §7.3 step 5b: the application names the algorithms.
		{name: "alg not in AllowedAlgs", caller: func(w *KBVerifyParams) { w.AllowedAlgs = []string{jws.AlgES256K} }, err: jws.ErrAlgNotAllowed},
		{name: "caller: AllowedAlgs lists none", caller: func(w *KBVerifyParams) { w.AllowedAlgs = []string{"none"} }, err: jose.ErrUnsupportedAlg, not: ErrKBInvalid},
		{name: "caller: holder on P-384", holder: &p384.PublicKey, err: jose.ErrUnsupportedKey, not: ErrKBInvalid},
		{name: "caller: typed nil holder", holder: (*ecdsa.PublicKey)(nil), err: jose.ErrInvalidArgument, not: ErrKBInvalid},
		{name: "caller: zero MaxAge", caller: func(w *KBVerifyParams) { w.MaxAge = 0 }, err: jose.ErrInvalidArgument},
		// An empty expected nonce must not match a KB-JWT whose nonce is empty.
		{name: "caller: empty Nonce", edit: func(_ jws.Header, c map[string]any) { c["nonce"] = "" }, caller: func(w *KBVerifyParams) { w.Nonce = "" }, err: jose.ErrInvalidArgument},
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
			kb, err := jws.Sign(context.Background(), s, s.pub, h, payload)
			if err != nil {
				t.Fatal(err)
			}
			w := want
			if tc.caller != nil {
				tc.caller(&w)
			}
			holder := tc.holder
			if holder == nil {
				holder = holderSigner.pub
			}
			claims, err := VerifyKBJWT(kb, holder, w)
			if claims != nil {
				t.Fatalf("claims %v returned with an error", claims)
			}
			if !errors.Is(err, tc.err) || tc.not != nil && errors.Is(err, tc.not) {
				t.Fatalf("got %v, want %v and not %v", err, tc.err, tc.not)
			}
		})
	}
}

// Extra cannot replace the claims that bind the KB-JWT: a value copied from
// one Verifier's request must not make it valid for another Verifier or
// transaction.
func TestNewKBJWTKeepsItsClaims(t *testing.T) {
	s := newMemSigner(t, elliptic.P256())
	for _, name := range []string{"iat", "aud", "nonce", "sd_hash"} {
		c := KBClaims{
			Audience: "https://verifier.example",
			Nonce:    "n-0S6_WzA2Mj",
			IssuedAt: time.Unix(1748537244, 0),
			SDHash:   "0_Af-2B-EhLWX5ydh_w2xzwmO6iM66B_2QCEanI4fUY",
			Extra:    map[string]any{name: "https://other.example"},
		}
		if _, err := NewKBJWT(context.Background(), s, s.pub, c); !errors.Is(err, jose.ErrInvalidArgument) {
			t.Errorf("Extra holding %s: err = %v, want jose.ErrInvalidArgument", name, err)
		}
	}
}

// The holder key is the caller's: its class must not depend on the kb the
// holder sends, here one that is not even a JWS.
func TestVerifyKBJWTClassesHolderFirst(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	offCurve := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}
	p := KBVerifyParams{Audience: "https://verifier.example", Nonce: "n-0S6_WzA2Mj", SDHash: "0_Af-2B-EhLWX5ydh_w2xzwmO6iM66B_2QCEanI4fUY", MaxAge: time.Minute}
	for _, tc := range []struct {
		name   string
		holder crypto.PublicKey
		err    error
	}{
		{"P-384 holder", &p384.PublicKey, jose.ErrUnsupportedKey},
		{"off-curve holder", offCurve, jws.ErrBadKey},
	} {
		_, err := VerifyKBJWT("not-a-jws", tc.holder, p)
		if !errors.Is(err, tc.err) || errors.Is(err, ErrKBInvalid) {
			t.Errorf("%s: err = %v, want %v and not ErrKBInvalid", tc.name, err, tc.err)
		}
	}
}

// keySigner is a jws.Signer over an in-memory key, with its public key.
type keySigner struct {
	jws.Signer
	pub *ecdsa.PublicKey
}

func newMemSigner(t *testing.T, curve elliptic.Curve) keySigner {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jws.PrivateKeySigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return keySigner{s, &priv.PublicKey}
}
