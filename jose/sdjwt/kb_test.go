package sdjwt

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/jose"
)

const (
	rfcAudience = "https://verifier.example.org"
	rfcNonce    = "1234567890"
)

// RFC 9901 section 5, A.3 and A.4: SDHash of the presentation up to the last
// ~ is the sd_hash the holder signed, and the KB-JWT verifies with cnf.jwk.
func TestKBRFCExamples(t *testing.T) {
	checked := 0
	for _, ex := range loadRFCExamples(t) {
		issuerJWT, _, kb, err := Split(ex.presentation)
		mustNoErr(t, err)
		if kb == "" {
			continue
		}
		checked++
		t.Run(ex.name, func(t *testing.T) {
			_, raw, err := jose.Verify(issuerJWT, rfcIssuerKey(t), nil)
			mustNoErr(t, err)
			payload, err := jose.DecodeJSONObject(raw)
			mustNoErr(t, err)
			holderKey, err := jose.PublicKeyFromJWK(payload["cnf"].(map[string]any)["jwk"].(map[string]any))
			mustNoErr(t, err)

			kbPayload := mustObject(t, string(mustSegment(t, strings.Split(kb, ".")[1])))
			sdHash := SDHash(ex.presentation[:strings.LastIndex(ex.presentation, "~")+1])
			if sdHash != kbPayload["sd_hash"] {
				t.Fatalf("SDHash %s, KB-JWT has %v", sdHash, kbPayload["sd_hash"])
			}
			iat, _ := kbPayload["iat"].(json.Number).Int64()
			want := KBWant{Audience: rfcAudience, Nonce: rfcNonce, SDHash: sdHash, Now: time.Unix(iat, 0)}
			mustNoErr(t, VerifyKBJWT(kb, holderKey, want))
		})
	}
	if checked != 3 {
		t.Fatalf("%d examples with a KB-JWT, want 3", checked)
	}
}

func mustSegment(t *testing.T, s string) []byte {
	t.Helper()
	b, err := jose.DecodeSegment(s)
	mustNoErr(t, err)
	return b
}

func TestNewKBJWTRoundTrip(t *testing.T) {
	holder, holderPub := holderSigner(t)
	secp, secpPub := newSecpSigner(t) // 65-byte r||s||v, Vault style
	now := time.Unix(1748537244, 0)
	for _, tc := range []struct {
		name string
		s    jose.Signer
		alg  string
		key  *ecdsa.PublicKey
	}{
		{"ES256", holder, jose.AlgES256, holderPub},
		{"ES256K", secp, jose.AlgES256K, secpPub},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kb, err := NewKBJWT(tc.s, tc.alg, rfcAudience, rfcNonce, now, "hash")
			mustNoErr(t, err)
			parts := strings.Split(kb, ".")
			assertJSONEqual(t, mustObject(t, string(mustSegment(t, parts[0]))), map[string]any{"alg": tc.alg, "typ": "kb+jwt"})
			assertJSONEqual(t, mustObject(t, string(mustSegment(t, parts[1]))), map[string]any{
				"iat": json.Number("1748537244"), "aud": rfcAudience, "nonce": rfcNonce, "sd_hash": "hash",
			})
			want := KBWant{Audience: rfcAudience, Nonce: rfcNonce, SDHash: "hash", Now: now}
			mustNoErr(t, VerifyKBJWT(kb, tc.key, want))
		})
	}
}

func TestNewKBJWTRejects(t *testing.T) {
	holder, _ := holderSigner(t)
	now := time.Now()
	for _, args := range [][3]string{{"", "n", "h"}, {"a", "", "h"}, {"a", "n", ""}} {
		if _, err := NewKBJWT(holder, jose.AlgES256, args[0], args[1], now, args[2]); err == nil {
			t.Fatalf("NewKBJWT accepted %q", args)
		}
	}
	if _, err := NewKBJWT(holder, jose.AlgES256, "a", "n", time.Time{}, "h"); err == nil {
		t.Fatal("NewKBJWT accepted a zero iat")
	}
}

func TestVerifyKBJWTRejects(t *testing.T) {
	holder, holderPub := holderSigner(t)
	_, otherPub := newP256Signer(t)
	now := time.Unix(1_800_000_000, 0)
	sign := func(header map[string]any, payload string) string {
		kb, err := jose.Sign(holder, jose.AlgES256, header, []byte(payload))
		mustNoErr(t, err)
		return kb
	}
	kbHeader := map[string]any{"typ": "kb+jwt"}
	claims := func(aud, nonce, sdHash string, iat any) string {
		b, err := jose.EncodeJSON(map[string]any{"aud": json.RawMessage(aud), "nonce": json.RawMessage(nonce), "sd_hash": json.RawMessage(sdHash), "iat": iat})
		mustNoErr(t, err)
		return string(b)
	}
	good := func(iat any) string { return claims(`"aud"`, `"nonce"`, `"hash"`, iat) }
	want := KBWant{Audience: "aud", Nonce: "nonce", SDHash: "hash", Now: now}
	maxPast := now.Add(-DefaultKBMaxAge - DefaultKBClockSkew).Unix()
	maxFuture := now.Add(DefaultKBClockSkew).Unix()

	for _, tc := range []struct {
		name string
		kb   string
		key  *ecdsa.PublicKey // nil: the holder key
		want error            // nil: accepted
	}{
		{"valid", sign(kbHeader, good(now.Unix())), nil, nil},
		{"extra claims ignored", sign(kbHeader, `{"aud":"aud","nonce":"nonce","sd_hash":"hash","iat":1800000000,"x":[1]}`), nil, nil},
		{"fractional iat", sign(kbHeader, good(json.Number("1799999999.5"))), nil, nil},
		{"oldest accepted iat", sign(kbHeader, good(maxPast)), nil, nil},
		{"latest accepted iat", sign(kbHeader, good(maxFuture)), nil, nil},
		{"another key", sign(kbHeader, good(now.Unix())), otherPub, ErrKBInvalid},
		{"typ JWT", sign(map[string]any{"typ": "JWT"}, good(now.Unix())), nil, ErrKBInvalid},
		{"no typ", sign(nil, good(now.Unix())), nil, ErrKBInvalid},
		{"payload not an object", sign(kbHeader, `["aud"]`), nil, ErrKBInvalid},
		{"payload with duplicate keys", sign(kbHeader, `{"aud":"aud","aud":"aud"}`), nil, ErrKBInvalid},
		{"aud array", sign(kbHeader, claims(`["aud"]`, `"nonce"`, `"hash"`, now.Unix())), nil, ErrKBAudience},
		{"aud other", sign(kbHeader, claims(`"aud2"`, `"nonce"`, `"hash"`, now.Unix())), nil, ErrKBAudience},
		{"aud missing", sign(kbHeader, `{"nonce":"nonce","sd_hash":"hash","iat":1800000000}`), nil, ErrKBAudience},
		{"nonce other", sign(kbHeader, claims(`"aud"`, `"nonce2"`, `"hash"`, now.Unix())), nil, ErrKBNonce},
		{"nonce number", sign(kbHeader, claims(`"aud"`, `1`, `"hash"`, now.Unix())), nil, ErrKBNonce},
		{"sd_hash other", sign(kbHeader, claims(`"aud"`, `"nonce"`, `"hash2"`, now.Unix())), nil, ErrKBSDHash},
		{"sd_hash missing", sign(kbHeader, `{"aud":"aud","nonce":"nonce","iat":1800000000}`), nil, ErrKBSDHash},
		{"iat too old", sign(kbHeader, good(maxPast-1)), nil, ErrKBInvalid},
		{"iat in the future", sign(kbHeader, good(maxFuture+1)), nil, ErrKBInvalid},
		{"iat a string", sign(kbHeader, good("1800000000")), nil, ErrKBInvalid},
		{"iat missing", sign(kbHeader, `{"aud":"aud","nonce":"nonce","sd_hash":"hash"}`), nil, ErrKBInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := holderPub
			if tc.key != nil {
				key = tc.key
			}
			err := VerifyKBJWT(tc.kb, key, want)
			if tc.want == nil {
				mustNoErr(t, err)
				return
			}
			wantErr(t, err, tc.want)
		})
	}

	// MaxAge and ClockSkew are configurable.
	old := sign(kbHeader, good(now.Add(-30*time.Minute).Unix()))
	wantErr(t, VerifyKBJWT(old, holderPub, want), ErrKBInvalid)
	w := want
	w.MaxAge = time.Hour
	mustNoErr(t, VerifyKBJWT(old, holderPub, w))
	ahead := sign(kbHeader, good(now.Add(5*time.Minute).Unix()))
	w.ClockSkew = 10 * time.Minute
	mustNoErr(t, VerifyKBJWT(ahead, holderPub, w))

	// Empty expectations are a caller error, never a match, even against a
	// token carrying the same empty value.
	for _, w := range []KBWant{{Nonce: "n", SDHash: "h"}, {Audience: "a", SDHash: "h"}, {Audience: "a", Nonce: "n"}} {
		w.Now = now
		kb := sign(kbHeader, claims(fmt.Sprintf("%q", w.Audience), fmt.Sprintf("%q", w.Nonce), fmt.Sprintf("%q", w.SDHash), now.Unix()))
		if err := VerifyKBJWT(kb, holderPub, w); err == nil {
			t.Fatalf("accepted with %+v", w)
		}
	}
}
