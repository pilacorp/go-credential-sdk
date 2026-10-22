package statuslist

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/jose"
)

var t0 = time.Unix(1_760_000_000, 0)

func TestSignTokenShape(t *testing.T) {
	signer, pub := newP256(t)
	l := mustList(t, 1000, 2, map[int]byte{0: 1, 917: 2, 999: 3})
	tok, err := SignToken(l, TokenClaims{
		Sub:      "https://issuer.example/statuslists/7",
		IssuedAt: t0.Add(400 * time.Millisecond),
		Expiry:   t0.Add(time.Hour),
		TTL:      12 * time.Hour,
	}, SigningKey{Signer: signer, KID: "did:nda:testnet:0xabc#key-2"})
	if err != nil {
		t.Fatal(err)
	}
	h, payload, err := jose.Verify(tok, pub, []string{jose.AlgES256})
	if err != nil {
		t.Fatalf("token does not verify: %v", err)
	}
	if len(h) != 3 || h.Alg() != "ES256" || h.Typ() != "statuslist+jwt" || h.Kid() != "did:nda:testnet:0xabc#key-2" {
		t.Errorf("header %v, want exactly alg ES256 (the default), typ statuslist+jwt, kid", h)
	}
	lst, _ := l.Encode()
	want := `{"exp":1760003600,"iat":1760000000,"status_list":{"bits":2,"lst":"` + lst +
		`"},"sub":"https://issuer.example/statuslists/7","ttl":43200}`
	if string(payload) != want {
		t.Errorf("payload\n%s\nwant\n%s", payload, want)
	}

	// Same bytes on both sides: what the issuer anchors on chain is
	// List.Bytes(), and it equals the inflated lst of the token.
	anchored := l.Bytes()
	var claims struct {
		StatusList struct {
			Bits int
			Lst  string
		} `json:"status_list"`
	}
	_ = json.Unmarshal(payload, &claims)
	fromToken, err := Decode(claims.StatusList.Lst, claims.StatusList.Bits)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fromToken.Bytes(), anchored) {
		t.Errorf("inflated lst %x differs from List.Bytes() %x", fromToken.Bytes(), anchored)
	}
	fromChain, _ := FromBytes(anchored, 2)
	for _, i := range []int{0, 917, 999, 500} {
		a, _ := fromChain.Get(i)
		b, _ := fromToken.Get(i)
		if a != b {
			t.Errorf("entry %d: chain %d, token %d", i, a, b)
		}
	}
}

func TestSignTokenOptionalClaims(t *testing.T) {
	signer, pub := newP256(t)
	tok, err := SignToken(mustList(t, 8, 1, nil), TokenClaims{Sub: "https://x.example/l", IssuedAt: t0},
		SigningKey{Signer: signer, KID: "k", Public: pub})
	if err != nil {
		t.Fatal(err)
	}
	_, payload, _ := jose.Verify(tok, pub, nil)
	if strings.Contains(string(payload), `"exp"`) || strings.Contains(string(payload), `"ttl"`) {
		t.Errorf("payload %s carries exp or ttl that were not set", payload)
	}
}

func TestSignTokenES256KVault(t *testing.T) {
	signer, pub := newSecpVault(t)
	tok, err := SignToken(mustList(t, 8, 1, nil), TokenClaims{Sub: "https://x.example/l", IssuedAt: t0},
		SigningKey{Signer: signer, Alg: jose.AlgES256K, KID: "k", Public: pub})
	if err != nil {
		t.Fatal(err)
	}
	if h, _, err := jose.Verify(tok, pub, nil); err != nil || h.Alg() != "ES256K" {
		t.Fatalf("ES256K token: %v %v", h, err)
	}
}

func TestSignTokenSelfCheck(t *testing.T) {
	signer, _ := newP256(t)
	_, otherPub := newP256(t)
	_, err := SignToken(mustList(t, 8, 1, nil), TokenClaims{Sub: "https://x.example/l", IssuedAt: t0},
		SigningKey{Signer: signer, KID: "k", Public: otherPub})
	wantErr(t, err, ErrSelfCheck)
}

func TestSignTokenRules(t *testing.T) {
	signer, _ := newP256(t)
	key := SigningKey{Signer: signer, KID: "k"}
	ok := TokenClaims{Sub: "https://x.example/l", IssuedAt: t0}
	l := mustList(t, 8, 1, nil)
	for _, tc := range []struct {
		name string
		l    *List
		c    func(*TokenClaims)
		k    func(*SigningKey)
	}{
		{"nil list", nil, nil, nil},
		{"zero list", &List{}, nil, nil},
		{"no sub", l, func(c *TokenClaims) { c.Sub = "" }, nil},
		{"http sub", l, func(c *TokenClaims) { c.Sub = "http://x.example/l" }, nil},
		{"sub without host", l, func(c *TokenClaims) { c.Sub = "https:///l" }, nil},
		{"sub with userinfo", l, func(c *TokenClaims) { c.Sub = "https://u@x.example/l" }, nil},
		{"no iat", l, func(c *TokenClaims) { c.IssuedAt = time.Time{} }, nil},
		{"exp equal to iat", l, func(c *TokenClaims) { c.Expiry = t0 }, nil},
		{"exp before iat", l, func(c *TokenClaims) { c.Expiry = t0.Add(-time.Second) }, nil},
		{"negative ttl", l, func(c *TokenClaims) { c.TTL = -time.Second }, nil},
		{"sub-second ttl", l, func(c *TokenClaims) { c.TTL = time.Millisecond }, nil},
		{"fractional ttl", l, func(c *TokenClaims) { c.TTL = 1500 * time.Millisecond }, nil},
		{"nil signer", l, nil, func(k *SigningKey) { k.Signer = nil }},
		{"no kid", l, nil, func(k *SigningKey) { k.KID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, k := ok, key
			if tc.c != nil {
				tc.c(&c)
			}
			if tc.k != nil {
				tc.k(&k)
			}
			tok, err := SignToken(tc.l, c, k)
			if tok != "" {
				t.Fatal("a token was returned with the error")
			}
			wantErr(t, err, ErrInvalidArgument)
		})
	}
	if _, err := SignToken(l, ok, SigningKey{Signer: signer, KID: "k", Alg: "HS256"}); err == nil {
		t.Error("alg HS256 was accepted")
	} else {
		wantErr(t, err, jose.ErrAlgNotAllowed)
	}
}
