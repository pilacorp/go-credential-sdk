package statuslist

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuerkey"
	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
)

// The non-normative Status List Token of draft-ietf-oauth-status-list-21
// §5.1: header kid "12" and its claims, with the bits=1 list of §4.2 it
// carries, then the same claims with the bits=2 list of §4.2. lst is compared
// by decoding, since Go's zlib does not reproduce the draft's bytes.
func TestIssueTokenDraft21Section51Example(t *testing.T) {
	key := newSigningKey(t, "12")
	lists := []struct {
		bits  int
		bytes []byte
	}{
		{1, []byte{0xb9, 0xa3}},
		{2, []byte{0xc9, 0x44, 0xf9}},
	}
	for _, tt := range lists {
		l, err := FromBytes(tt.bytes, tt.bits)
		if err != nil {
			t.Fatal(err)
		}
		token, err := l.IssueToken(t.Context(), TokenClaims{
			Sub:      "https://example.com/statuslists/1",
			IssuedAt: time.Unix(1686920170, 0),
			Expiry:   time.Unix(2291720170, 0),
			TTL:      43200 * time.Second,
		}, key)
		if err != nil {
			t.Fatalf("bits=%d: IssueToken: %v", tt.bits, err)
		}

		header, payload, err := jws.Verify(token, key.Public, nil)
		if err != nil {
			t.Fatalf("bits=%d: Verify: %v", tt.bits, err)
		}
		if len(header) != 3 || header.Alg() != "ES256" || header.Typ() != "statuslist+jwt" || header.Kid() != "12" {
			t.Errorf("bits=%d: header = %v, want alg ES256, kid 12, typ statuslist+jwt", tt.bits, header)
		}
		claims, err := jose.DecodeJSONObject(payload)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]any{
			"sub": "https://example.com/statuslists/1",
			"iat": json.Number("1686920170"),
			"exp": json.Number("2291720170"),
			"ttl": json.Number("43200"),
		}
		if len(claims) != len(want)+1 {
			t.Errorf("bits=%d: claims = %v, want sub, iat, exp, ttl and status_list", tt.bits, claims)
		}
		for name, v := range want {
			if claims[name] != v {
				t.Errorf("bits=%d: %s = %#v, want %#v", tt.bits, name, claims[name], v)
			}
		}
		sl, _ := claims["status_list"].(map[string]any)
		lst, _ := sl["lst"].(string)
		if len(sl) != 2 || sl["bits"] != json.Number(strconv.Itoa(tt.bits)) {
			t.Fatalf("bits=%d: status_list = %v, want bits and lst", tt.bits, sl)
		}
		back, err := Decode(lst, tt.bits)
		if err != nil {
			t.Fatalf("bits=%d: Decode(lst): %v", tt.bits, err)
		}
		if got := back.Bytes(); !bytes.Equal(got, tt.bytes) {
			t.Fatalf("bits=%d: lst decodes to %x, want %x", tt.bits, got, tt.bytes)
		}
	}
}

// TC-29: Other carries the claims §5.1 lets the token hold, and never one of
// those IssueToken writes itself.
func TestIssueTokenOther(t *testing.T) {
	key := newSigningKey(t, "")
	l, err := New(16, 1)
	if err != nil {
		t.Fatal(err)
	}
	claims := TokenClaims{Sub: "https://example.com/statuslists/1", IssuedAt: time.Unix(1686920170, 0)}

	c := claims
	c.Other = map[string]any{"iss": "https://example.com"}
	token, err := l.IssueToken(t.Context(), c, key)
	if err != nil {
		t.Fatal(err)
	}
	_, payload, err := jws.Verify(token, key.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := jose.DecodeJSONObject(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got["iss"] != "https://example.com" {
		t.Errorf("iss = %v, want the value of Other", got["iss"])
	}

	for name, other := range map[string]map[string]any{
		"ttl in Other":           {"ttl": 60},
		"status_list in Other":   {"status_list": map[string]any{"bits": 1, "lst": "eNoDAAAAAAE"}},
		"nbf as time.Time":       {"nbf": time.Unix(1686920170, 0)},
		"value JSON cannot hold": {"x": func() {}},
	} {
		c := claims
		c.Other = other
		if _, err := l.IssueToken(t.Context(), c, key); !errors.Is(err, jose.ErrInvalidArgument) {
			t.Errorf("%s: %v, want jose.ErrInvalidArgument", name, err)
		}
	}
}

// A token is verified with key.Public before it is returned, so a signer
// holding another key never yields a token.
func TestIssueTokenSelfCheck(t *testing.T) {
	key := newSigningKey(t, "")
	key.Public = newSigningKey(t, "").Public
	l, err := New(16, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = l.IssueToken(t.Context(), TokenClaims{Sub: "https://example.com/statuslists/1", IssuedAt: time.Unix(1686920170, 0)}, key)
	if !errors.Is(err, jws.ErrSelfCheck) {
		t.Fatalf("IssueToken = %v, want jws.ErrSelfCheck", err)
	}
}

// newSigningKey returns a fresh P-256 issuer key.
func newSigningKey(t *testing.T, kid string) issuerkey.SigningKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jws.PrivateKeySigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return issuerkey.SigningKey{Signer: signer, Public: &priv.PublicKey, KID: kid}
}
