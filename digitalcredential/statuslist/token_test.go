package statuslist

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
)

// The non-normative Status List Token of draft-ietf-oauth-status-list-21
// §5.1: header kid "12" and its claims, with the bits=1 list of §4.2 it
// carries, then the same claims with the bits=2 list of §4.2. lst is compared
// by decoding, since Go's zlib does not reproduce the draft's bytes.
func TestSignTokenDraft21Section51Example(t *testing.T) {
	signer, pub := newP256Signer(t)
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
		token, err := SignToken(l, TokenClaims{
			Sub:      "https://example.com/statuslists/1",
			IssuedAt: time.Unix(1686920170, 0),
			Expiry:   time.Unix(2291720170, 0),
			TTL:      43200 * time.Second,
		}, SigningKey{Signer: signer, Public: pub, KID: "12"})
		if err != nil {
			t.Fatalf("bits=%d: SignToken: %v", tt.bits, err)
		}

		header, payload, err := jws.Verify(token, pub, nil)
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

func TestSignTokenRejects(t *testing.T) {
	signer, pub := newP256Signer(t)
	claims := TokenClaims{Sub: "https://example.com/statuslists/1", IssuedAt: time.Unix(1686920170, 0)}
	small, err := New(16, 1)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("signer holds another key", func(t *testing.T) {
		_, other := newP256Signer(t)
		_, err := SignToken(small, claims, SigningKey{Signer: signer, Public: other})
		if !errors.Is(err, jws.ErrSelfCheck) {
			t.Fatalf("SignToken = %v, want jws.ErrSelfCheck", err)
		}
	})

	// A 1 MiB kid passes the payload check and makes the signed token too
	// long, so this reaches the exact check made after signing.
	t.Run("token over 1 MiB", func(t *testing.T) {
		_, err := SignToken(small, claims, SigningKey{Signer: signer, Public: pub, KID: strings.Repeat("k", 1<<20)})
		if !errors.Is(err, jose.ErrInvalidArgument) {
			t.Fatalf("SignToken = %v, want jose.ErrInvalidArgument", err)
		}
	})
}

// RFC 7519 §2: a sub holding ":" MUST be a URI (RFC 3986 §3). url.Parse
// accepts each of these https URLs, so only the URI check refuses them.
func TestSignTokenSubURI(t *testing.T) {
	signer, pub := newP256Signer(t)
	key := SigningKey{Signer: signer, Public: pub}
	l, err := New(16, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{
		"https://example.com/a b",    // space is not a pchar (§3.3)
		"https://example.com/a[b]",   // brackets only around an IP-literal (§3.2.2)
		"https://example.com/?x=[1]", // nor in a query (§3.4)
		"https://ü.example/x",        // not ASCII (§2)
		"https://example.com/?x=%zz", // pct-encoded is "%" HEXDIG HEXDIG (§2.1)
	} {
		_, err := SignToken(l, TokenClaims{Sub: sub, IssuedAt: time.Unix(1686920170, 0)}, key)
		if !errors.Is(err, jose.ErrInvalidArgument) {
			t.Errorf("SignToken(sub %q) = %v, want jose.ErrInvalidArgument", sub, err)
		}
	}
	if _, err := SignToken(l, TokenClaims{Sub: "https://[2001:db8::1]/x", IssuedAt: time.Unix(1686920170, 0)}, key); err != nil {
		t.Errorf("SignToken(IP-literal sub) = %v", err)
	}
}

// p256Signer signs in memory and returns r||s, as jws.Signer requires.
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
