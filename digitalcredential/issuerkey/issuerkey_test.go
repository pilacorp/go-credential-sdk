package issuerkey

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
)

// The selection rule of REQ-34 (stricter than RFC 7517 §4.5 and
// draft-ietf-oauth-sd-jwt-vc-19 §4): a header kid that is a non-empty string
// names exactly one key; no kid needs exactly one key; anything else selects
// nothing, so a token never makes the verifier try keys in turn.
func TestSelect(t *testing.T) {
	a, b, d1, d2 := newKey(t), newKey(t), newKey(t), newKey(t)
	two := []PublicKey{{KID: "a", Public: a}, {KID: "b", Public: b}}
	tests := []struct {
		name   string
		keys   []PublicKey
		header jws.Header
		want   crypto.PublicKey // nil: no key
	}{
		{"kid names one of two", two, jws.Header{"kid": "b"}, b},
		{"no kid, one key", []PublicKey{{KID: "a", Public: a}}, jws.Header{}, a},
		{"kid names none", two, jws.Header{"kid": "c"}, nil},
		{"no kid, two keys", two, jws.Header{}, nil},
		{"no kid, empty set", nil, jws.Header{}, nil},
		{"kid not a string", []PublicKey{{KID: "a", Public: a}}, jws.Header{"kid": json.Number("7")}, nil},
		{"kid empty", []PublicKey{{KID: "", Public: a}}, jws.Header{"kid": ""}, nil},
		{"kid on two keys", []PublicKey{{KID: "d", Public: d1}, {KID: "d", Public: d2}}, jws.Header{"kid": "d"}, nil},
		{"selected key nil", []PublicKey{{KID: "a"}}, jws.Header{"kid": "a"}, nil},
		{"selected key typed nil", []PublicKey{{KID: "a", Public: (*ecdsa.PublicKey)(nil)}}, jws.Header{"kid": "a"}, nil},
	}
	for _, tt := range tests {
		got, err := Select(tt.keys, tt.header)
		if tt.want == nil {
			if err == nil || got != nil {
				t.Errorf("%s: Select = %v, %v; want no key and an error", tt.name, got, err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("%s: Select = %v, %v; want the named key", tt.name, got, err)
		}
	}
}

type prefixResolver struct {
	prefix string
	keys   []PublicKey
	err    error
	calls  *int
}

func (r prefixResolver) Keys(_ context.Context, iss string) ([]PublicKey, error) {
	if r.calls != nil {
		*r.calls++
	}
	if !strings.HasPrefix(iss, r.prefix) {
		return nil, ErrIssuerNotSupported
	}
	return r.keys, r.err
}

// TC-40 (REQ-56): Multi asks in order, passes on only ErrIssuerNotSupported,
// and a failed fetch never moves the issuer to another key source.
func TestMulti(t *testing.T) {
	ctx := context.Background()
	ka := []PublicKey{{KID: "a", Public: newKey(t)}}
	kb := []PublicKey{{KID: "b", Public: newKey(t)}}
	a := prefixResolver{prefix: "did:", keys: ka}
	var bCalls int
	b := prefixResolver{prefix: "https://", keys: kb, calls: &bCalls}
	m, err := Multi(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := m.Keys(ctx, "did:x"); err != nil || len(got) != 1 || got[0].KID != "a" {
		t.Errorf("did:x = %v, %v; want the keys of a", got, err)
	}
	if got, err := m.Keys(ctx, "https://x"); err != nil || len(got) != 1 || got[0].KID != "b" {
		t.Errorf("https://x = %v, %v; want the keys of b", got, err)
	}
	if _, err := m.Keys(ctx, "ftp://x"); !errors.Is(err, ErrIssuerNotSupported) {
		t.Errorf("ftp://x: err = %v; want ErrIssuerNotSupported", err)
	}

	fetch := errors.New("fetch failed")
	c := prefixResolver{prefix: "https://", err: fetch}
	m, err = Multi(c, b)
	if err != nil {
		t.Fatal(err)
	}
	bCalls = 0
	if _, err := m.Keys(ctx, "https://x"); !errors.Is(err, fetch) || bCalls != 0 {
		t.Errorf("Multi(c, b): err = %v, b called %d times; want the fetch error of c and b not called", err, bCalls)
	}

	m, err = Multi(a, b)
	if err != nil {
		t.Fatal(err)
	}
	done, cancel := context.WithCancel(ctx)
	cancel()
	bCalls = 0
	if _, err := m.Keys(done, "https://x"); !errors.Is(err, context.Canceled) || bCalls != 0 {
		t.Errorf("ended ctx: err = %v, b called %d times; want context.Canceled and b not called", err, bCalls)
	}
	var nilCtx context.Context
	if _, err := m.Keys(nilCtx, "https://x"); !errors.Is(err, jose.ErrInvalidArgument) {
		t.Errorf("nil ctx: err = %v; want jose.ErrInvalidArgument", err)
	}

	if _, err := Multi(); !errors.Is(err, jose.ErrInvalidArgument) {
		t.Errorf("Multi(): err = %v; want jose.ErrInvalidArgument", err)
	}
	if _, err := Multi(a, nil); !errors.Is(err, jose.ErrInvalidArgument) {
		t.Errorf("Multi(a, nil): err = %v; want jose.ErrInvalidArgument", err)
	}
}

func newKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &priv.PublicKey
}
