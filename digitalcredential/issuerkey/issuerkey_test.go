package issuerkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/pilacorp/go-credential-sdk/jose/jws"
)

// The selection rule of go-credential-sdk#108 (stricter than RFC 7517 §4.5
// and draft-ietf-oauth-sd-jwt-vc-19 §4.2): a header kid that is a non-empty
// string names exactly one key; no kid needs exactly one key; anything else
// selects nothing, so a token never makes the verifier try keys in turn.
func TestSelect(t *testing.T) {
	a, b, d1, d2 := newKey(t), newKey(t), newKey(t), newKey(t)
	two := []Key{{KID: "a", Key: a}, {KID: "b", Key: b}}
	tests := []struct {
		name   string
		keys   []Key
		header jws.Header
		want   *ecdsa.PublicKey // nil: no key
	}{
		{"kid names one of two", two, jws.Header{"kid": "b"}, b},
		{"no kid, one key", []Key{{KID: "a", Key: a}}, jws.Header{}, a},
		{"kid names none", two, jws.Header{"kid": "c"}, nil},
		{"no kid, two keys", two, jws.Header{}, nil},
		{"no kid, empty set", nil, jws.Header{}, nil},
		// Header.Kid reads both as "": they must not pass as "no kid".
		{"kid not a string", []Key{{KID: "a", Key: a}}, jws.Header{"kid": json.Number("7")}, nil},
		{"kid empty", []Key{{KID: "", Key: a}}, jws.Header{"kid": ""}, nil},
		{"kid on two keys", []Key{{KID: "d", Key: d1}, {KID: "d", Key: d2}}, jws.Header{"kid": "d"}, nil},
		{"selected key nil", []Key{{KID: "a"}}, jws.Header{"kid": "a"}, nil},
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

func newKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &priv.PublicKey
}
