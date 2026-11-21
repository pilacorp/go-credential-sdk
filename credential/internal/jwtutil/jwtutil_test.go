package jwtutil

import (
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestSetIssuedAt(t *testing.T) {
	signedAt := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

	p := map[string]interface{}{"validFrom": "2020-01-01T00:00:00Z", "validUntil": "2030-01-01T00:00:00Z"}
	SetIssuedAt(p, signedAt)

	if p["iat"] != signedAt.Unix() {
		t.Fatalf("iat = %v, want the signing time %v", p["iat"], signedAt.Unix())
	}
	// exp and nbf describe the signature, not the credential. Deriving them
	// from the validity period would state one fact in the other's field, and
	// vc-jose-cose calls nbf on a signature NOT RECOMMENDED outright.
	if _, ok := p["exp"]; ok {
		t.Fatalf("exp written from validUntil: %v", p["exp"])
	}
	if _, ok := p["nbf"]; ok {
		t.Fatalf("nbf written from validFrom: %v", p["nbf"])
	}
}

func TestCheckTimeClaims(t *testing.T) {
	now := time.Now()

	cases := []struct {
		name    string
		payload map[string]interface{}
		leeway  time.Duration
		wantErr string
	}{
		{
			name:    "inside the window",
			payload: map[string]interface{}{"nbf": float64(now.Add(-time.Hour).Unix()), "exp": float64(now.Add(time.Hour).Unix())},
		},
		{
			name:    "no claims at all",
			payload: map[string]interface{}{},
		},
		{
			name:    "expired",
			payload: map[string]interface{}{"exp": float64(now.Add(-time.Second).Unix())},
			wantErr: "signature expired at",
		},
		{
			name:    "not yet valid",
			payload: map[string]interface{}{"nbf": float64(now.Add(time.Hour).Unix())},
			wantErr: "not valid before",
		},
		{
			name:    "exp exactly now is already expired",
			payload: map[string]interface{}{"exp": float64(now.Unix())},
			wantErr: "signature expired at",
		},
		{
			name:    "nbf ahead of the verifier clock, within leeway",
			payload: map[string]interface{}{"nbf": float64(now.Add(5 * time.Second).Unix())},
			leeway:  10 * time.Second,
		},
		{
			name:    "nbf ahead of the verifier clock, beyond leeway",
			payload: map[string]interface{}{"nbf": float64(now.Add(15 * time.Second).Unix())},
			leeway:  10 * time.Second,
			wantErr: "not valid before",
		},
		{
			name:    "exp just passed, within leeway",
			payload: map[string]interface{}{"exp": float64(now.Add(-5 * time.Second).Unix())},
			leeway:  10 * time.Second,
		},
		{
			name:    "exp passed, beyond leeway",
			payload: map[string]interface{}{"exp": float64(now.Add(-15 * time.Second).Unix())},
			leeway:  10 * time.Second,
			wantErr: "signature expired at",
		},
		{
			name:    "exp exactly at the edge of leeway is expired",
			payload: map[string]interface{}{"exp": float64(now.Add(-10 * time.Second).Unix())},
			leeway:  10 * time.Second,
			wantErr: "signature expired at",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckTimeClaims(tc.payload, tc.leeway)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestNormalizeLowS(t *testing.T) {
	for _, alg := range []string{"ES256", "ES256K"} {
		n := curveOrder(alg)
		halfN := new(big.Int).Rsh(n, 1)
		sig := func(s *big.Int) []byte {
			out := make([]byte, 64)
			out[31] = 7 // r
			s.FillBytes(out[32:])
			return out
		}
		sOf := func(b []byte) *big.Int { return new(big.Int).SetBytes(b[32:]) }

		t.Run(alg, func(t *testing.T) {
			// s = n/2 is already low-S and is kept.
			if got := sOf(NormalizeLowS(alg, sig(halfN))); got.Cmp(halfN) != 0 {
				t.Fatalf("s = n/2 changed to %v", got)
			}
			// s = n/2 + 1 becomes n - s, which is n/2 (n is odd).
			high := new(big.Int).Add(halfN, big.NewInt(1))
			in := sig(high)
			out := NormalizeLowS(alg, in)
			if want := new(big.Int).Sub(n, high); sOf(out).Cmp(want) != 0 {
				t.Fatalf("s = n/2+1 normalized to %v, want %v", sOf(out), want)
			}
			if out[31] != 7 {
				t.Fatal("r changed")
			}
			if sOf(in).Cmp(high) != 0 {
				t.Fatal("the input slice was modified")
			}
		})
	}
	// Anything it cannot judge is returned unchanged.
	odd := []byte{1, 2, 3}
	if got := NormalizeLowS("ES256", odd); len(got) != 3 {
		t.Fatalf("non-64-byte input changed: %v", got)
	}
	in := make([]byte, 64)
	in[63] = 0xff
	if got := NormalizeLowS("RS256", in); got[63] != 0xff {
		t.Fatal("unknown alg changed the signature")
	}
}
