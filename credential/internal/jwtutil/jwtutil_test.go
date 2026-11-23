package jwtutil

import (
	"encoding/json"
	"math"
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

// An nbf too far ahead for time.Time is refused, not wrapped into the past
// and accepted (RFC 7519 §4.1.5).
func TestCheckTimeClaimsRefusesFarFutureNbf(t *testing.T) {
	for _, nbf := range []interface{}{json.Number("9223371974719179008"), 9223372000000000000.0} {
		if err := CheckTimeClaims(map[string]interface{}{"nbf": nbf}, 0); err == nil {
			t.Fatalf("CheckTimeClaims accepted nbf %v", nbf)
		}
	}
}

// A NumericDate gives the same seconds, or the same refusal, on every CPU and
// for every decoded form. A fraction is allowed (RFC 7519 §2) and dropped.
func TestNumericClaim(t *testing.T) {
	cases := []struct {
		name    string
		value   interface{}
		want    int64
		wantErr bool
	}{
		{name: "float64", value: float64(1700000000), want: 1700000000},
		{name: "float64 with a fraction", value: 1700000000.5, want: 1700000000},
		{name: "json.Number with a fraction", value: json.Number("1700000000.5"), want: 1700000000},
		{name: "json.Number above 2^53", value: json.Number("9007199254740993"), want: 9007199254740993},
		{name: "int64 at the last second time.Time holds", value: int64(9223371974719179007), want: 9223371974719179007},
		{name: "int64 past the last second time.Time holds", value: int64(9223371974719179008), wantErr: true},
		{name: "json.Number past the last second time.Time holds", value: json.Number("9223371974719179008"), wantErr: true},
		{name: "float64 below the last second time.Time holds", value: 9.2e18, want: 9200000000000000000},
		{name: "float64 past the last second time.Time holds", value: 9223372000000000000.0, wantErr: true},
		{name: "float64 of 2^63", value: 9223372036854775808.0, wantErr: true},
		{name: "float64 above int64", value: 1e19, wantErr: true},
		{name: "json.Number above int64", value: json.Number("1e19"), wantErr: true},
		{name: "json.Number of 2^63", value: json.Number("9223372036854775808"), wantErr: true},
		{name: "NaN", value: math.NaN(), wantErr: true},
		{name: "+Inf", value: math.Inf(1), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok, err := NumericClaim(map[string]interface{}{"exp": tc.value}, "exp")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NumericClaim(%v) = %d, %v, want an error", tc.value, got, ok)
				}
				return
			}
			if err != nil || !ok || got != tc.want {
				t.Fatalf("NumericClaim(%v) = %d, %v, %v, want %d", tc.value, got, ok, err, tc.want)
			}
		})
	}
}
