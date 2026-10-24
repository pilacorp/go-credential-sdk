package jwt

import (
	"encoding/json"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/jose"
)

func TestNumericDate(t *testing.T) {
	// 1700000000 s after the epoch is 2023-11-14T22:13:20Z (19675 days and
	// 80000 s). 9223371974719179008 is one past math.MaxInt64 minus the
	// 62135596800 s from 0001-01-01 to 1970-01-01, where time.Time overflows.
	at := time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC)
	for _, tc := range []struct {
		name string
		v    any
		want time.Time // zero: ErrMalformed expected
	}{
		{"json.Number fraction", json.Number("1700000000.25"), at.Add(250 * time.Millisecond)},
		{"float64", 1700000000.5, at.Add(500 * time.Millisecond)},
		{"int", 1700000000, at},
		{"int64", int64(1700000000), at},
		{"string", "1700000000", time.Time{}},
		{"json.Number not a number", json.Number("1700000000x"), time.Time{}},
		{"NaN", math.NaN(), time.Time{}},
		{"below int64", -1e19, time.Time{}},
		{"past time.Time", json.Number("9223371974719179008"), time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NumericDate(tc.v)
			if tc.want.IsZero() {
				if !errors.Is(err, jose.ErrMalformed) {
					t.Fatalf("got %v, %v; want ErrMalformed", got, err)
				}
				return
			}
			if err != nil || !got.Equal(tc.want) {
				t.Fatalf("got %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

// RFC 7519 §4.1.4 refuses on or after exp, §4.1.5 before nbf; with a skew of
// 60 s the edges are now = exp + 60 (refused) and now = nbf − 60 (accepted).
func TestCheckExpNbf(t *testing.T) {
	now := time.Unix(1748537244, 0)
	for _, tc := range []struct {
		name   string
		claims map[string]any
		ok     bool
		skew   time.Duration // zero: one minute
		err    error         // checked with errors.Is when not nil
	}{
		{name: "neither", claims: map[string]any{}, ok: true},
		{name: "exp one second before the edge", claims: map[string]any{"exp": json.Number("1748537185")}, ok: true},
		{name: "exp at the edge", claims: map[string]any{"exp": json.Number("1748537184")}},
		{name: "nbf at the edge", claims: map[string]any{"nbf": json.Number("1748537304")}, ok: true},
		{name: "nbf one second past the edge", claims: map[string]any{"nbf": json.Number("1748537305")}},
		{name: "exp not a number", claims: map[string]any{"exp": "1748537304"}, err: jose.ErrMalformed},
		// A negative skew is a caller mistake; MinInt64 would overflow when
		// negated and let an expired token pass.
		{name: "negative skew", claims: map[string]any{"exp": json.Number("1748537184")}, skew: math.MinInt64, err: jose.ErrInvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			skew := time.Minute
			if tc.skew != 0 {
				skew = tc.skew
			}
			err := CheckExpNbf(tc.claims, now, skew)
			switch {
			case tc.ok && err != nil, !tc.ok && err == nil:
				t.Fatalf("got %v, want ok=%v", err, tc.ok)
			case tc.err != nil && !errors.Is(err, tc.err):
				t.Fatalf("got %v, want %v", err, tc.err)
			}
		})
	}
}
