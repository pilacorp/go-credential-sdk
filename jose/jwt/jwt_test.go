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
