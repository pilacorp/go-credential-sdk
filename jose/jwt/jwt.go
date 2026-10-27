// Package jwt reads JSON Web Token claim values under the rules of RFC 7519:
// NumericDate (§2), the type of exp, nbf and iat (§4.1.4 to §4.1.6), and
// checks exp and nbf against a time (§4.1.4, §4.1.5).
package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// maxUnix is the last second time.Time holds: time.Unix adds the seconds from
// year 1 to 1970 to its argument, and a larger value wraps around to a date
// in the past (an nbf in the far future would read as long gone).
const maxUnix = math.MaxInt64 - 62135596800

// NumericDate converts a claim value, as jose.DecodeJSON yields it
// (json.Number), to a time. RFC 7519 §2: a JSON number of seconds since
// 1970-01-01T00:00:00Z UTC; non-integer values can be represented. The value
// is read as a float64, so a fraction is kept to that precision. float64, int
// and int64 are accepted too. Anything else, NaN, ±Inf, or a value time.Time
// cannot hold is jose.ErrMalformed.
func NumericDate(v any) (time.Time, error) {
	switch n := v.(type) {
	case json.Number:
		f, err := strconv.ParseFloat(string(n), 64)
		if err != nil {
			// The cause only: a *strconv.NumError quotes the whole literal,
			// which a received token makes as long as it likes.
			var ne *strconv.NumError
			if errors.As(err, &ne) {
				err = ne.Err
			}
			return time.Time{}, fmt.Errorf("%w: NumericDate: %v", jose.ErrMalformed, err)
		}
		return fromFloat(f)
	case float64:
		return fromFloat(n)
	case int:
		return fromFloat(float64(n))
	case int64:
		return fromFloat(float64(n))
	}
	return time.Time{}, fmt.Errorf("%w: NumericDate is %T, not a number", jose.ErrMalformed, v)
}

// DateClaim reads the NumericDate claim name from claims, as
// jose.DecodeJSONObject yields them; ok is false when it is absent. A present
// value that NumericDate refuses is jose.ErrMalformed.
func DateClaim(claims map[string]any, name string) (t time.Time, ok bool, err error) {
	v, ok := claims[name]
	if !ok {
		return time.Time{}, false, nil
	}
	t, err = NumericDate(v)
	if err != nil {
		return time.Time{}, true, fmt.Errorf("%s: %w", name, err)
	}
	return t, true, nil
}

// CheckExpNbf checks the exp and nbf claims, when present, against now with
// a leeway of skew. exp refuses when now ≥ exp + skew (RFC 7519 §4.1.4: "on
// or after"), nbf when now < nbf − skew (§4.1.5: "after or equal"). A
// negative skew is jose.ErrInvalidArgument, a malformed value
// jose.ErrMalformed; a failing one is an error with no sentinel, which
// callers wrap in their own.
func CheckExpNbf(claims map[string]any, now time.Time, skew time.Duration) error {
	// Negating math.MinInt64 overflows to itself, which would move the exp
	// edge into the distant past and accept an expired token.
	if skew < 0 {
		return fmt.Errorf("%w: jwt: negative skew", jose.ErrInvalidArgument)
	}
	// Shifting now, not the claim, keeps a far-off date from overflowing.
	exp, ok, err := DateClaim(claims, "exp")
	if err != nil {
		return err
	}
	if ok && !now.Add(-skew).Before(exp) {
		return fmt.Errorf("jwt: expired at %s", exp)
	}
	nbf, ok, err := DateClaim(claims, "nbf")
	if err != nil {
		return err
	}
	if ok && now.Add(skew).Before(nbf) {
		return fmt.Errorf("jwt: not valid before %s", nbf)
	}
	return nil
}

func fromFloat(f float64) (time.Time, error) {
	// Converting a float64 outside int64 to int64 is implementation-defined in
	// Go, so the range is checked first. float64(maxUnix) is not exact; the
	// strict < keeps the floor of f at or below maxUnix either way.
	if math.IsNaN(f) || f < math.MinInt64 || f >= float64(maxUnix) {
		return time.Time{}, fmt.Errorf("%w: NumericDate %v is out of range", jose.ErrMalformed, f)
	}
	sec := math.Floor(f)
	nsec := math.Round((f - sec) * 1e9) // time.Unix carries 1e9 into sec
	return time.Unix(int64(sec), int64(nsec)).UTC(), nil
}
