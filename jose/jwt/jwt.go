// Package jwt reads JSON Web Token claim values under the rules of RFC 7519:
// NumericDate (§2), the type of exp, nbf and iat (§4.1.4 to §4.1.6), and
// checks exp and nbf against a time (§4.1.4, §4.1.5) and aud against an
// audience (§4.1.3).
//
// The functions that take claims read them as jose.DecodeJSONObject yields
// them from a received token: string, json.Number, bool, nil, []any and
// map[string]any (RFC 7519 §2 defines a Claim Value as any JSON value).
// Other Go types are not converted (NumericDate also takes float64, int and
// int64), so a map built in Go may hold values these functions refuse as
// malformed.
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

// CheckExpNbf and CheckAud wrap one of these when a claim fails, so a caller
// maps the failure with errors.Is. No standard defines them.
var (
	// ErrExpired: now is on or after exp plus the skew (RFC 7519 §4.1.4).
	ErrExpired = errors.New("jwt: expired")
	// ErrNotYetValid: now is before nbf minus the skew (RFC 7519 §4.1.5).
	ErrNotYetValid = errors.New("jwt: not yet valid")
	// ErrAudience: aud is present and does not list the audience, or the
	// caller named none (RFC 7519 §4.1.3).
	ErrAudience = errors.New("jwt: aud does not list this audience")
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
// jose.ErrMalformed, an expired token ErrExpired and one not yet valid
// ErrNotYetValid. exp is checked before nbf is read.
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
		return fmt.Errorf("%w at %s", ErrExpired, exp)
	}
	nbf, ok, err := DateClaim(claims, "nbf")
	if err != nil {
		return err
	}
	if ok && now.Add(skew).Before(nbf) {
		return fmt.Errorf("%w: valid from %s", ErrNotYetValid, nbf)
	}
	return nil
}

// CheckAud checks the aud claim, when present, as RFC 7519 §4.1.3 says: a
// recipient that does not identify itself with a value in aud MUST reject
// the JWT. aud is a string or an array of strings, compared with audience
// byte for byte (§2, StringOrURI); every element's type is checked before any
// is compared. Absent aud is nil. Present aud is ErrAudience when audience is
// "" or not listed, an empty array included, and jose.ErrMalformed when it is
// neither a string nor an array of strings. An array is []any, as decoded:
// a Go []string, or a named string type, is jose.ErrMalformed. No aud value
// is echoed.
func CheckAud(claims map[string]any, audience string) error {
	v, ok := claims["aud"]
	if !ok {
		return nil
	}
	var list []any
	switch a := v.(type) {
	case string:
		list = []any{a}
	case []any:
		list = a
	default:
		return fmt.Errorf("%w: aud is %T, not a string or an array of strings", jose.ErrMalformed, v)
	}
	for _, el := range list {
		if _, ok := el.(string); !ok {
			return fmt.Errorf("%w: aud holds a %T, not a string", jose.ErrMalformed, el)
		}
	}
	if audience == "" {
		return fmt.Errorf("%w: aud is present and no audience was given to compare it with", ErrAudience)
	}
	for _, el := range list {
		if el == audience {
			return nil
		}
	}
	return ErrAudience
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
