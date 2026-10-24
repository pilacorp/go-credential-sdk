// Package jwt reads JSON Web Token claim values under the rules of RFC 7519:
// NumericDate (§2), the type of exp, nbf and iat (§4.1.4 to §4.1.6).
package jwt

import (
	"encoding/json"
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
