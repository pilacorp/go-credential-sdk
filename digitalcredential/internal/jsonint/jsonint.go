// Package jsonint reads a JSON number as an exact non-negative integer: the
// Integer of draft-ietf-oauth-status-list-21 §6.2 (idx) and §4.2 (bits).
// The draft fixes a value, not a form, so every number RFC 8259 §6 writes
// for it counts: 7, 7.0, 7e0, 70e-1 and, for 0, -0.
package jsonint

import (
	"errors"
	"math"
)

var (
	// ErrNotInteger: not a JSON number, or one whose value is negative or
	// has a fraction.
	ErrNotInteger = errors.New("not a non-negative integer")
	// ErrTooLarge: a non-negative integer larger than an int holds.
	ErrTooLarge = errors.New("integer too large")
)

// maxExp bounds the exponent read, so a long exponent cannot overflow; any
// value it stands for has more digits than an int.
const maxExp = 1 << 40

// NonNegative returns the value of the JSON number n when it is a
// non-negative integer. It reads n once, never through a float64 or a big
// number, so a long n costs no more than its length.
func NonNegative(n string) (int, error) {
	s, neg := n, false
	if len(s) > 0 && s[0] == '-' {
		s, neg = s[1:], true
	}
	// RFC 8259 §6: int = zero / ( digit1-9 *DIGIT ); frac = "." 1*DIGIT;
	// exp = ( "e" / "E" ) [ "-" / "+" ] 1*DIGIT.
	i := digits(s, 0)
	if i == 0 || (s[0] == '0' && i > 1) {
		return 0, ErrNotInteger
	}
	whole, frac := s[:i], ""
	if i < len(s) && s[i] == '.' {
		j := digits(s, i+1)
		if j == i+1 {
			return 0, ErrNotInteger
		}
		frac, i = s[i+1:j], j
	}
	var exp int64
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		i++
		expNeg := i < len(s) && s[i] == '-'
		if i < len(s) && (s[i] == '-' || s[i] == '+') {
			i++
		}
		j := digits(s, i)
		if j == i {
			return 0, ErrNotInteger
		}
		for _, c := range s[i:j] {
			if exp < maxExp {
				exp = exp*10 + int64(c-'0')
			}
		}
		if expNeg {
			exp = -exp
		}
		i = j
	}
	if i != len(s) {
		return 0, ErrNotInteger
	}
	// The value is the digits of whole and frac, read as one integer, times
	// 10^(exp-len(frac)). Zeros at its ends do not change it: leading ones
	// are dropped, trailing ones move into the exponent.
	all := len(whole) + len(frac)
	at := func(k int) byte {
		if k < len(whole) {
			return whole[k]
		}
		return frac[k-len(whole)]
	}
	lo, hi := 0, all
	for lo < hi && at(lo) == '0' {
		lo++
	}
	if lo == hi {
		return 0, nil // 0, -0, 0.0e9: zero whatever its sign and exponent
	}
	for at(hi-1) == '0' {
		hi--
	}
	if neg {
		return 0, ErrNotInteger
	}
	shift := exp - int64(len(frac)) + int64(all-hi)
	if shift < 0 {
		return 0, ErrNotInteger // the last digit that is not 0 is after the point
	}
	// math.MaxInt64 has 19 digits, so a value of more never fits, and one of
	// at most 19 is computed without overflow in a uint64.
	if int64(hi-lo)+shift > 19 {
		return 0, ErrTooLarge
	}
	var v uint64
	for k := lo; k < hi; k++ {
		v = v*10 + uint64(at(k)-'0')
	}
	for ; shift > 0; shift-- {
		v *= 10
	}
	if v > math.MaxInt {
		return 0, ErrTooLarge
	}
	return int(v), nil
}

// digits returns the index of the first byte at or after i of s that is not
// a decimal digit.
func digits(s string, i int) int {
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return i
}
