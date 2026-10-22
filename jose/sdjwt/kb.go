// Ported from sd-jwt-python (Apache-2.0), src/sd_jwt/common.py
// (_calculate_kb_hash), src/sd_jwt/holder.py (_create_key_binding_jwt) and
// src/sd_jwt/verifier.py (_verify_key_binding_jwt), and eudi-lib-jvm-sdjwt-kt
// (Apache-2.0), src/main/kotlin/eu/europa/ec/eudi/sdjwt/SdJwtVerifier.kt
// (KeyBindingVerifier). See jose/NOTICE.

package sdjwt

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// TypKB is the typ header of a Key Binding JWT.
const TypKB = "kb+jwt"

// Defaults of KBWant.
const (
	DefaultKBMaxAge    = 5 * time.Minute
	DefaultKBClockSkew = time.Minute
)

// SDHash returns the sd_hash of a presentation: base64url(SHA-256(ASCII of
// sdJWT)), where sdJWT is <issuer JWT>~<D1>~…~<Dk>~ — exactly the disclosures
// sent, with the trailing ~ and without the KB-JWT.
func SDHash(sdJWT string) string {
	return digestOf(sdJWT)
}

// NewKBJWT signs a Key Binding JWT through jose.Sign: header
// {"alg": alg, "typ": "kb+jwt"}, payload {"iat", "aud", "nonce", "sd_hash"}
// and nothing else. aud, nonce and sdHash must not be empty, iat not zero.
func NewKBJWT(s jose.Signer, alg, aud, nonce string, iat time.Time, sdHash string) (string, error) {
	if aud == "" || nonce == "" || sdHash == "" || iat.IsZero() {
		return "", fmt.Errorf("sdjwt: key binding JWT needs aud, nonce, iat and sd_hash")
	}
	payload, err := jose.EncodeJSON(map[string]any{
		"iat":     iat.Unix(),
		"aud":     aud,
		"nonce":   nonce,
		"sd_hash": sdHash,
	})
	if err != nil {
		return "", err
	}
	return jose.Sign(s, alg, map[string]any{"typ": TypKB}, payload)
}

// KBWant is what VerifyKBJWT expects of a Key Binding JWT.
type KBWant struct {
	Audience string // required
	Nonce    string // required
	// SDHash is SDHash of the presentation as received: everything up to and
	// including the last ~. Required.
	SDHash    string
	Now       time.Time     // zero: time.Now()
	MaxAge    time.Duration // zero: DefaultKBMaxAge
	ClockSkew time.Duration // zero: DefaultKBClockSkew
}

// VerifyKBJWT checks a Key Binding JWT against the holder key taken from the
// cnf.jwk of the issuer-signed payload:
//  1. signature through jose.Verify with holderKey (ES256 or ES256K, the key
//     decides), then typ is kb+jwt and the payload is a JSON object
//     (ErrKBInvalid);
//  2. aud is a string equal to want.Audience; an array is refused
//     (ErrKBAudience);
//  3. nonce is a string equal to want.Nonce (ErrKBNonce);
//  4. sd_hash is a string equal to want.SDHash (ErrKBSDHash);
//  5. iat is a number in [now − MaxAge − ClockSkew, now + ClockSkew]
//     (ErrKBInvalid).
//
// Other claims are ignored. Empty Audience, Nonce or SDHash in want is a
// caller error, never a match.
func VerifyKBJWT(kb string, holderKey *ecdsa.PublicKey, want KBWant) error {
	if want.Audience == "" || want.Nonce == "" || want.SDHash == "" {
		return fmt.Errorf("sdjwt: KBWant needs Audience, Nonce and SDHash")
	}
	header, raw, err := jose.Verify(kb, holderKey, nil)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrKBInvalid, err)
	}
	if header.Typ() != TypKB {
		return fmt.Errorf("%w: typ %q, want %q", ErrKBInvalid, header.Typ(), TypKB)
	}
	claims, err := jose.DecodeJSONObject(raw)
	if err != nil {
		return fmt.Errorf("%w: payload: %w", ErrKBInvalid, err)
	}
	if aud, ok := claims["aud"].(string); !ok || aud != want.Audience {
		return fmt.Errorf("%w: aud %v", ErrKBAudience, claims["aud"])
	}
	if nonce, ok := claims["nonce"].(string); !ok || nonce != want.Nonce {
		return fmt.Errorf("%w", ErrKBNonce)
	}
	if h, ok := claims["sd_hash"].(string); !ok || h != want.SDHash {
		return fmt.Errorf("%w", ErrKBSDHash)
	}

	now := want.Now
	if now.IsZero() {
		now = time.Now()
	}
	maxAge, skew := want.MaxAge, want.ClockSkew
	if maxAge <= 0 {
		maxAge = DefaultKBMaxAge
	}
	if skew <= 0 {
		skew = DefaultKBClockSkew
	}
	iat, err := numericDate(claims["iat"])
	if err != nil {
		return fmt.Errorf("%w: iat: %v", ErrKBInvalid, err)
	}
	earliest := float64(now.Add(-maxAge-skew).UnixNano()) / 1e9
	latest := float64(now.Add(skew).UnixNano()) / 1e9
	if iat < earliest || iat > latest {
		return fmt.Errorf("%w: iat %v outside [now-%v-%v, now+%v]", ErrKBInvalid, claims["iat"], maxAge, skew, skew)
	}
	return nil
}

// numericDate reads a JWT NumericDate (RFC 7519): a JSON number of seconds,
// possibly fractional.
func numericDate(v any) (float64, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, fmt.Errorf("missing or not a number")
	}
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, fmt.Errorf("%s is not a finite number", n)
	}
	return f, nil
}
