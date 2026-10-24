package sdjwt

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
	"github.com/pilacorp/go-credential-sdk/jose/jwt"
)

// typKB is the explicit type of a Key Binding JWT (RFC 9901 §4.3, §11.2.3).
const typKB = "kb+jwt"

// RFC 9901 §7.3 step 5e leaves the acceptable iat window to the Verifier;
// these are the defaults of KBWant.
const (
	defaultKBMaxAge    = 5 * time.Minute
	defaultKBClockSkew = time.Minute
)

// VerifyKBJWT wraps one of these when a Key Binding JWT fails RFC 9901 §7.3
// step 5, so a caller maps each to its own error code; ErrKBInvalid also wraps
// the jws or jose cause. Only a nil holder or a bad KBWant wraps
// jose.ErrInvalidArgument instead; a non-nil holder that jws rejects (wrong
// curve, off-curve) is ErrKBInvalid.
var (
	// ErrKBInvalid: not a compact JWS, an alg other than the holder key's, a
	// crit or b64 header, a signature that does not verify with the holder
	// key, a typ other than kb+jwt, a payload that is not a JSON object, a
	// missing or malformed iat or one outside the window, or an exp or nbf
	// that fails.
	ErrKBInvalid = errors.New("sdjwt: key binding JWT invalid")
	// ErrKBAudience: aud is missing, not a single string, or differs.
	ErrKBAudience = errors.New("sdjwt: key binding JWT aud mismatch")
	// ErrKBNonce: nonce is missing, not a string, or differs.
	ErrKBNonce = errors.New("sdjwt: key binding JWT nonce mismatch")
	// ErrKBSDHash: sd_hash is missing, not a string, or differs.
	ErrKBSDHash = errors.New("sdjwt: key binding JWT sd_hash mismatch")
)

// SDHash returns the sd_hash of an SD-JWT (RFC 9901 §4.3.1):
// base64url(SHA-256(US-ASCII of sdJWT)), where sdJWT is
// <Issuer-signed JWT>~<D.1>~…~<D.N>~, exactly the disclosures presented, with
// the trailing ~ and without a KB-JWT. §4.3.1 uses the hash algorithm of the
// disclosures, and this package supports only sha-256 (§4.1.1).
func SDHash(sdJWT string) string {
	return digestOf(sdJWT)
}

// KBClaims are the claims of a new Key Binding JWT (RFC 9901 §4.3). All are
// required.
type KBClaims struct {
	Audience string    // aud: the Verifier the KB-JWT is for
	Nonce    string    // nonce: from the Verifier, binds the KB-JWT to one transaction
	IssuedAt time.Time // iat: written in whole seconds, the fraction dropped
	SDHash   string    // sd_hash: SDHash of the SD-JWT presented with it
}

// NewKBJWT signs a Key Binding JWT (RFC 9901 §4.3) with s, which holds the
// private key of holder, the key the SD-JWT binds (cnf, §4.1.2). The header
// is {"alg", "typ": "kb+jwt"}, alg chosen by the curve of holder (jws.Sign);
// the payload is iat, aud, nonce and sd_hash and nothing else (§4.3:
// additional claims and header parameters SHOULD be avoided unless there is a
// compelling reason).
//
// A nil s or holder, an empty Audience, Nonce or SDHash, or a zero IssuedAt is
// jose.ErrInvalidArgument. jws.Sign errors are wrapped unchanged: a signer
// that does not hold the private key of holder gives jws.ErrSelfCheck.
func NewKBJWT(s jws.Signer, holder *ecdsa.PublicKey, c KBClaims) (string, error) {
	if s == nil || holder == nil {
		return "", fmt.Errorf("%w: sdjwt: NewKBJWT needs a signer and the holder key", jose.ErrInvalidArgument)
	}
	if c.Audience == "" || c.Nonce == "" || c.SDHash == "" || c.IssuedAt.IsZero() {
		return "", fmt.Errorf("%w: sdjwt: KBClaims needs Audience, Nonce, IssuedAt and SDHash", jose.ErrInvalidArgument)
	}
	payload, err := jose.EncodeJSON(map[string]any{
		"iat":     c.IssuedAt.Unix(),
		"aud":     c.Audience,
		"nonce":   c.Nonce,
		"sd_hash": c.SDHash,
	})
	if err != nil {
		return "", fmt.Errorf("sdjwt: key binding JWT: %w", err)
	}
	kb, err := jws.Sign(s, holder, jws.Header{"typ": typKB}, payload)
	if err != nil {
		return "", fmt.Errorf("sdjwt: key binding JWT: %w", err)
	}
	return kb, nil
}

// KBWant is what VerifyKBJWT checks a Key Binding JWT against. Audience, Nonce
// and SDHash are required: an empty one is a caller mistake, never a match.
// MaxAge and ClockSkew zero mean the defaults, so a skew of zero cannot be
// asked for; a negative one is a caller mistake.
type KBWant struct {
	Audience  string        // this Verifier, compared byte for byte with aud
	Nonce     string        // the nonce this Verifier gave for the transaction
	SDHash    string        // SDHash of the SD-JWT as received, up to and including the last ~
	Now       time.Time     // zero: time.Now()
	MaxAge    time.Duration // how old iat may be; zero: 5 minutes
	ClockSkew time.Duration // leeway on iat, exp and nbf; zero: 1 minute
}

// VerifyKBJWT checks kb, the Key Binding JWT of a presentation, with the key
// the SD-JWT binds (cnf, RFC 9901 §4.3.2), in the order of RFC 9901 §7.3 step
// 5, and returns at the first failure:
//   - 5c: jws.Verify with holder; the key decides alg, ES256 or ES256K. Which
//     algorithms the application accepts (5b) is the caller's check, before
//     this one. ErrKBInvalid;
//   - 5d: typ is kb+jwt, as jws.Header.TypIs compares it; then the payload is a
//     JSON object (RFC 7519 §7.2 step 10). ErrKBInvalid;
//   - 5e: iat is present, a NumericDate (RFC 7519 §2), and within
//     [Now − MaxAge − ClockSkew, Now + ClockSkew], both ends included.
//     ErrKBInvalid;
//   - 5f: aud is a string equal to Audience, else ErrKBAudience; nonce is a
//     string equal to Nonce, else ErrKBNonce;
//   - 5g: sd_hash is a string equal to SDHash. ErrKBSDHash;
//   - 5h: exp, when present, is a NumericDate and Now < exp + ClockSkew, so
//     Now = exp + ClockSkew is refused (RFC 7519 §4.1.4: "on or after"); nbf,
//     when present, is a NumericDate and Now ≥ nbf − ClockSkew, so
//     Now = nbf − ClockSkew passes (§4.1.5: "after or equal"). ErrKBInvalid.
//
// Other claims are ignored, and so are other header members except crit and
// b64, which jws.Verify refuses. aud, nonce and sd_hash are compared byte for
// byte after JSON unescaping, without Unicode normalization (RFC 7519 §7.3,
// RFC 8259 §8.3). A nil holder, an empty Audience, Nonce or SDHash, or a
// negative MaxAge or ClockSkew is jose.ErrInvalidArgument, checked before kb
// is read.
//
// It keeps no state: that Nonce was issued by this Verifier and is used once
// is the caller's check. ECDSA signatures are malleable, so a replay cannot
// be detected from the bytes of kb.
func VerifyKBJWT(kb string, holder *ecdsa.PublicKey, want KBWant) error {
	if holder == nil {
		return fmt.Errorf("%w: sdjwt: VerifyKBJWT needs the holder key", jose.ErrInvalidArgument)
	}
	if want.Audience == "" || want.Nonce == "" || want.SDHash == "" {
		return fmt.Errorf("%w: sdjwt: KBWant needs Audience, Nonce and SDHash", jose.ErrInvalidArgument)
	}
	if want.MaxAge < 0 || want.ClockSkew < 0 {
		return fmt.Errorf("%w: sdjwt: KBWant MaxAge and ClockSkew must not be negative", jose.ErrInvalidArgument)
	}
	now, maxAge, skew := want.Now, want.MaxAge, want.ClockSkew
	if now.IsZero() {
		now = time.Now()
	}
	if maxAge == 0 {
		maxAge = defaultKBMaxAge
	}
	if skew == 0 {
		skew = defaultKBClockSkew
	}

	header, raw, err := jws.Verify(kb, holder, nil)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrKBInvalid, err)
	}
	if !header.TypIs(typKB) {
		return fmt.Errorf("%w: typ is not %s", ErrKBInvalid, typKB)
	}
	claims, err := jose.DecodeJSONObject(raw)
	if err != nil {
		return fmt.Errorf("%w: payload: %w", ErrKBInvalid, err)
	}

	iat, ok, err := dateClaim(claims, "iat")
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: iat is missing", ErrKBInvalid)
	}
	// Shifting now, not the claim, keeps a far-off date from overflowing.
	earliest, latest := now.Add(-maxAge).Add(-skew), now.Add(skew)
	if iat.Before(earliest) || iat.After(latest) {
		return fmt.Errorf("%w: iat %s is outside [%s, %s]", ErrKBInvalid, iat, earliest.UTC(), latest.UTC())
	}

	// RFC 9901 §4.3: aud MUST be a single string, where RFC 7519 §4.1.3 also
	// allows an array. An array is refused: one KB-JWT is bound to one
	// Verifier, and an array would let each Verifier listed accept it.
	if err := stringClaim(claims, "aud", want.Audience, ErrKBAudience); err != nil {
		return err
	}
	if err := stringClaim(claims, "nonce", want.Nonce, ErrKBNonce); err != nil {
		return err
	}
	if err := stringClaim(claims, "sd_hash", want.SDHash, ErrKBSDHash); err != nil {
		return err
	}

	exp, ok, err := dateClaim(claims, "exp")
	if err != nil {
		return err
	}
	if ok && !now.Add(-skew).Before(exp) {
		return fmt.Errorf("%w: expired at %s", ErrKBInvalid, exp)
	}
	nbf, ok, err := dateClaim(claims, "nbf")
	if err != nil {
		return err
	}
	if ok && now.Add(skew).Before(nbf) {
		return fmt.Errorf("%w: not valid before %s", ErrKBInvalid, nbf)
	}
	return nil
}

// dateClaim reads the NumericDate claim name; ok is false when it is absent.
func dateClaim(claims map[string]any, name string) (t time.Time, ok bool, err error) {
	v, ok := claims[name]
	if !ok {
		return time.Time{}, false, nil
	}
	t, err = jwt.NumericDate(v)
	if err != nil {
		return time.Time{}, true, fmt.Errorf("%w: %s: %w", ErrKBInvalid, name, err)
	}
	return t, true, nil
}

// stringClaim checks that claim name is a string equal to want, and wraps
// sentinel when it is not.
func stringClaim(claims map[string]any, name, want string, sentinel error) error {
	v, ok := claims[name]
	if !ok {
		return fmt.Errorf("%w: %s is missing", sentinel, name)
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Errorf("%w: %s is %T, not a string", sentinel, name, v)
	}
	if s != want {
		return fmt.Errorf("%w: %s differs from the expected value", sentinel, name)
	}
	return nil
}
