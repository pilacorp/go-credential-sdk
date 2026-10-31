// The Key Binding JWT of RFC 9901: its form and sd_hash (§4.3) and its
// verification (§7.3 step 5). Written from the RFC, not ported.

package sdjwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/internal/ec"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
	"github.com/pilacorp/go-credential-sdk/jose/jwt"
)

// typKB is the explicit type of a Key Binding JWT (RFC 9901 §4.3, §11.2.3).
const typKB = "kb+jwt"

// VerifyKBJWT wraps one of these when a Key Binding JWT fails RFC 9901 §7.3
// step 5, so a caller maps each to its own error code; ErrKBInvalid also wraps
// the jws or jose cause. The caller's own inputs are classed before kb is
// read, so the class does not depend on what the holder sends: a nil holder
// (or a nil *ecdsa.PublicKey) or bad KBVerifyParams wraps
// jose.ErrInvalidArgument, a holder key or AllowedAlgs entry the SDK does not
// support wraps jose.ErrUnsupportedKey or jose.ErrUnsupportedAlg, and a
// broken holder key of a supported kind (a coordinate out of range, a point
// off its curve) wraps jws.ErrBadKey.
var (
	// ErrKBInvalid: not a compact JWS, an alg other than the holder key's or
	// not in KBVerifyParams.AllowedAlgs, a crit or b64 header, a signature that does
	// not verify with the holder key, a typ other than kb+jwt, a payload that
	// is not a JSON object, a missing or malformed iat or one outside the
	// window, an aud, nonce or sd_hash that is missing or not a single string
	// (RFC 9901 §4.3), or an exp or nbf that fails.
	ErrKBInvalid = errors.New("sdjwt: key binding JWT invalid")
	// ErrKBAudience: aud is a string that differs from KBVerifyParams.Audience.
	ErrKBAudience = errors.New("sdjwt: key binding JWT aud mismatch")
	// ErrKBNonce: nonce is a string that differs from KBVerifyParams.Nonce.
	ErrKBNonce = errors.New("sdjwt: key binding JWT nonce mismatch")
	// ErrKBSDHash: sd_hash is a string that differs from KBVerifyParams.SDHash.
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

// KBClaims are the claims of a new Key Binding JWT (RFC 9901 §4.3). All but
// Extra are required.
type KBClaims struct {
	Audience string    // aud: the Verifier the KB-JWT is for (§4.3: identifies the intended receiver)
	Nonce    string    // nonce: from the Verifier, binds the KB-JWT to one transaction (§4.3: freshness)
	IssuedAt time.Time // iat: written in whole seconds, the fraction dropped
	SDHash   string    // sd_hash: SDHash of the SD-JWT presented with it
	// Extra holds other claims, for a protocol that defines them, such as
	// transaction_data_hashes of OpenID4VP 1.0 Appendix B.3.3.1; nil writes
	// none. §4.3 allows them and asks to avoid them without a compelling
	// reason. It must not hold iat, aud, nonce or sd_hash, so a value copied
	// from a request cannot bind the KB-JWT to another Verifier or
	// transaction, and it is not modified. Values are written by
	// jose.EncodeJSON as they are: exp or nbf must be a NumericDate (int64
	// Unix seconds), since a time.Time is written as an RFC 3339 string,
	// which VerifyKBJWT refuses.
	Extra map[string]any
}

// NewKBJWT signs a Key Binding JWT (RFC 9901 §4.3) with s, which holds the
// private key of holder, the key the SD-JWT binds (cnf, §4.1.2). ctx goes to
// jws.Sign and from there to s unchanged; NewKBJWT does no I/O itself. The header
// is {"alg", "typ": "kb+jwt"}, alg the alg of s, which jws.Sign checks
// against the curve of holder;
// the payload is iat, aud, nonce and sd_hash, and the claims of Extra (§4.3:
// additional claims SHOULD be avoided unless there is a compelling reason).
//
// A nil s or holder, an empty Audience, Nonce or SDHash, a zero IssuedAt, an
// Extra holding one of the four claims, or an Extra that jose.EncodeJSON
// cannot encode or that encodes to JSON jose.DecodeJSON refuses (duplicate
// names, nesting past jose.MaxJSONDepth) is jose.ErrInvalidArgument. jws.Sign
// errors are wrapped unchanged: a nil ctx is jose.ErrInvalidArgument, and a
// signer that does not hold the private key of holder gives jws.ErrSelfCheck.
//
// The size of Extra is not bounded here. Split refuses an SD-JWT over 1 MiB
// with its KB-JWT, so a large Extra makes a presentation that readers of this
// package refuse.
func NewKBJWT(ctx context.Context, s jws.Signer, holder crypto.PublicKey, c KBClaims) (string, error) {
	if s == nil || isNilKey(holder) {
		return "", fmt.Errorf("%w: sdjwt: NewKBJWT needs a signer and the holder key", jose.ErrInvalidArgument)
	}
	if c.Audience == "" || c.Nonce == "" || c.SDHash == "" || c.IssuedAt.IsZero() {
		return "", fmt.Errorf("%w: sdjwt: KBClaims needs Audience, Nonce, IssuedAt and SDHash", jose.ErrInvalidArgument)
	}
	for _, name := range [...]string{"iat", "aud", "nonce", "sd_hash"} {
		if _, ok := c.Extra[name]; ok {
			return "", fmt.Errorf("%w: sdjwt: KBClaims.Extra holds %s, which NewKBJWT writes from its own field", jose.ErrInvalidArgument, name)
		}
	}
	// A copy read back as VerifyKBJWT reads it, so Extra holds only JSON that
	// VerifyKBJWT can decode.
	claims, err := copyClaims(c.Extra)
	if err != nil {
		return "", fmt.Errorf("sdjwt: KBClaims.Extra: %w", err)
	}
	claims["iat"] = c.IssuedAt.Unix()
	claims["aud"] = c.Audience
	claims["nonce"] = c.Nonce
	claims["sd_hash"] = c.SDHash
	payload, err := jose.EncodeJSON(claims)
	if err != nil {
		return "", fmt.Errorf("sdjwt: key binding JWT: %w", err)
	}
	kb, err := jws.Sign(ctx, s, holder, jws.Header{"typ": typKB}, payload)
	if err != nil {
		return "", fmt.Errorf("sdjwt: key binding JWT: %w", err)
	}
	return kb, nil
}

// KBVerifyParams is what VerifyKBJWT checks a Key Binding JWT against.
// Audience, Nonce and SDHash are required: an empty one is a caller mistake,
// never a match. RFC 9901 §7.3 step 5e leaves the acceptable iat window to
// the Verifier, so MaxAge and ClockSkew are used exactly as given: MaxAge must
// be positive, and a ClockSkew of zero allows no clock skew.
type KBVerifyParams struct {
	Audience  string        // this Verifier, compared byte for byte with aud
	Nonce     string        // the nonce this Verifier gave for the transaction
	SDHash    string        // SDHash of the SD-JWT as received, up to and including the last ~
	Now       time.Time     // zero: time.Now()
	MaxAge    time.Duration // how old iat may be; must be positive
	ClockSkew time.Duration // leeway on iat, exp and nbf; must not be negative
	// AllowedAlgs are the KB-JWT algorithms this application deems secure
	// (RFC 9901 §7.3 step 5b), as jws.Verify takes them: nil or empty means
	// ES256 and ES256K, and any other entry is jose.ErrUnsupportedAlg.
	AllowedAlgs []string
}

// VerifyKBJWT checks kb, the Key Binding JWT of a presentation, with the key
// the SD-JWT binds (cnf, RFC 9901 §4.3.2), in the order of RFC 9901 §7.3 step
// 5, and returns at the first failure:
//   - 5b and 5c: jws.Verify with holder and AllowedAlgs; the key decides
//     alg, ES256 or ES256K, and it must be in AllowedAlgs. ErrKBInvalid,
//     except that jose.ErrUnsupportedAlg, which names the caller's
//     AllowedAlgs, is returned as jws.Verify gives it;
//   - 5d: typ is kb+jwt, as jws.Header.TypIs compares it; then the payload is a
//     JSON object (RFC 7519 §7.2 step 10). ErrKBInvalid;
//   - 5e: iat is present, a NumericDate (RFC 7519 §2), and within
//     [Now − MaxAge − ClockSkew, Now + ClockSkew], both ends included.
//     ErrKBInvalid;
//   - 5f: aud is a string equal to Audience, else ErrKBAudience; nonce is a
//     string equal to Nonce, else ErrKBNonce;
//   - 5g: sd_hash is a string equal to SDHash, else ErrKBSDHash;
//   - 5h: exp and nbf, when present, pass jwt.CheckExpNbf with ClockSkew, so
//     Now = exp + ClockSkew is refused and Now = nbf − ClockSkew passes.
//     ErrKBInvalid.
//
// In 5f and 5g a claim that is missing or not a single string is
// ErrKBInvalid (RFC 9901 §4.3: REQUIRED, a string), not the mismatch error,
// which means a well-formed KB-JWT made for another verifier, transaction or
// presentation.
//
// On success it returns the claims of kb as jose.DecodeJSONObject decodes
// them, numbers as json.Number, every one included: the claims a protocol
// adds, such as transaction_data_hashes of OpenID4VP 1.0 Appendix B.3.3.1,
// are not checked here and are the caller's to check. On an error the claims
// are nil. Header members other than crit and b64, which jws.Verify refuses,
// are ignored. aud, nonce and sd_hash are compared byte for
// byte after JSON unescaping, without Unicode normalization (RFC 7519 §7.3,
// RFC 8259 §8.3). A nil holder, an empty Audience, Nonce or SDHash, a MaxAge
// that is not positive or a negative ClockSkew is jose.ErrInvalidArgument;
// then the holder key is checked as jws checks a key (jose.ErrUnsupportedKey
// or jws.ErrBadKey); both before kb is read.
//
// It keeps no state: that Nonce was issued by this Verifier and is used once
// is the caller's check. ECDSA signatures are malleable, so a replay cannot
// be detected from the bytes of kb.
func VerifyKBJWT(kb string, holder crypto.PublicKey, p KBVerifyParams) (map[string]any, error) {
	if isNilKey(holder) {
		return nil, fmt.Errorf("%w: sdjwt: VerifyKBJWT needs the holder key", jose.ErrInvalidArgument)
	}
	if p.Audience == "" || p.Nonce == "" || p.SDHash == "" {
		return nil, fmt.Errorf("%w: sdjwt: KBVerifyParams needs Audience, Nonce and SDHash", jose.ErrInvalidArgument)
	}
	if p.MaxAge <= 0 || p.ClockSkew < 0 {
		return nil, fmt.Errorf("%w: sdjwt: KBVerifyParams needs a positive MaxAge and a ClockSkew that is not negative", jose.ErrInvalidArgument)
	}
	// jws.Verify reads the key only after the token, so a holder key checked
	// there would get its class from the bytes the holder sends.
	if _, err := ec.FromPublicKey(holder); err != nil {
		if errors.Is(err, jose.ErrUnsupportedKey) {
			return nil, fmt.Errorf("sdjwt: key binding JWT: holder key: %w", err)
		}
		return nil, fmt.Errorf("%w: sdjwt: key binding JWT: holder key: %v", jws.ErrBadKey, err)
	}
	now, maxAge, skew := p.Now, p.MaxAge, p.ClockSkew
	if now.IsZero() {
		now = time.Now()
	}

	header, raw, err := jws.Verify(kb, holder, p.AllowedAlgs)
	if errors.Is(err, jose.ErrUnsupportedAlg) {
		// The caller's AllowedAlgs, refused before kb is read.
		return nil, fmt.Errorf("sdjwt: key binding JWT: %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKBInvalid, err)
	}
	if !header.TypIs(typKB) {
		return nil, fmt.Errorf("%w: typ is not %s", ErrKBInvalid, typKB)
	}
	claims, err := jose.DecodeJSONObject(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: payload: %w", ErrKBInvalid, err)
	}

	iat, ok, err := jwt.DateClaim(claims, "iat")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKBInvalid, err)
	}
	if !ok {
		return nil, fmt.Errorf("%w: iat is missing", ErrKBInvalid)
	}
	// Shifting now, not the claim, keeps a far-off date from overflowing.
	earliest, latest := now.Add(-maxAge).Add(-skew), now.Add(skew)
	if iat.Before(earliest) || iat.After(latest) {
		return nil, fmt.Errorf("%w: iat %s is outside [%s, %s]", ErrKBInvalid, iat, earliest.UTC(), latest.UTC())
	}

	// RFC 9901 §4.3: aud MUST be a single string, where RFC 7519 §4.1.3 also
	// allows an array. An array is refused: one KB-JWT is bound to one
	// Verifier, and an array would let each Verifier listed accept it.
	if err := stringClaim(claims, "aud", p.Audience, ErrKBAudience); err != nil {
		return nil, err
	}
	if err := stringClaim(claims, "nonce", p.Nonce, ErrKBNonce); err != nil {
		return nil, err
	}
	if err := stringClaim(claims, "sd_hash", p.SDHash, ErrKBSDHash); err != nil {
		return nil, err
	}

	if err := jwt.CheckExpNbf(claims, now, skew); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKBInvalid, err)
	}
	return claims, nil
}

// stringClaim checks that claim name is a string equal to want. A missing or
// non-string claim is ErrKBInvalid; a string that differs wraps sentinel.
func stringClaim(claims map[string]any, name, want string, sentinel error) error {
	v, ok := claims[name]
	if !ok {
		return fmt.Errorf("%w: %s is missing", ErrKBInvalid, name)
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Errorf("%w: %s is %T, not a string", ErrKBInvalid, name, v)
	}
	if s != want {
		return fmt.Errorf("%w: %s differs from the expected value", sentinel, name)
	}
	return nil
}

// isNilKey reports a missing holder key: nil, or a nil *ecdsa.PublicKey, the
// one key type the SDK reads. A nil of another type is a key type the SDK does
// not support, as jws and ec class it.
func isNilKey(k crypto.PublicKey) bool {
	pub, ok := k.(*ecdsa.PublicKey)
	return k == nil || ok && pub == nil
}
