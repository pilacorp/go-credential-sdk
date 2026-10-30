// The Status List Token in JWT format: draft-ietf-oauth-status-list-21 §5.1.

package statuslist

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
)

// typStatusList: draft 21 §5.1, typ MUST be statuslist+jwt.
const typStatusList = "statuslist+jwt"

// TokenClaims are the claims of a new Status List Token (draft 21 §5.1).
type TokenClaims struct {
	// Sub is the URI of the token, the uri the Referenced Tokens carry
	// (§6.2); §5.1 requires the two to be equal, which is the caller's to
	// keep. It must be a URI (§6.2; RFC 7519 §2: a StringOrURI holding ":"
	// MUST be one; RFC 3986 §3), with a host when it is http or https (RFC
	// 9110 §4.2.1, §4.2.2); any scheme, since the scheme a verifier fetches
	// is the Relying Party's choice (§6.2).
	Sub string
	// IssuedAt is iat, required (§5.1); written in whole seconds, the
	// fraction dropped.
	IssuedAt time.Time
	// Expiry is exp (§5.1: RECOMMENDED); zero writes none. Written in whole
	// seconds, the fraction dropped.
	Expiry time.Time
	// TTL is ttl, how long a verifier may cache the token (§5.1:
	// RECOMMENDED, a positive number of seconds); zero writes none and a
	// negative one is refused. Whole seconds are written as a JSON integer,
	// a fraction as a JSON number with up to nine decimals.
	TTL time.Duration
}

// SigningKey is an issuer's signing key: the Signer, the public key that
// decides alg, and an optional kid.
type SigningKey struct {
	Signer jws.Signer       // holds the private key of Public
	Public *ecdsa.PublicKey // decides alg (RFC 8725 §3.1: one algorithm per key)
	// KID is the kid header; empty writes none (RFC 7515 §4.1.4: optional),
	// and a verifier selecting keys with issuerkey.Select then accepts the
	// token only from an issuer that publishes exactly one key.
	KID string
}

// SignToken signs l as a Status List Token in JWT format (draft 21 §5.1):
// header {"alg", "typ": "statuslist+jwt", "kid"}, alg chosen by the curve of
// key.Public (jws.Sign) and kid only when key.KID is set; payload {"sub",
// "iat", "exp", "ttl", "status_list": {"bits", "lst"}} (§4.2), exp and ttl
// only when set, lst from l.Encode.
//
// A list not made by New, FromBytes or Decode, or claims breaking the rules
// of TokenClaims, are jose.ErrInvalidArgument. jws.Sign errors are wrapped
// unchanged, a nil key.Signer or key.Public included; the token is verified
// with key.Public before it is returned, so a signer holding another key
// gives jws.ErrSelfCheck.
//
// Draft 21 sets no size limit (§13.4); SignToken adds none beyond the List's
// 16 MiB. A Checker refuses one over 1 MiB, which holds only about 576 KiB of
// list bytes that do not compress: a larger list reads only while it
// compresses well, so size or split lists for the highest change rate
// expected (draft 21 §13.4, Appendix B). Encode uses the best compression level (§4.1 step 4 RECOMMENDS it), whose
// CPU time grows with the list size, so sign on each status change and before
// exp, and serve the stored token.
func SignToken(l *List, c TokenClaims, key SigningKey) (string, error) {
	if err := checkListURI(c.Sub); err != nil {
		return "", fmt.Errorf("%w: statuslist: Sub %v", jose.ErrInvalidArgument, err)
	}
	if c.IssuedAt.IsZero() {
		return "", fmt.Errorf("%w: statuslist: IssuedAt is required", jose.ErrInvalidArgument)
	}
	claims := map[string]any{"sub": c.Sub, "iat": c.IssuedAt.Unix()}
	if !c.Expiry.IsZero() {
		claims["exp"] = c.Expiry.Unix()
	}
	if c.TTL != 0 {
		// §5.1: ttl MUST be a positive number.
		if c.TTL < 0 {
			return "", fmt.Errorf("%w: statuslist: TTL %v is not positive", jose.ErrInvalidArgument, c.TTL)
		}
		claims["ttl"] = ttlNumber(c.TTL)
	}
	lst, err := l.Encode() // refuses a list not made by New, FromBytes or Decode
	if err != nil {
		return "", err
	}
	claims["status_list"] = map[string]any{"bits": l.bits, "lst": lst}
	payload, err := jose.EncodeJSON(claims)
	if err != nil {
		return "", fmt.Errorf("statuslist: %w", err)
	}

	header := jws.Header{"typ": typStatusList}
	if key.KID != "" {
		header["kid"] = key.KID
	}
	token, err := jws.Sign(key.Signer, key.Public, header, payload)
	if err != nil {
		return "", fmt.Errorf("statuslist: %w", err)
	}
	return token, nil
}

// ttlNumber writes d, a positive duration, in seconds as a JSON number:
// exact in decimal, an integer when d is whole seconds.
func ttlNumber(d time.Duration) json.Number {
	s := strconv.FormatInt(int64(d/time.Second), 10)
	if frac := d % time.Second; frac != 0 {
		s += "." + strings.TrimRight(fmt.Sprintf("%09d", int64(frac)), "0")
	}
	return json.Number(s)
}
