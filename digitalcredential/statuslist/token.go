// The Status List Token in JWT format: draft-ietf-oauth-status-list-21 §5.1.

package statuslist

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuerkey"
	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
	"github.com/pilacorp/go-credential-sdk/jose/jwt"
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
	// Other holds the other claims of the token (§5.1: "The JWT MAY contain
	// other claims"), such as iss. IssueToken reads it through
	// jose.EncodeJSON, so any value encoding/json encodes may be given, and
	// never modifies it. It must not hold sub, iat, exp, ttl or status_list,
	// which the fields above and the list write; an nbf in it must be a
	// NumericDate (RFC 7519 §4.1.5).
	Other map[string]any
}

// reservedTokenClaims are the claims IssueToken writes from TokenClaims and
// the list, so Other must not hold them: each claim has one source.
var reservedTokenClaims = []string{"sub", "iat", "exp", "ttl", "status_list"}

// IssueToken signs l as a Status List Token in JWT format (draft 21 §5.1):
// header {"alg", "typ": "statuslist+jwt", "kid"}, alg the one of key.Signer,
// which jws.Sign checks against key.Public, and kid only when key.KID is set;
// payload {"sub", "iat", "exp", "ttl", "status_list": {"bits", "lst"}} (§4.2),
// exp and ttl only when set, lst from l.Encode, plus the claims of c.Other.
//
// A nil or zero l, a nil ctx, or claims breaking the rules of TokenClaims are
// jose.ErrInvalidArgument, checked before key.Signer is called. jws.Sign
// errors are wrapped unchanged: a nil key.Signer or key.Public, a signer
// error (jws.ErrSignerFailed, which also matches the ctx error when ctx ends
// inside the signer), and jws.ErrSelfCheck when the signer holds another key.
//
// Draft 21 sets no size limit (§13.4); IssueToken adds none beyond the List's
// 16 MiB. A Checker refuses a token over 1 MiB, which holds only about 576 KiB
// of list bytes that do not compress: a larger list reads only while it
// compresses well, so size or split lists for the highest change rate expected
// (draft 21 §13.4, Appendix B). Encode uses the best compression level (§4.1
// step 4 RECOMMENDS it), whose CPU time grows with the list size, so sign on
// each status change and before exp, and serve the stored token.
func (l *List) IssueToken(ctx context.Context, c TokenClaims, key issuerkey.SigningKey) (string, error) {
	if !l.valid() {
		return "", fmt.Errorf("%w: statuslist: list not made by New, FromBytes or Decode", jose.ErrInvalidArgument)
	}
	if ctx == nil {
		return "", fmt.Errorf("%w: statuslist: nil context", jose.ErrInvalidArgument)
	}
	claims, err := c.payload()
	if err != nil {
		return "", err
	}
	lst, err := l.Encode()
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
	token, err := jws.Sign(ctx, key.Signer, key.Public, header, payload)
	if err != nil {
		return "", fmt.Errorf("statuslist: %w", err)
	}
	return token, nil
}

// payload checks c and returns the claims it writes, all but status_list.
func (c TokenClaims) payload() (map[string]any, error) {
	if err := checkListURI(c.Sub); err != nil {
		return nil, fmt.Errorf("%w: statuslist: Sub %v", jose.ErrInvalidArgument, err)
	}
	if c.IssuedAt.IsZero() {
		return nil, fmt.Errorf("%w: statuslist: IssuedAt is required", jose.ErrInvalidArgument)
	}
	// §5.1: ttl MUST be a positive number; zero writes none.
	if c.TTL < 0 {
		return nil, fmt.Errorf("%w: statuslist: TTL %v is negative", jose.ErrInvalidArgument, c.TTL)
	}
	claims, err := c.otherClaims()
	if err != nil {
		return nil, err
	}
	claims["sub"] = c.Sub
	claims["iat"] = c.IssuedAt.Unix()
	if !c.Expiry.IsZero() {
		claims["exp"] = c.Expiry.Unix()
	}
	if c.TTL != 0 {
		claims["ttl"] = ttlNumber(c.TTL)
	}
	return claims, nil
}

// otherClaims returns Other as jose.DecodeJSONObject reads it from its JSON,
// so later steps see JSON types whatever Go types the caller used, and Other
// is never modified. nil gives an empty object.
func (c TokenClaims) otherClaims() (map[string]any, error) {
	if c.Other == nil {
		return map[string]any{}, nil
	}
	b, err := jose.EncodeJSON(c.Other)
	if err != nil {
		return nil, fmt.Errorf("%w: statuslist: Other: %v", jose.ErrInvalidArgument, err)
	}
	claims, err := jose.DecodeJSONObject(b)
	if err != nil {
		return nil, fmt.Errorf("%w: statuslist: Other: %v", jose.ErrInvalidArgument, err)
	}
	for _, name := range reservedTokenClaims {
		if _, ok := claims[name]; ok {
			return nil, fmt.Errorf("%w: statuslist: Other holds %q, which TokenClaims or the list writes", jose.ErrInvalidArgument, name)
		}
	}
	// RFC 7519 §4.1.5: nbf is a NumericDate. A time.Time in Other encodes as
	// an RFC 3339 string, which a verifier's CheckExpNbf refuses.
	if v, ok := claims["nbf"]; ok {
		if _, err := jwt.NumericDate(v); err != nil {
			return nil, fmt.Errorf("%w: statuslist: Other nbf: %v", jose.ErrInvalidArgument, err)
		}
	}
	return claims, nil
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
