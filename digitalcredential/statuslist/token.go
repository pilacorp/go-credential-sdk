// The Status List Token in JWT format: draft-ietf-oauth-status-list-21 §5.1.

package statuslist

import (
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"net/url"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/safehttp"
	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
)

// maxTokenBytes caps a Status List Token in compact form: the cap the Checker
// applies to the response body, and SignToken refuses a larger token, so no
// signed token exceeds it. Draft 21 sets no limit (§13.4). With
// lst base64url-encoded inside the base64url payload, the cap holds only
// about 576 KiB of list bytes that do not compress.
const maxTokenBytes = 1 << 20

// typStatusList: draft 21 §5.1, typ MUST be statuslist+jwt.
const typStatusList = "statuslist+jwt"

// TokenClaims are the claims of a new Status List Token (draft 21 §5.1).
type TokenClaims struct {
	// Sub is the URI of the token, the uri the Referenced Tokens carry
	// (§6.2); §5.1 requires the two to be equal, which is the caller's to
	// keep. It must be a URI (RFC 7519 §2: a StringOrURI holding ":" MUST be
	// one; RFC 3986 §3), and an https URL with a host and no userinfo (RFC
	// 9110 §4.2.4), the only URLs this module fetches, as §6.2 lets the
	// Relying Party restrict uri.
	Sub string
	// IssuedAt is iat, required (§5.1); written in whole seconds, the
	// fraction dropped.
	IssuedAt time.Time
	// Expiry is exp (§5.1: RECOMMENDED); zero writes none. Written in whole
	// seconds, which must come after those of IssuedAt.
	Expiry time.Time
	// TTL is ttl, how long a verifier may cache the token (§5.1:
	// RECOMMENDED, a positive number of seconds); zero writes none. It must
	// be a whole number of seconds: ttl is written as a JSON integer, and a
	// fraction is refused rather than dropped, though §5.1 allows one.
	TTL time.Duration
}

// SigningKey is the issuer key a Status List Token is signed with.
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
// of TokenClaims, are jose.ErrInvalidArgument, and so is a token over 1 MiB,
// refused before key.Signer is called when the payload alone is that long.
// jws.Sign errors are wrapped unchanged, a nil key.Signer or key.Public
// included; the token is verified with key.Public before it is returned, so a
// signer holding another key gives jws.ErrSelfCheck.
//
// The 1 MiB token holds only about 576 KiB of list bytes that do not
// compress: a larger list signs only while it compresses well, and SignToken
// refuses it once status changes make it less compressible, so size or split
// lists for the highest change rate expected (draft 21 §13.4, Appendix B).
// Encode uses the best compression level (§4.1 step 4 RECOMMENDS it), whose
// CPU time grows with the list size, so sign on each status change and before
// exp, and serve the stored token.
func SignToken(l *List, c TokenClaims, key SigningKey) (string, error) {
	if err := checkListURI(c.Sub); err != nil {
		return "", fmt.Errorf("%w: statuslist: Sub %v", jose.ErrInvalidArgument, err)
	}
	if u, err := url.Parse(c.Sub); err != nil || !safehttp.HTTPSURL(u) {
		return "", fmt.Errorf("%w: statuslist: Sub is not an https URL with a host and no userinfo", jose.ErrInvalidArgument)
	}
	if c.IssuedAt.IsZero() {
		return "", fmt.Errorf("%w: statuslist: IssuedAt is required", jose.ErrInvalidArgument)
	}
	claims := map[string]any{"sub": c.Sub, "iat": c.IssuedAt.Unix()}
	if !c.Expiry.IsZero() {
		// Compared in the seconds written, so exp never equals iat.
		if c.Expiry.Unix() <= c.IssuedAt.Unix() {
			return "", fmt.Errorf("%w: statuslist: Expiry is not after IssuedAt", jose.ErrInvalidArgument)
		}
		claims["exp"] = c.Expiry.Unix()
	}
	if c.TTL != 0 {
		if c.TTL < 0 || c.TTL%time.Second != 0 {
			return "", fmt.Errorf("%w: statuslist: TTL %v is not a positive whole number of seconds", jose.ErrInvalidArgument, c.TTL)
		}
		claims["ttl"] = int64(c.TTL / time.Second)
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
	// RFC 7515 §7.1: the payload segment is part of the token, so a payload
	// already over the cap is refused before the signer is called; the exact
	// check after signing covers the header and signature.
	if n := base64.RawURLEncoding.EncodedLen(len(payload)); n > maxTokenBytes {
		return "", fmt.Errorf("%w: statuslist: payload encodes to %d bytes, over %d", jose.ErrInvalidArgument, n, maxTokenBytes)
	}

	header := jws.Header{"typ": typStatusList}
	if key.KID != "" {
		header["kid"] = key.KID
	}
	token, err := jws.Sign(key.Signer, key.Public, header, payload)
	if err != nil {
		return "", fmt.Errorf("statuslist: %w", err)
	}
	if len(token) > maxTokenBytes {
		return "", fmt.Errorf("%w: statuslist: token is %d bytes, over %d", jose.ErrInvalidArgument, len(token), maxTokenBytes)
	}
	return token, nil
}
