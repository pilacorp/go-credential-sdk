package statuslist

import (
	"crypto/ecdsa"
	"fmt"
	"net/url"
	"time"

	"github.com/pilacorp/go-credential-sdk/jose"
)

// MediaType is the Content-Type and Accept value of a status list token, and
// TokenType its typ header (draft 21 §5.1).
const (
	MediaType = "application/statuslist+jwt"
	TokenType = "statuslist+jwt"
)

// SigningKey is the key a status list token is signed with: the same key that
// signs the credentials pointing to the list.
//
// It has the fields of digitalcredential.SigningKey (spec S2), in the same
// order. It is declared here because the root package imports statuslist and
// statuslist must not import the root package; the root package is meant to
// declare `type SigningKey = statuslist.SigningKey`, so one value serves Issue
// and SignToken. Should it declare its own struct instead, identical fields
// keep the two convertible with statuslist.SigningKey(k).
type SigningKey struct {
	Signer jose.Signer
	Alg    string           // "ES256" (default when empty) or "ES256K"
	KID    string           // required, e.g. did:nda:…#key-2
	Public *ecdsa.PublicKey // optional; when set, the token is verified before it is returned
}

// TokenClaims are the claims of a status list token besides status_list.
type TokenClaims struct {
	// Sub is the URI the token is served at. It must be exactly the uri
	// written in status.status_list of the credentials, character for
	// character: the Checker compares the two. Required, https.
	Sub string
	// IssuedAt is required; written as integer Unix seconds.
	IssuedAt time.Time
	// Expiry is optional; when set it must be after IssuedAt.
	Expiry time.Time
	// TTL is optional: how long a verifier may cache the token. When set it
	// must be a positive whole number of seconds.
	TTL time.Duration
}

// SignToken signs l as a status list token (draft 21 §5.1):
//   - header {"alg", "kid", "typ": "statuslist+jwt"};
//   - payload {"sub", "iat", "exp"?, "ttl"?, "status_list": {"bits", "lst"}},
//     times and ttl in integer seconds, encoded once and signed as is through
//     jose.Sign;
//   - when key.Public is set, the token is verified with it before it is
//     returned (ErrSelfCheck otherwise).
//
// authen-service calls it on every request for the list (D6).
func SignToken(l *List, c TokenClaims, key SigningKey) (string, error) {
	if l == nil {
		return "", fmt.Errorf("%w: nil list", ErrInvalidArgument)
	}
	if err := checkTokenClaims(c); err != nil {
		return "", err
	}
	alg := key.Alg
	if alg == "" {
		alg = jose.AlgES256
	}
	if key.Signer == nil {
		return "", fmt.Errorf("%w: nil signer", ErrInvalidArgument)
	}
	if key.KID == "" {
		return "", fmt.Errorf("%w: kid is required", ErrInvalidArgument)
	}
	lst, err := l.Encode()
	if err != nil {
		return "", fmt.Errorf("statuslist: encode: %w", err)
	}
	payload := map[string]any{
		"sub": c.Sub,
		"iat": c.IssuedAt.Unix(),
		"status_list": map[string]any{
			"bits": l.bits,
			"lst":  lst,
		},
	}
	if !c.Expiry.IsZero() {
		payload["exp"] = c.Expiry.Unix()
	}
	if c.TTL != 0 {
		payload["ttl"] = int64(c.TTL / time.Second)
	}
	payloadJSON, err := jose.EncodeJSON(payload)
	if err != nil {
		return "", fmt.Errorf("statuslist: encode payload: %w", err)
	}
	header := map[string]any{"typ": TokenType, "kid": key.KID}
	token, err := jose.Sign(key.Signer, alg, header, payloadJSON)
	if err != nil {
		return "", fmt.Errorf("statuslist: sign: %w", err)
	}
	if key.Public != nil {
		if _, _, err := jose.Verify(token, key.Public, []string{alg}); err != nil {
			return "", fmt.Errorf("%w: %w", ErrSelfCheck, err)
		}
	}
	return token, nil
}

func checkTokenClaims(c TokenClaims) error {
	if err := checkHTTPSURI(c.Sub); err != nil {
		return fmt.Errorf("%w: sub: %v", ErrInvalidArgument, err)
	}
	if c.IssuedAt.IsZero() {
		return fmt.Errorf("%w: IssuedAt is required", ErrInvalidArgument)
	}
	if !c.Expiry.IsZero() && !c.Expiry.After(c.IssuedAt) {
		return fmt.Errorf("%w: Expiry must be after IssuedAt", ErrInvalidArgument)
	}
	if c.TTL < 0 || c.TTL%time.Second != 0 {
		return fmt.Errorf("%w: TTL must be a positive whole number of seconds", ErrInvalidArgument)
	}
	return nil
}

// checkHTTPSURI requires an absolute https URL with a host and no userinfo.
func checkHTTPSURI(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return fmt.Errorf("%q is not an https URL with a host", s)
	}
	return nil
}
