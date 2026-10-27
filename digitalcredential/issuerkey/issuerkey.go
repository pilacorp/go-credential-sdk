// Package issuerkey selects the issuer key that verifies a JWS by its kid
// (RFC 7515 §4.1.4, RFC 7517 §4.5), for the credentials of
// draft-ietf-oauth-sd-jwt-vc-19 and the Status List Tokens of
// draft-ietf-oauth-status-list-21 alike: draft 21 §11.3 lets a Status List
// Token use the key resolution of the credential.
//
// The keys of an issuer come from a Resolver the caller writes. The token
// header never reaches it, so a token cannot influence how it is verified
// (draft 19 §7.3); Select then picks one key by kid, never trying keys in
// turn.
package issuerkey

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/jose/jws"
)

// Key is one public key an issuer publishes for signing.
type Key struct {
	KID string           // its kid (RFC 7517 §4.5); may be empty
	Key *ecdsa.PublicKey // P-256 or secp256k1; the curve decides alg (RFC 8725 §3.1)
}

// ErrIssuerNotSupported is what a Resolver wraps when this verifier does not
// accept iss at all: an issuer outside its trust list, or an identifier
// scheme it does not resolve. It is a definite answer, unlike any other
// error, which means the keys could not be found out.
var ErrIssuerNotSupported = errors.New("issuerkey: issuer not supported")

// Resolver returns the keys an issuer publishes for signing. Keys may be
// called from several goroutines at once and should return when ctx is done:
// a statuslist.Checker calls it on every cache miss, outside its 5-second
// fetch bound. iss is untrusted and may be long (see Keys): an error should
// not quote it whole, since callers such as digitalcredential.Verify pass the
// error on as returned.
type Resolver interface {
	// Keys returns the keys iss currently publishes for signing, and only
	// those that may still verify: revocation is the resolver's policy. It
	// has three outcomes, which callers map apart:
	//   - a set, empty when the issuer has no usable key (unknown, rotated
	//     out or deactivated): no key verifies the token;
	//   - an error wrapping ErrIssuerNotSupported: iss is not accepted;
	//   - any other error: the keys could not be found out (a network or
	//     store failure), and a later call may succeed.
	//
	// iss comes from a token whose signature is not verified yet, so anyone
	// can write it. It may be "" (iss is OPTIONAL in draft 19 §2.2.2.3) and
	// has no length bound beyond the token's own (up to about 0.75 MiB).
	Keys(ctx context.Context, iss string) ([]Key, error)
}

// Select returns the key in keys that the JWS header h names. A kid member
// must be a non-empty string equal to the KID of exactly one key; without
// kid, keys must hold exactly one key. Any other case, an empty set or a
// selected Key that is nil included, is an error: no key verifies the token.
//
// This is stricter than RFC 7517 §4.5 (distinct kid values SHOULD) and draft
// 19 §4.2 (kid RECOMMENDED), so the key is deterministic and a token cannot
// make the verifier try many keys. h is untrusted; Select only reads kid.
func Select(keys []Key, h jws.Header) (*ecdsa.PublicKey, error) {
	var key *ecdsa.PublicKey
	// Read raw: Header.Kid gives "" for an absent, empty or non-string kid,
	// and only the absent one may fall back to a single key. A kid that is
	// not a string (RFC 7515 §4.1.4) reads as "" and is refused with it.
	if v, ok := h["kid"]; ok {
		kid, _ := v.(string)
		if kid == "" {
			return nil, errors.New("issuerkey: header kid is not a non-empty string")
		}
		n := 0
		for _, k := range keys {
			if k.KID == kid {
				n++
				key = k.Key
			}
		}
		if n != 1 {
			return nil, fmt.Errorf("issuerkey: %d keys have the header kid, want 1", n)
		}
	} else {
		if len(keys) != 1 {
			return nil, fmt.Errorf("issuerkey: no header kid and %d keys, want 1", len(keys))
		}
		key = keys[0].Key
	}
	if key == nil {
		return nil, errors.New("issuerkey: the selected key is nil")
	}
	return key, nil
}
