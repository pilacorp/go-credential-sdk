// Package issuerkey holds the issuer keys of draft-ietf-oauth-sd-jwt-vc-19
// and draft-ietf-oauth-status-list-21, on both sides.
//
// The signing side is SigningKey: the issuer's jws.Signer and its public key,
// which dc.Issue and statuslist's IssueToken sign with. The verifying side is
// PublicKey and Resolver: a Resolver returns the keys an issuer publishes
// (draft 19 §2.5), and Select picks the one that verifies a JWS by its kid
// (RFC 7515 §4.1.4, RFC 7517 §4.5). draft 21 §11.3 lets a Status List Token
// use the key resolution of the credential, so one Resolver serves both.
//
// The token header never reaches a Resolver, so a token cannot steer how its
// keys are found (draft 19 §7.3), and Select never tries keys in turn.
package issuerkey

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/jose/jws"
)

// SigningKey is an issuer's signing key, for dc.Issue and the Status List
// Token. Signer holds the private key and Public is its public key; KID, when
// not empty, is written as the kid header (RFC 7515 §4.1.4). Nothing is
// checked here: jws.Sign checks Signer and Public when it signs.
type SigningKey struct {
	Signer jws.Signer
	Public crypto.PublicKey
	KID    string
}

// PublicKey is one key an issuer publishes for verifying its signatures.
type PublicKey struct {
	KID    string           // its kid (RFC 7517 §4.5); may be empty
	Public crypto.PublicKey // the curve decides the alg (RFC 8725 §3.1)
}

// ErrIssuerNotSupported is what a Resolver wraps when it does not accept iss
// at all: an issuer outside its trust list, or an identifier scheme it does
// not resolve. It is a definite answer, as ErrNoUsableKey is.
var ErrIssuerNotSupported = errors.New("issuerkey: issuer not supported")

// ErrNoUsableKey is what a Resolver wraps when the issuer's key source
// answered and the answer gives no usable key, for a reason the error states:
// a document that is not valid for its standard, or one naming another
// issuer. A later call gives the same until the issuer changes its document.
var ErrNoUsableKey = errors.New("issuerkey: no usable key")

// Resolver returns the keys an issuer publishes for verifying its signatures.
// Keys may be called from several goroutines at once and should return when
// ctx is done.
type Resolver interface {
	// Keys returns the keys iss currently publishes for verification, and
	// only those that may still verify: revocation is the resolver's policy.
	// The outcomes, told apart with errors.Is in this order:
	//   - an error wrapping ErrIssuerNotSupported: iss is not accepted. A
	//     resolver returns it before any network call when iss is outside
	//     what it covers (another scheme, an issuer it does not trust);
	//   - an error wrapping ErrNoUsableKey: the issuer answered with no
	//     usable key, for the reason the error states;
	//   - an error wrapping jose.ErrInvalidArgument: the code that built or
	//     calls the resolver is wrong, such as a zero-value resolver or a nil
	//     ctx. Wrap it only for such a mistake, never for anything iss or the
	//     issuer's answer controls;
	//   - any other error: the keys could not be found out (a network or
	//     store failure), and a later call may succeed. Wrap the cause with
	//     %w, so context.Canceled and context.DeadlineExceeded stay visible;
	//   - otherwise the keys, possibly none.
	//
	// iss comes from a token whose signature is not verified yet, so anyone
	// can write it. It may be "" (iss is OPTIONAL in draft 19 §2.2.2.3) and
	// can be long; an error should not quote it whole.
	Keys(ctx context.Context, iss string) ([]PublicKey, error)
}

// Select returns the key in keys that the JWS header h names. When h has kid,
// it must be a non-empty string equal to the KID of exactly one key; without
// kid, keys must hold exactly one key. Any other case, an empty set or a
// selected key that is nil included, is an error: no key verifies the token.
//
// This is stricter than RFC 7517 §4.5 (distinct kid values SHOULD) and draft
// 19 §4.2 (kid RECOMMENDED), so that the key is deterministic and a token cannot
// make the verifier try many keys. h is untrusted; Select reads only kid.
func Select(keys []PublicKey, h jws.Header) (crypto.PublicKey, error) {
	if len(keys) == 0 {
		return nil, errors.New("issuerkey: the resolver returned no key for this issuer")
	}
	var key crypto.PublicKey
	// Read kid raw: only an absent kid may fall back to a single key, and a
	// kid that is not a string (RFC 7515 §4.1.4) is refused like an empty one.
	if v, ok := h["kid"]; ok {
		kid, _ := v.(string)
		if kid == "" {
			return nil, errors.New("issuerkey: header kid is not a non-empty string")
		}
		n := 0
		for _, k := range keys {
			if k.KID == kid {
				n++
				key = k.Public
			}
		}
		if n != 1 {
			return nil, fmt.Errorf("issuerkey: %d of the keys the resolver returned have the header kid, want 1", n)
		}
	} else {
		if len(keys) != 1 {
			return nil, fmt.Errorf("issuerkey: no header kid and %d keys, want 1", len(keys))
		}
		key = keys[0].Public
	}
	if p, ok := key.(*ecdsa.PublicKey); key == nil || ok && p == nil {
		return nil, errors.New("issuerkey: the selected key is nil")
	}
	return key, nil
}
