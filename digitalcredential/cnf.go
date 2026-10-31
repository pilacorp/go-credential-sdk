// Reading the Holder key from cnf: RFC 7800 §3, §3.1, §3.2 and
// draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3.

package dc

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jwk"
	"github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

// errNoCnf: the credential has no cnf claim, neither in the Issuer-signed JWT
// nor in a disclosure. Whether that is an error, and whose, is the caller's
// to say, so it carries no sentinel.
var errNoCnf = errors.New("dc: the credential has no cnf claim")

// holderKey reads the Holder's public key from cnf.jwk of payload, the
// Issuer-signed JWT payload, with r recreated from it. It is the one reader of
// cnf.jwk in this package, and its errors describe the credential:
//   - no cnf at all: errNoCnf;
//   - cnf, or any claim inside it, in a disclosure, which draft 19 §2.2.2.3
//     forbids, or a cnf with more than one of jwk, jwe and jku (RFC 7800
//     §3.1): jose.ErrMalformed;
//   - a cnf without jwk, or a cnf.jwk of a key type or curve jose/jwk does
//     not convert: ErrKeyBindingUnsupported, the second also
//     jose.ErrUnsupportedKey;
//   - a cnf or cnf.jwk that is not an object, a symmetric cnf.jwk, or a key
//     jwk.ToPublicKey refuses as broken: jose.ErrMalformed and jwk.ErrBadKey.
func holderKey(payload map[string]any, r *sdjwt.Recreated) (crypto.PublicKey, error) {
	// draft 19 §2.2.2.3: cnf "including any of their sub-claims" MUST NOT be
	// in a Disclosure. Checked on what was recreated, so a disclosed member
	// such as jku cannot join a cnf.jwk the Issuer signed in plain.
	if r.Disclosed(sdjwt.Path{"cnf"}) {
		return nil, fmt.Errorf("%w: dc: the credential's cnf, or a claim inside it, is in a disclosure, which draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 forbids; the Issuer must reissue it with all of cnf in the Issuer-signed JWT", jose.ErrMalformed)
	}
	cnf, ok := payload["cnf"]
	if !ok {
		return nil, errNoCnf
	}
	obj, isObject := cnf.(map[string]any)
	if isObject {
		// RFC 7800 §3.1: cnf MUST represent a single proof-of-possession key,
		// so at most one of jwk, jwe and jku may be present.
		n := 0
		for _, m := range []string{"jwk", "jwe", "jku"} {
			if _, ok := obj[m]; ok {
				n++
			}
		}
		if n > 1 {
			return nil, fmt.Errorf("%w: dc: the credential's cnf has more than one of jwk, jwe and jku, and RFC 7800 §3.1 allows one; the Issuer must reissue it", jose.ErrMalformed)
		}
		if _, ok := obj["jwk"]; !ok {
			return nil, fmt.Errorf("%w: its cnf has no jwk member, and this SDK binds only to cnf.jwk holding an EC P-256 or secp256k1 key", ErrKeyBindingUnsupported)
		}
	}
	m, ok := obj["jwk"].(map[string]any) // obj is nil when cnf is not an object
	if !ok {
		return nil, fmt.Errorf("%w: dc: the credential's cnf or cnf.jwk is not a JSON object (RFC 7800 §3, §3.2); the Issuer must reissue it: %w", jose.ErrMalformed, jwk.ErrBadKey)
	}
	// RFC 7800 §3.2: a symmetric key goes in jwk only when the JWT is
	// encrypted, and the Issuer-signed JWT of an SD-JWT is a JWS.
	if kty, _ := m["kty"].(string); kty == "oct" {
		return nil, fmt.Errorf("%w: dc: the credential's cnf.jwk is a symmetric key in a JWT that is not encrypted (RFC 7800 §3.2); the Issuer must reissue it: %w", jose.ErrMalformed, jwk.ErrBadKey)
	}
	key, err := jwk.ToPublicKey(m)
	if errors.Is(err, jose.ErrUnsupportedKey) {
		return nil, fmt.Errorf("%w: its cnf.jwk holds a key this SDK does not bind (%w)", ErrKeyBindingUnsupported, err)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: dc: the credential's cnf.jwk is not a usable key; the Issuer must reissue it: %w", jose.ErrMalformed, err)
	}
	return key, nil
}
