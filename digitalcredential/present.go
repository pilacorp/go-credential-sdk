// Presenting an SD-JWT VC on the holder side: RFC 9901 §7.2 (selection §4,
// §4.2.6; Key Binding JWT §4.3, §4.3.1) and draft-ietf-oauth-sd-jwt-vc-19
// §2.2.2.3 (cnf).

package digitalcredential

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jwk"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
	"github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

// ErrKeyBindingUnsupported: the credential's cnf is in a form this SDK cannot
// use for Key Binding, here when Present makes a Key Binding JWT: a cnf
// without jwk, or a cnf.jwk of a key type jose/jwk does not convert (then
// jwk.ErrUnsupportedKey too). draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 lets cnf
// hold any RFC 7800 confirmation method and recommends a JWK; binding only to
// cnf.jwk with an EC key on P-256 or secp256k1 is this SDK's restriction. The
// SDK does not check a cnf it cannot use, so the credential may be valid or
// broken: the error claims neither, and wraps neither jose.ErrMalformed nor
// jose.ErrInvalidArgument. No standard defines it.
var ErrKeyBindingUnsupported = errors.New("digitalcredential: this SDK cannot use this credential's cnf for Key Binding")

// KeyBinding asks Present for a Key Binding JWT (RFC 9901 §4.3). Every field
// is required. Signer must hold the private key of the credential's cnf.jwk
// (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3); that key decides the alg.
type KeyBinding struct {
	Signer   jws.Signer
	Audience string    // aud: the Verifier the presentation is for
	Nonce    string    // nonce: from the Verifier, for this transaction
	IssuedAt time.Time // iat: when the Key Binding JWT is issued (RFC 9901 §4.3), in whole seconds
}

// Present builds what a Holder sends to a Verifier (RFC 9901 §7.2) from
// issued, an SD-JWT as the Issuer gave it: the Issuer-signed JWT with the
// disclosures reveal selects and, when kb is not nil, a Key Binding JWT.
//
// Present checks issued only as far as it must to select disclosures: it
// splits it and recreates the claims (§7.1), but does not verify the Issuer's
// signature or any claim. The Holder checks the credential when it receives
// it (§7.2).
//
// Each reveal path selects the disclosure of that claim, if it is concealed,
// and those of its concealed ancestors (§4.2.6), never a descendant's; an
// empty reveal sends no disclosure (§4: any subset, none included). An
// ancestor's disclosure shows the ancestor's whole value except what is
// concealed inside it, so naming a claim can reveal more than that claim.
// Paths, array indices included, point into the claims Recreate rebuilds
// from issued; Split and Recreate on the result show what a Verifier sees.
// Disclosures go out each once (§4), in the order of issued; §4 sets no
// order, so that one is this SDK's choice.
//
// With kb nil there is no Key Binding JWT, even when the credential has cnf:
// whether Key Binding is required is the Verifier's decision (§7.2 step 4,
// §9.5). Otherwise the key comes from cnf.jwk, the form
// draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 recommends; that it must be cnf.jwk,
// with an EC key on P-256 or secp256k1, is this SDK's restriction. sd_hash
// covers exactly the returned SD-JWT before the Key Binding JWT (§4.3.1).
//
// Present sets no size limit, but readers built on this SDK refuse an SD-JWT
// over 1 MiB, with more than 1000 disclosures, or nested deeper than 32
// (sdjwt.Split, sdjwt.Recreate), so a credential near 1 MiB plus a Key Binding
// JWT is refused.
//
// Errors, with "" for the result:
//   - issued is not an SD-JWT (sdjwt.Split, jws.UnverifiedPayload, the
//     payload, sdjwt.Recreate), or is an SD-JWT+KB: jose.ErrMalformed; an
//     Issuer-signed JWT whose header has crit or b64: jws.ErrUnsupportedHeader;
//   - a reveal path that is not valid or not a claim of issued:
//     jose.ErrInvalidArgument;
//   - kb given and the credential has no cnf, neither in the Issuer-signed JWT
//     nor in any Disclosure: jose.ErrInvalidArgument, since the caller asked
//     to bind a credential that binds no key;
//   - kb given and a cnf this SDK cannot bind, one with no jwk, neither in the
//     Issuer-signed JWT nor in any Disclosure (kid, jku, …), or a cnf.jwk of a
//     key type jose/jwk does not convert: ErrKeyBindingUnsupported, the second
//     also jwk.ErrUnsupportedKey;
//   - kb given and a cnf the Issuer got wrong: jose.ErrMalformed. A cnf or
//     cnf.jwk in a Disclosure, which draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3
//     forbids for cnf and its sub-claims, and a cnf with more than one of jwk,
//     jwe and jku (RFC 7800 §3.1: one key), are that alone; a cnf or
//     cnf.jwk that is not an object, a symmetric cnf.jwk (RFC 7800 §3.2
//     allows one only in an encrypted JWT), or a key jwk.ToPublicKey refuses
//     as broken also matches jwk.ErrBadKey;
//   - sdjwt.NewKBJWT errors unchanged: jose.ErrInvalidArgument for an empty
//     KeyBinding field, jws.ErrSigner, and jws.ErrSelfCheck for a Signer that
//     does not hold the cnf.jwk key.
//
// The three kb classes are disjoint: such an error matches exactly one of
// jose.ErrInvalidArgument, ErrKeyBindingUnsupported and jose.ErrMalformed.
//
// Present's own error texts hold no disclosure and no claim value. Errors of
// sdjwt.Split, sdjwt.Recreate and jwk.ToPublicKey keep their own text, which
// can quote claim names (concealed ones included), digests, _sd_alg or part
// of it, and the kty or crv of cnf.jwk; never a salt or a whole disclosure.
// Do not forward error text to a Verifier.
func Present(issued string, reveal []sdjwt.Path, kb *KeyBinding) (string, error) {
	issuerJWT, encoded, kbJWT, payload, err := readCompact(issued)
	if err != nil {
		return "", err
	}
	if kbJWT != "" {
		return "", fmt.Errorf("%w: digitalcredential: Present takes an SD-JWT, not an SD-JWT+KB (RFC 9901 §4, §7.2)", jose.ErrMalformed)
	}
	given := make([]sdjwt.Disclosure, len(encoded))
	for i, e := range encoded {
		given[i] = sdjwt.Disclosure{Encoded: e}
	}
	r, err := sdjwt.Recreate(payload, given)
	if err != nil {
		return "", fmt.Errorf("digitalcredential: %w", err)
	}

	// Keyed by the 43-character digest: many paths can name one large
	// ancestor, and keying by Encoded would hash all of it once per path.
	keep := map[string]sdjwt.Disclosure{}
	for i, p := range reveal {
		ds, ok := r.Disclosures(p)
		if !ok {
			return "", fmt.Errorf("%w: digitalcredential: reveal[%d] %s is not a claim of the credential", jose.ErrInvalidArgument, i, p)
		}
		for _, d := range ds {
			keep[d.Digest] = d
		}
	}
	// Recreate refuses a disclosure given twice, so each one has one position.
	pos := make(map[string]int, len(given))
	for i, d := range given {
		pos[d.Encoded] = i
	}
	send := make([]bool, len(given))
	for _, d := range keep {
		send[pos[d.Encoded]] = true
	}
	sent := make([]sdjwt.Disclosure, 0, len(keep))
	for i, d := range given {
		if send[i] {
			sent = append(sent, d)
		}
	}
	sdJWT := compactSDJWT(issuerJWT, sent)
	if kb == nil {
		return sdJWT, nil
	}

	// holderKey describes the credential; the request and the next step are
	// Present's to name.
	// draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3: cnf and its sub-claims MUST NOT
	// be in a Disclosure. When holderKey finds no cnf, or a cnf with no jwk,
	// in the payload, Recreate has one only if a Disclosure carried it.
	holder, err := holderKey(payload)
	switch {
	case errors.Is(err, errNoCnf):
		if _, concealed := r.Disclosures(sdjwt.Path{"cnf"}); concealed {
			return "", fmt.Errorf("%w: digitalcredential: the credential's cnf claim is in a Disclosure, which draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 forbids, so it cannot carry a Key Binding JWT and the Issuer must reissue it with cnf in the Issuer-signed JWT", jose.ErrMalformed)
		}
		return "", fmt.Errorf("%w: digitalcredential: kb given, but the credential has no cnf claim: it binds no Holder key, so it cannot carry a Key Binding JWT; call Present with kb nil", jose.ErrInvalidArgument)
	case errors.Is(err, jwk.ErrUnsupportedKey):
		return "", fmt.Errorf("%w; call Present with kb nil, or use a library that supports this key", err)
	case errors.Is(err, ErrKeyBindingUnsupported):
		if _, concealed := r.Disclosures(sdjwt.Path{"cnf", "jwk"}); concealed {
			return "", fmt.Errorf("%w: digitalcredential: the credential's cnf.jwk is in a Disclosure, which draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 forbids for cnf and its sub-claims, so it cannot carry a Key Binding JWT and the Issuer must reissue it with cnf.jwk in the Issuer-signed JWT", jose.ErrMalformed)
		}
		return "", fmt.Errorf("%w; call Present with kb nil, or use a library that supports this cnf", err)
	case err != nil:
		return "", err
	}
	binding, err := sdjwt.NewKBJWT(kb.Signer, holder, sdjwt.KBClaims{
		Audience: kb.Audience,
		Nonce:    kb.Nonce,
		IssuedAt: kb.IssuedAt,
		SDHash:   sdjwt.SDHash(sdJWT),
	})
	if err != nil {
		return "", fmt.Errorf("digitalcredential: %w", err)
	}
	return sdJWT + binding, nil
}

// readCompact splits an SD-JWT or SD-JWT+KB (RFC 9901 §4) and decodes the
// payload of its Issuer-signed JWT, which it does not verify. It is this
// package's one reader of the compact form. Every error wraps
// jose.ErrMalformed, except jws.ErrUnsupportedHeader for an Issuer-signed JWT
// whose header has crit or b64.
func readCompact(compact string) (issuerJWT string, disclosures []string, kbJWT string, payload map[string]any, err error) {
	issuerJWT, disclosures, kbJWT, err = sdjwt.Split(compact)
	if err != nil {
		return "", nil, "", nil, fmt.Errorf("digitalcredential: %w", err)
	}
	raw, err := jws.UnverifiedPayload(issuerJWT)
	if err == nil {
		payload, err = jose.DecodeJSONObject(raw)
	}
	if err != nil {
		return "", nil, "", nil, fmt.Errorf("digitalcredential: Issuer-signed JWT: %w", err)
	}
	return issuerJWT, disclosures, kbJWT, payload, nil
}

// errNoCnf: the Issuer-signed JWT has no cnf claim. Whether that is an error,
// and whose, depends on the request and on the Disclosures, which holderKey
// does not see, so it carries no sentinel.
var errNoCnf = errors.New("digitalcredential: the Issuer-signed JWT has no cnf claim")

// holderKey reads the Holder's public key from cnf.jwk of an Issuer-signed
// JWT payload (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3, RFC 7800 §3.2). It is
// this package's one reader of cnf.jwk, and its errors describe the
// credential, not a request: no cnf in the payload is errNoCnf; a cnf with
// more than one of jwk, jwe and jku is jose.ErrMalformed; a cnf without jwk,
// or a cnf.jwk of a key type jose/jwk does not convert, is
// ErrKeyBindingUnsupported; a cnf or jwk that is not an object, a symmetric
// jwk, or a key jwk.ToPublicKey refuses as broken is jose.ErrMalformed and
// jwk.ErrBadKey.
func holderKey(payload map[string]any) (*ecdsa.PublicKey, error) {
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
			return nil, fmt.Errorf("%w: digitalcredential: the credential's cnf has more than one of jwk, jwe and jku, and RFC 7800 §3.1 allows one, so the Issuer must reissue it", jose.ErrMalformed)
		}
		if _, ok := obj["jwk"]; !ok {
			return nil, fmt.Errorf("%w: its cnf has no jwk member, and this SDK binds only to cnf.jwk holding an EC P-256 or secp256k1 key", ErrKeyBindingUnsupported)
		}
	}
	m, ok := obj["jwk"].(map[string]any) // obj is nil when cnf is not an object
	if !ok {
		return nil, fmt.Errorf("%w: digitalcredential: the credential's cnf or cnf.jwk is not a JSON object (RFC 7800 §3, §3.2), so the Issuer must reissue it: %w", jose.ErrMalformed, jwk.ErrBadKey)
	}
	// RFC 7800 §3.2: a symmetric key goes in jwk only when the JWT is
	// encrypted, and the Issuer-signed JWT of an SD-JWT is a JWS.
	if kty, _ := m["kty"].(string); kty == "oct" {
		return nil, fmt.Errorf("%w: digitalcredential: the credential's cnf.jwk is a symmetric key in a JWT that is not encrypted (RFC 7800 §3.2), so the Issuer must reissue it: %w", jose.ErrMalformed, jwk.ErrBadKey)
	}
	key, err := jwk.ToPublicKey(m)
	if errors.Is(err, jwk.ErrUnsupportedKey) {
		return nil, fmt.Errorf("%w: its cnf.jwk holds a key type this SDK does not bind (%w)", ErrKeyBindingUnsupported, err)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: digitalcredential: the credential's cnf.jwk is not a usable key, so the Issuer must reissue it: %w", jose.ErrMalformed, err)
	}
	return key, nil
}
