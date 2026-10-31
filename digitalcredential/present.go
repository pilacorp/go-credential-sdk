// Presenting an SD-JWT VC on the Holder side: RFC 9901 §7.2 (selection §4,
// §4.2.6; Key Binding JWT §4.3, §4.3.1), claims path pointers of OpenID4VP
// 1.0 §7.1.1, and draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 (cnf).

package dc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
	"github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

// PresentRequest says what Credential.Present sends to a Verifier.
type PresentRequest struct {
	// Reveal lists claims path pointers (OpenID4VP 1.0 §7.1.1) to the claims
	// to disclose: a string selects an object key, a non-negative int an
	// array index, and nil every element of an array. Paths point into the
	// claims recreated from every disclosure the credential holds. Empty
	// sends no disclosure. A pointer decoded from JSON holds float64 indices
	// (encoding/json) or json.Number (UseNumber); convert them to int.
	Reveal []sdjwt.Path
	// KeyBinding asks for a Key Binding JWT (RFC 9901 §4.3); nil sends none.
	KeyBinding *KeyBinding
}

// KeyBinding is the content of a Key Binding JWT (RFC 9901 §4.3). Every field
// but Claims is required. Signer must hold the private key of the
// credential's cnf.jwk (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3); that key
// decides the alg.
type KeyBinding struct {
	Signer   jws.Signer
	Audience string    // aud: the Verifier the presentation is for
	Nonce    string    // nonce: from the Verifier, for this transaction
	IssuedAt time.Time // iat: when the Key Binding JWT is issued, in whole seconds
	// Claims are other claims of the Key Binding JWT, those a protocol
	// defines, such as transaction_data_hashes of OpenID4VP 1.0 Appendix
	// B.3.3.1; nil writes none. It must not hold iat, aud, nonce or sd_hash
	// (sdjwt.KBClaims.Extra).
	Claims map[string]any
}

// Present builds what a Holder sends to a Verifier (RFC 9901 §7.2): the
// Issuer-signed JWT with the disclosures req.Reveal selects and, when
// req.KeyBinding is set, a Key Binding JWT. The credential itself does not
// change.
//
// Present reads the credential with sdjwt.Split, jws.UnverifiedPayload and
// sdjwt.Recreate, as far as it must to select disclosures. It verifies
// neither the Issuer's signature nor any claim: the Holder checks the
// credential when it receives it (§7.2). Those readers' limits hold, so a
// credential over 1 MiB, with more than 1000 disclosures or nested deeper
// than 32 is refused here, even one Issue signed.
//
// Each path of req.Reveal is resolved as OpenID4VP 1.0 §7.1.1 says: a
// missing key drops that element from the selection and a missing index
// drops that array, while a string meeting a selected element that is not an
// object, a nil or an index meeting one that is not an array, or an empty
// final selection is an error. Each selected element then sends the
// disclosure of that claim, if it is concealed, and those of its concealed
// ancestors (§4.2.6), never a descendant's. An ancestor's disclosure shows
// its whole value except what is concealed inside it, so naming a claim can
// reveal more than that claim. Disclosures go out each once, in the order of
// the credential; §4 sets no order. The work grows with len(req.Reveal)
// times the elements each path selects, so a Holder taking Reveal from a
// Verifier's request bounds the number of paths.
//
// With req.KeyBinding nil there is no Key Binding JWT, even when the
// credential has cnf: whether one is required is the Verifier's decision
// (RFC 9901 §4.3.2; OpenID4VP 1.0 §6.1 require_cryptographic_holder_binding,
// which defaults to true, so a Holder answering OpenID4VP sets KeyBinding
// unless the query says false). Otherwise the key comes from cnf.jwk, the
// form draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 recommends; that it must be
// cnf.jwk with an EC key on P-256 or secp256k1 is this SDK's limit. The key
// is read before the Signer is called, and sd_hash covers exactly the SD-JWT
// returned before the Key Binding JWT (§4.3.1).
//
// Errors:
//   - a nil or zero Credential, or a nil ctx: jose.ErrInvalidArgument;
//   - a credential that is not an SD-JWT (Split, UnverifiedPayload, the
//     payload, Recreate), or one that already has a Key Binding JWT (§7.2: a
//     Holder MUST reject an SD-JWT+KB it receives): jose.ErrMalformed; an
//     Issuer-signed JWT whose header has crit or b64:
//     jws.ErrUnsupportedHeader;
//   - a Reveal path that is not valid or selects no claim:
//     jose.ErrInvalidArgument;
//   - with KeyBinding, a credential with no cnf: jose.ErrInvalidArgument; a
//     cnf this SDK cannot bind (no jwk, or a key type jose/jwk does not
//     convert): ErrKeyBindingUnsupported, the second also
//     jose.ErrUnsupportedKey; a cnf the Issuer got wrong: jose.ErrMalformed,
//     and jwk.ErrBadKey too for a cnf or cnf.jwk that is not an object, a
//     symmetric cnf.jwk or a broken key. Each such error matches exactly one
//     of the three classes;
//   - sdjwt.NewKBJWT errors unchanged: jose.ErrInvalidArgument for an empty
//     KeyBinding field or Claims holding iat, aud, nonce or sd_hash,
//     jws.ErrSignerFailed wrapping the Signer's error, and jws.ErrSelfCheck
//     for a Signer that does not hold the cnf.jwk key.
//
// Present's own error texts hold no disclosure and no claim value. Errors of
// Split, Recreate and jwk.ToPublicKey keep their own text, which can quote
// claim names, digests, the kty or crv of cnf.jwk and the coordinates of an
// EC cnf.jwk off its curve, never a salt or a whole disclosure. Do not forward error text to a Verifier.
func (c *Credential) Present(ctx context.Context, req PresentRequest) (*Credential, error) {
	if c == nil || c.compact == "" {
		return nil, fmt.Errorf("%w: dc: Present on a nil or zero Credential; make one with Parse or Issue", jose.ErrInvalidArgument)
	}
	if ctx == nil {
		return nil, fmt.Errorf("%w: dc: Present: nil context", jose.ErrInvalidArgument)
	}
	issuerJWT, encoded, kbJWT, err := sdjwt.Split(c.compact)
	if err != nil {
		return nil, fmt.Errorf("dc: %w", err)
	}
	if kbJWT != "" {
		return nil, fmt.Errorf("%w: dc: Present takes an SD-JWT, not an SD-JWT+KB (RFC 9901 §7.2)", jose.ErrMalformed)
	}
	raw, err := jws.UnverifiedPayload(issuerJWT)
	if err != nil {
		return nil, fmt.Errorf("dc: Issuer-signed JWT: %w", err)
	}
	payload, err := jose.DecodeJSONObject(raw)
	if err != nil {
		return nil, fmt.Errorf("dc: Issuer-signed JWT payload: %w", err)
	}
	given := make([]sdjwt.Disclosure, len(encoded))
	for i, e := range encoded {
		given[i] = sdjwt.Disclosure{Encoded: e}
	}
	r, err := sdjwt.Recreate(payload, given)
	if err != nil {
		return nil, fmt.Errorf("dc: %w", err)
	}

	// Keyed by digest: many paths can name one large ancestor, and keying by
	// Encoded would hash all of it once per path.
	keep := map[string]string{}
	for i, p := range req.Reveal {
		claims, err := selectClaims(r.Claims, p)
		if err != nil {
			return nil, fmt.Errorf("%w: dc: Reveal[%d] %v", jose.ErrInvalidArgument, i, err)
		}
		for _, cp := range claims {
			ds, ok := r.Disclosures(cp)
			if !ok {
				return nil, fmt.Errorf("%w: dc: Reveal[%d] selects %s, which is not a claim of the credential", jose.ErrInvalidArgument, i, cp)
			}
			for _, d := range ds {
				keep[d.Digest] = d.Encoded
			}
		}
	}
	send := make(map[string]bool, len(keep))
	for _, e := range keep {
		send[e] = true
	}
	// Split refuses a disclosure given twice, so each goes out once, in the
	// order of the credential.
	sent := make([]sdjwt.Disclosure, 0, len(keep))
	for _, e := range encoded {
		if send[e] {
			sent = append(sent, sdjwt.Disclosure{Encoded: e})
		}
	}
	sdJWT := compactSDJWT(issuerJWT, sent)
	kb := req.KeyBinding
	if kb == nil {
		return &Credential{compact: sdJWT}, nil
	}

	holder, err := holderKey(payload, r)
	switch {
	case errors.Is(err, errNoCnf):
		return nil, fmt.Errorf("%w: dc: KeyBinding given, but the credential has no cnf claim: it binds no Holder key, so it cannot carry a Key Binding JWT; call Present with KeyBinding nil", jose.ErrInvalidArgument)
	case errors.Is(err, ErrKeyBindingUnsupported):
		return nil, fmt.Errorf("%w; call Present with KeyBinding nil, or use a library that supports this cnf", err)
	case err != nil:
		return nil, err
	}
	binding, err := sdjwt.NewKBJWT(ctx, kb.Signer, holder, sdjwt.KBClaims{
		Audience: kb.Audience,
		Nonce:    kb.Nonce,
		IssuedAt: kb.IssuedAt,
		SDHash:   sdjwt.SDHash(sdJWT),
		Extra:    kb.Claims,
	})
	if err != nil {
		return nil, fmt.Errorf("dc: %w", err)
	}
	return &Credential{compact: sdJWT + binding}, nil
}

// selected is one element of a claims path selection and the concrete path
// that reaches it.
type selected struct {
	value any
	path  sdjwt.Path
}

// selectClaims resolves the claims path pointer p over claims as OpenID4VP
// 1.0 §7.1.1 says and returns the concrete path of every selected element,
// each holding only strings and ints. The error text names the component at
// fault, never a claim value.
func selectClaims(claims map[string]any, p sdjwt.Path) ([]sdjwt.Path, error) {
	if len(p) == 0 {
		return nil, errors.New("is empty; a claims path pointer has at least one component (OpenID4VP 1.0 §7)")
	}
	sel := []selected{{value: claims, path: sdjwt.Path{}}}
	for i, comp := range p {
		var next []selected
		switch k := comp.(type) {
		case string:
			for _, s := range sel {
				obj, ok := s.value.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("component %d is a key, and %s is not an object", i, where(s.path))
				}
				if v, ok := obj[k]; ok {
					next = append(next, selected{v, appendPath(s.path, k)})
				}
			}
		case nil:
			for _, s := range sel {
				arr, ok := s.value.([]any)
				if !ok {
					return nil, fmt.Errorf("component %d is null, and %s is not an array", i, where(s.path))
				}
				for j, v := range arr {
					next = append(next, selected{v, appendPath(s.path, j)})
				}
			}
		case int:
			if k < 0 {
				return nil, fmt.Errorf("component %d is a negative index", i)
			}
			for _, s := range sel {
				arr, ok := s.value.([]any)
				if !ok {
					return nil, fmt.Errorf("component %d is an index, and %s is not an array", i, where(s.path))
				}
				if k < len(arr) {
					next = append(next, selected{arr[k], appendPath(s.path, k)})
				}
			}
		default:
			return nil, fmt.Errorf("component %d is a %T; a component is a string, a non-negative int or nil", i, comp)
		}
		sel = next
	}
	if len(sel) == 0 {
		return nil, fmt.Errorf("%s selects no claim of the credential", p)
	}
	paths := make([]sdjwt.Path, len(sel))
	for i, s := range sel {
		paths[i] = s.path
	}
	return paths, nil
}

// appendPath returns p with e added, never sharing p's backing array, since
// one selection extends p once per element.
func appendPath(p sdjwt.Path, e any) sdjwt.Path {
	return append(p[:len(p):len(p)], e)
}

// where names the place p points at, for error text.
func where(p sdjwt.Path) string {
	if len(p) == 0 {
		return "the top level"
	}
	return p.String()
}
