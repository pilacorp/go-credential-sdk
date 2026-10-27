// Issuing an SD-JWT VC: draft-ietf-oauth-sd-jwt-vc-19 §2.2, the SD-JWT
// component and its claims, on the issuer side.

package digitalcredential

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/statuslist"
	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jwk"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
	"github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

// typDCSDJWT: draft 19 §2.2.1, the typ header MUST be dc+sd-jwt.
const typDCSDJWT = "dc+sd-jwt"

// requestClaims are the claims an IssueRequest field writes. Claims may hold
// one only while set reports the field unset, so each claim has one source
// and Claims carries the forms the field cannot write. fieldOnly claims, iss
// and vct, never go in Claims: their string fields write every value the
// standards allow. The fixed order makes the error deterministic when Claims
// holds several.
var requestClaims = []struct {
	name, field string
	fieldOnly   bool
	set         func(IssueRequest) bool
}{
	{"iss", "Issuer", true, nil},
	{"vct", "VCT", true, nil},
	{"iat", "IssuedAt", false, func(r IssueRequest) bool { return !r.IssuedAt.IsZero() }},
	{"nbf", "NotBefore", false, func(r IssueRequest) bool { return !r.NotBefore.IsZero() }},
	{"exp", "Expiry", false, func(r IssueRequest) bool { return !r.Expiry.IsZero() }},
	{"cnf", "HolderKey", false, func(r IssueRequest) bool { return r.HolderKey != nil }},
	{"status", "Status", false, func(r IssueRequest) bool { return r.Status != nil }},
}

// neverDisclosable: draft 19 §2.2.2.3, these claims, including any of their
// sub-claims, MUST NOT be included in Disclosures. All are top-level claims,
// so a path is refused by its first element.
var neverDisclosable = map[string]bool{
	"iss":           true,
	"nbf":           true,
	"exp":           true,
	"cnf":           true,
	"vct":           true,
	"vct#integrity": true,
	"aka_vcts":      true,
	"status":        true,
}

// IssueRequest is the content of one SD-JWT VC. Issue writes the values as
// given. It checks that VCT is set, aka_vcts in Claims (draft 19 §2.2.2.2),
// Status with statuslist.Ref.Validate, and the structure it builds itself:
// the never-disclosable claims and the claims the fields below set.
type IssueRequest struct {
	// Issuer is iss (draft 19 §2.2.2.3: OPTIONAL); empty writes none.
	Issuer string
	// VCT is vct, required (draft 19 §2.2.2.3); its value rules are §2.2.2.1.
	VCT string
	// IssuedAt is iat; zero writes none. It may be concealed with Disclose
	// {"iat"} (draft 19 §2.2.2.3).
	IssuedAt time.Time
	// NotBefore is nbf; zero writes none.
	NotBefore time.Time
	// Expiry is exp; zero writes none. The three times are written in whole
	// seconds, the fraction dropped, and in no required order (RFC 7519
	// §4.1.4-4.1.6 define none). A time with a fraction goes in Claims, with
	// its field zero.
	Expiry time.Time
	// HolderKey is written as cnf.jwk (RFC 7800 §3.2), on P-256 or secp256k1;
	// nil writes no cnf.
	HolderKey *ecdsa.PublicKey
	// Status is written as status.status_list {idx, uri}
	// (draft-ietf-oauth-status-list-21 §6.2); nil writes no status. Issue
	// refuses what statuslist.Ref.Validate refuses (status-list-21 §6.2).
	Status *statuslist.Ref
	// Claims holds every other claim, sub, vct#integrity and aka_vcts
	// included; it is never modified. It must not hold iss or vct, nor a
	// claim whose field above is set. With its field unset it may hold iat,
	// nbf or exp as any NumericDate (RFC 7519 §2, a fraction included), cnf
	// in any form RFC 7800 defines (draft 19 §2.2.2.3 only RECOMMENDS jwk),
	// or status with any mechanism (draft-ietf-oauth-status-list-21 §6.2);
	// Issue does not check their values, which are the issuer's. aka_vcts,
	// given as []string or []any, must be a non-empty array of strings
	// without the value of VCT (draft 19 §2.2.2.2).
	Claims map[string]any
	// Disclose lists the claims to conceal, in any order. A path must not
	// start at a claim draft 19 §2.2.2.3 forbids concealing: iss, nbf, exp,
	// cnf, vct, vct#integrity, aka_vcts or status.
	Disclose []sdjwt.Path
	// MinDigests is sdjwt.ConcealOptions.MinDigests: decoy digests pad every
	// object and array of Claims, and the top level, up to this count. It
	// must be 0 when Disclose is empty (draft 19 §2.2.2.5).
	MinDigests int
}

// Issue signs an SD-JWT VC (draft 19) with key and returns it in compact form,
// <Issuer-signed JWT>~<D1>~…~<Dn>~, ending in "~" even with no disclosure.
// The header is {"alg", "typ": "dc+sd-jwt", "kid"}: alg comes from the curve
// of key.Public (jws.Sign), kid only when key.KID is set. iat and the claims
// of Claims go through sdjwt.Conceal, except those draft 19 §2.2.2.3 forbids
// disclosing (nbf, exp, vct#integrity, aka_vcts, cnf, status). Those, iss
// and vct are added after it, so they are neither concealed nor padded with
// decoys: draft 19 §5.6 counts an undisclosed array element as selectively
// disclosable, and a verifier cannot tell a decoy from one. Two calls with
// one request may return different credentials (new salts and decoys, and
// the signer's own randomness).
//
// Work and output grow with (the objects and arrays in Claims, plus the top
// level) × MinDigests. Issue sets no size or depth limit (RFC 9901 and draft
// 19 set none), but holders and verifiers built on this SDK refuse an SD-JWT
// over 1 MiB (sdjwt.Split), with more than 1000 disclosures (sdjwt.Split,
// sdjwt.Recreate), or nested deeper than 32 levels, the payload counted
// (sdjwt.Recreate). Issue can sign the first and the last: Claims may nest up
// to jose.MaxJSONDepth (64) levels, so a credential nested 33 to 64 deep is
// signed and then refused by every reader on this SDK. sdjwt.Conceal takes at
// most 1000 paths, one disclosure each, so the second is never reached.
//
// Errors: a request breaking the rules of IssueRequest is
// jose.ErrInvalidArgument naming the field, a Status failing Validate
// included; a HolderKey jose/jwk refuses is jwk.ErrBadKey. sdjwt.Conceal
// errors (all jose.ErrInvalidArgument) and jws.Sign errors (jws.ErrBadKey for
// key.Public, jose.ErrInvalidArgument for a nil key.Signer, jws.ErrSigner,
// and jws.ErrSelfCheck when the signer holds another key) are wrapped
// unchanged.
func Issue(req IssueRequest, key statuslist.SigningKey) (string, error) {
	if err := checkRequest(req); err != nil {
		return "", err
	}
	var cnf map[string]any
	if req.HolderKey != nil {
		holder, err := jwk.FromPublicKey(req.HolderKey)
		if err != nil {
			return "", fmt.Errorf("digitalcredential: HolderKey: %w", err)
		}
		cnf = map[string]any{"jwk": holder}
	}

	// Shallow copies, so req.Claims is never modified: the never-disclosable
	// claims go apart, and iat, which may be concealed, joins the rest.
	claims := make(map[string]any, len(req.Claims)+1)
	plain := map[string]any{}
	for name, v := range req.Claims {
		if neverDisclosable[name] {
			plain[name] = v
		} else {
			claims[name] = v
		}
	}
	putTime(claims, "iat", req.IssuedAt)
	payload, disclosures, err := sdjwt.Conceal(claims, req.Disclose, sdjwt.ConcealOptions{MinDigests: req.MinDigests})
	if err != nil {
		return "", fmt.Errorf("digitalcredential: %w", err)
	}
	// Through Conceal with no path and no decoy: a copy, nested at most
	// jose.MaxJSONDepth, with the reserved names checked as for the rest
	// (RFC 9901 §4.1 rule 7).
	plainPayload, _, err := sdjwt.Conceal(plain, nil, sdjwt.ConcealOptions{})
	if err != nil {
		return "", fmt.Errorf("digitalcredential: %w", err)
	}
	for name, v := range plainPayload {
		payload[name] = v
	}
	if req.Issuer != "" {
		payload["iss"] = req.Issuer
	}
	payload["vct"] = req.VCT
	putTime(payload, "nbf", req.NotBefore)
	putTime(payload, "exp", req.Expiry)
	if cnf != nil {
		payload["cnf"] = cnf
	}
	if req.Status != nil {
		payload["status"] = map[string]any{
			"status_list": map[string]any{"idx": req.Status.Index, "uri": req.Status.URI},
		}
	}

	body, err := jose.EncodeJSON(payload)
	if err != nil {
		return "", fmt.Errorf("digitalcredential: payload: %w", err)
	}
	header := jws.Header{"typ": typDCSDJWT}
	if key.KID != "" {
		header["kid"] = key.KID
	}
	token, err := jws.Sign(key.Signer, key.Public, header, body)
	if err != nil {
		return "", fmt.Errorf("digitalcredential: %w", err)
	}

	return compactSDJWT(token, disclosures), nil
}

// checkRequest applies the rules of IssueRequest that sdjwt.Conceal and
// jws.Sign do not.
func checkRequest(req IssueRequest) error {
	if req.VCT == "" {
		return fmt.Errorf("%w: digitalcredential: VCT is required", jose.ErrInvalidArgument)
	}
	for _, c := range requestClaims {
		if _, ok := req.Claims[c.name]; !ok {
			continue
		}
		if c.fieldOnly {
			return fmt.Errorf("%w: digitalcredential: Claims holds %q, which only IssueRequest.%s may set", jose.ErrInvalidArgument, c.name, c.field)
		}
		if c.set(req) {
			return fmt.Errorf("%w: digitalcredential: Claims holds %q and IssueRequest.%s is set; give it in one place", jose.ErrInvalidArgument, c.name, c.field)
		}
	}
	if v, ok := req.Claims["aka_vcts"]; ok {
		if err := checkAkaVCTs(v, req.VCT); err != nil {
			return fmt.Errorf("%w: digitalcredential: Claims aka_vcts %v (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.2)", jose.ErrInvalidArgument, err)
		}
	}
	if req.Status != nil {
		if err := req.Status.Validate(); err != nil {
			return fmt.Errorf("digitalcredential: Status: %w", err)
		}
	}
	for _, p := range req.Disclose {
		// An empty path or one starting with an index is Conceal's to refuse.
		if len(p) == 0 {
			continue
		}
		if name, _ := p[0].(string); neverDisclosable[name] {
			return fmt.Errorf("%w: digitalcredential: Disclose path %s: draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 forbids concealing %s", jose.ErrInvalidArgument, p, name)
		}
	}
	// draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.5: with no selectively disclosable
	// claim the credential MUST NOT contain _sd, and decoys alone would add one.
	if len(req.Disclose) == 0 && req.MinDigests > 0 {
		return fmt.Errorf("%w: digitalcredential: MinDigests %d with no Disclose path: draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.5 forbids _sd when no claim is selectively disclosable", jose.ErrInvalidArgument, req.MinDigests)
	}
	return nil
}

// checkAkaVCTs: draft 19 §2.2.2.2, aka_vcts MUST be a non-empty array of
// strings and MUST NOT contain the value of vct, compared exactly (the
// strings are case-sensitive). That each is a Collision-Resistant Name is
// the issuer's to keep; no syntax rule can tell.
func checkAkaVCTs(v any, vct string) error {
	var types []string
	switch a := v.(type) {
	case []string:
		types = a
	case []any:
		for _, e := range a {
			s, ok := e.(string)
			if !ok {
				return fmt.Errorf("holds a %T, not a string", e)
			}
			types = append(types, s)
		}
	default:
		return fmt.Errorf("is a %T, not an array of strings", v)
	}
	if len(types) == 0 {
		return errors.New("is empty")
	}
	if slices.Contains(types, vct) {
		return fmt.Errorf("holds the vct %q", vct)
	}
	return nil
}

// putTime writes t as a NumericDate (RFC 7519 §2) in whole seconds, the
// fraction dropped, unless t is zero.
func putTime(claims map[string]any, name string, t time.Time) {
	if !t.IsZero() {
		claims[name] = t.Unix()
	}
}
