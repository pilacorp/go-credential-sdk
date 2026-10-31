// Issuing an SD-JWT VC: draft-ietf-oauth-sd-jwt-vc-19 §2.2, the SD-JWT and its
// claims on the Issuer side; RFC 9901 §4, §4.2.

package dc

import (
	"context"
	"crypto"
	"fmt"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/sri"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuerkey"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/statuslist"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/typemeta"
	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jwk"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
	"github.com/pilacorp/go-credential-sdk/jose/jwt"
	"github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

// requestClaims are the claims an IssueRequest field writes. Claims may hold
// one only while set reports the field unset, so each claim has one source.
// fieldOnly claims, iss and vct, never go in Claims: their string fields
// write every value the standard allows. The fixed order makes the error
// deterministic when Claims holds several.
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

// IssueRequest is the content of one SD-JWT VC. Issue writes the values as
// given and checks only what the standard requires of the Issuer: VCT set,
// aka_vcts (draft 19 §2.2.2.2), vct#integrity as integrity metadata (§6),
// iat, nbf and exp as NumericDate (RFC 7519 §4.1.4-4.1.6), Status as
// statuslist.Ref.Validate checks it, iss or sub beside cnf (RFC 7800 §3),
// the claim metadata of TypeMetadata (§5.6), and the structure it
// builds itself: the eight claims draft 19 §2.2.2.3 never conceals and the
// claims the fields below set.
type IssueRequest struct {
	// Issuer is iss (draft 19 §2.2.2.3: OPTIONAL); "" writes none. It is not
	// checked as a URL: only an issuer that publishes Issuer Metadata needs
	// an https iss (draft 19 §4).
	Issuer string
	// VCT is vct, required (draft 19 §2.2.2.3); its value rules (§2.2.2.1)
	// are the Issuer's to keep.
	VCT string
	// IssuedAt is iat; zero writes none. It is the one field claim that may
	// be concealed, with Disclose {"iat"} (draft 19 §2.2.2.3).
	IssuedAt time.Time
	// NotBefore is nbf; zero writes none.
	NotBefore time.Time
	// Expiry is exp; zero writes none. The three times are written in whole
	// seconds, the fraction dropped, and in no required order (RFC 7519
	// §4.1.4-4.1.6 set none). A time with a fraction goes in Claims, with its
	// field zero.
	Expiry time.Time
	// HolderKey is written as cnf.jwk (RFC 7800 §3.2); nil writes no cnf. A
	// key jwk.FromPublicKey refuses gives its error unchanged.
	HolderKey crypto.PublicKey
	// Status is written as status.status_list {"idx", "uri"}
	// (draft-ietf-oauth-status-list-21 §6.2), the Referenced Token's entry in
	// the issuer's Status List; nil writes no status. It must pass
	// statuslist.Ref.Validate. Another status mechanism goes in Claims, with
	// Status nil.
	Status *statuslist.Ref
	// Claims holds every other claim, sub, vct#integrity and aka_vcts
	// included. Issue reads it through jose.EncodeJSON, so any value
	// encoding/json encodes may be given, and never modifies it. It must not
	// hold iss or vct, nor a claim whose field above is set (status for
	// Status). With its field
	// unset it may hold iat, nbf or exp as any NumericDate (RFC 7519 §2), a
	// fraction included, or cnf in any form RFC 7800 defines (draft 19
	// §2.2.2.3 only RECOMMENDS jwk). aka_vcts must be a non-empty array of
	// non-empty strings without the value of VCT (draft 19 §2.2.2.2).
	// vct#integrity must be integrity metadata whose tokens are sha256,
	// sha384 or sha512 hash expressions (§6, W3C SRI §3.5): take it from
	// typemeta.Encoded.Integrity of the published document. An empty value
	// fits that syntax and is signed, but every Verifier refuses it (§6).
	Claims map[string]any
	// Disclose lists the claims to conceal, in any order (sdjwt.Conceal). A
	// path must not start at one of the eight claims draft 19 §2.2.2.3
	// forbids concealing: iss, nbf, exp, cnf, vct, vct#integrity, aka_vcts
	// and status.
	Disclose []sdjwt.Path
	// MinDigests is sdjwt.ConcealOptions.MinDigests: decoy digests pad every
	// object and array of the concealable claims, and the top level, up to
	// this count. It must be 0 when Disclose is empty (draft 19 §2.2.2.5).
	MinDigests int
	// TypeMetadata, when set, is the Type Metadata of VCT, made by
	// typemeta.Load. Issue then checks the payload against its claim
	// metadata before concealing anything (ValidateIssuance, §5.6), and adds
	// no decoy to any array, since §5.6 counts array elements as issued and
	// a decoy would move every index after it. Its VCT() must equal VCT; with
	// vct#integrity in Claims, the document it was loaded from must match
	// it, so the hash written is that of the metadata checked. nil checks
	// nothing.
	TypeMetadata *typemeta.Metadata
}

// issuance is what IssueRequest.prepare builds: the payload to sign and the
// disclosures that follow the Issuer-signed JWT.
type issuance struct {
	payload     map[string]any
	disclosures []sdjwt.Disclosure
}

// Validate runs exactly the checks of Issue on req, and builds the payload as
// Issue does, without signing: it returns the error Issue would return for
// req, except the errors of signing (jws.Sign) and of a nil ctx. An Issuer
// whose signer is a remote service (KMS, HSM) calls it first, so that a bad
// request costs no signing call. Issue runs the same checks whether or not
// Validate was called.
func (req IssueRequest) Validate() error {
	_, err := req.prepare()
	return err
}

// Issue signs an SD-JWT VC (draft 19) with key and returns it. Its
// Serialize() is <Issuer-signed JWT>~<D1>~…~<Dn>~, ending in "~" even with no
// disclosure (RFC 9901 §4). The header is {"alg", "typ": "dc+sd-jwt", "kid"}:
// alg is key.Signer's, which jws.Sign checks against key.Public, and kid is
// written only when key.KID is set.
//
// iat and the claims of Claims go through sdjwt.Conceal, except the eight
// draft 19 §2.2.2.3 forbids disclosing. Those, iss and vct among them, are
// added after it, so they are neither concealed nor padded with decoys: draft
// 19 §5.6 counts an undisclosed array element as concealable, and a Verifier
// cannot tell a decoy from one. Two calls with one request give different
// credentials (new salts and decoys, and the signer's own randomness).
//
// Issue sets no size or depth limit of its own, since RFC 9901 and draft 19
// set none: it can sign a credential over 1 MiB, or nested 33 to 64 levels
// deep, that every reader on this SDK refuses (sdjwt.Split, sdjwt.Recreate).
//
// Errors, checked before key.Signer is called:
//   - a nil ctx, or a request breaking the rules of IssueRequest:
//     jose.ErrInvalidArgument naming the field; sdjwt.Conceal errors, all
//     jose.ErrInvalidArgument, wrapped unchanged;
//   - a payload breaking the claim metadata of TypeMetadata:
//     jose.ErrInvalidArgument also wrapping typemeta.ErrViolated, or
//     typemeta.ErrClaims when the check reads over the SDK's limit;
//   - a HolderKey jwk.FromPublicKey refuses: its error unchanged,
//     jose.ErrUnsupportedKey or jwk.ErrBadKey;
//   - jws.Sign errors unchanged: jose.ErrUnsupportedKey or jws.ErrBadKey for
//     key.Public, jose.ErrUnsupportedAlg or jws.ErrAlgKeyMismatch for
//     key.Signer's alg, jose.ErrInvalidArgument for a nil key.Signer;
//
// and after it: jws.ErrSignerFailed wrapping the signer's error, so a ctx
// that ends inside the signer matches context.Canceled or
// context.DeadlineExceeded too, and jws.ErrSelfCheck when the signer holds
// another key or answers in another format (a 65-byte r||s||v of an Ethereum
// signer must be cut to its first 64 bytes by a wrapper).
func Issue(ctx context.Context, req IssueRequest, key issuerkey.SigningKey) (*Credential, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: dc: Issue: nil context", jose.ErrInvalidArgument)
	}
	is, err := req.prepare()
	if err != nil {
		return nil, err
	}
	body, err := jose.EncodeJSON(is.payload)
	if err != nil {
		return nil, fmt.Errorf("dc: payload: %w", err)
	}
	header := jws.Header{"typ": typDCSDJWT}
	if key.KID != "" {
		header["kid"] = key.KID
	}
	token, err := jws.Sign(ctx, key.Signer, key.Public, header, body)
	if err != nil {
		return nil, fmt.Errorf("dc: %w", err)
	}
	return &Credential{compact: compactSDJWT(token, is.disclosures)}, nil
}

// prepare checks req (REQ-21) and builds the payload and the disclosures
// (REQ-22); Validate and Issue share it so that the two cannot drift apart.
func (req IssueRequest) prepare() (issuance, error) {
	claims, err := copyClaims(req.Claims)
	if err != nil {
		return issuance{}, err
	}
	if err := req.check(claims); err != nil {
		return issuance{}, err
	}

	if req.HolderKey != nil {
		holder, err := jwk.FromPublicKey(req.HolderKey)
		if err != nil {
			return issuance{}, fmt.Errorf("dc: HolderKey: %w", err)
		}
		claims["cnf"] = map[string]any{"jwk": holder}
	}
	if req.Status != nil {
		claims["status"] = map[string]any{"status_list": map[string]any{"idx": req.Status.Index, "uri": req.Status.URI}}
	}
	putTime(claims, "iat", req.IssuedAt)
	if req.Issuer != "" {
		claims["iss"] = req.Issuer
	}
	claims["vct"] = req.VCT
	putTime(claims, "nbf", req.NotBefore)
	putTime(claims, "exp", req.Expiry)
	// Every claim to be signed is in place and none is concealed yet.
	if req.TypeMetadata != nil {
		if err := req.TypeMetadata.ValidateIssuance(claims, req.Disclose); err != nil {
			return issuance{}, fmt.Errorf("%w: dc: TypeMetadata: %w", jose.ErrInvalidArgument, err)
		}
	}

	// The eight claims go apart, so that Conceal neither conceals them nor
	// pads them with decoys, then come back after it.
	plain := map[string]any{}
	for name, v := range claims {
		if neverDisclosable[name] {
			plain[name] = v
			delete(claims, name)
		}
	}
	payload, disclosures, err := sdjwt.Conceal(claims, req.Disclose, sdjwt.ConcealOptions{
		MinDigests:    req.MinDigests,
		NoArrayDecoys: req.TypeMetadata != nil,
	})
	if err != nil {
		return issuance{}, fmt.Errorf("dc: %w", err)
	}
	// Through Conceal with no path and no decoy, so the reserved names _sd,
	// _sd_alg and ... are refused in the eight claims as in the rest (RFC 9901
	// §4.1 rule 7, §4.1.1).
	plainPayload, _, err := sdjwt.Conceal(plain, nil, sdjwt.ConcealOptions{})
	if err != nil {
		return issuance{}, fmt.Errorf("dc: %w", err)
	}
	for name, v := range plainPayload {
		payload[name] = v
	}
	return issuance{payload: payload, disclosures: disclosures}, nil
}

// copyClaims returns Claims as jose.DecodeJSONObject reads it from its JSON,
// so every later step sees objects as map[string]any, arrays as []any and
// numbers as json.Number, whatever Go types the caller used, and req.Claims
// is never modified. nil gives an empty object.
func copyClaims(c map[string]any) (map[string]any, error) {
	if c == nil {
		return map[string]any{}, nil
	}
	b, err := jose.EncodeJSON(c)
	if err != nil {
		return nil, fmt.Errorf("dc: Claims: %w", err)
	}
	m, err := jose.DecodeJSONObject(b)
	if err != nil {
		// Duplicate keys or depth over jose.MaxJSONDepth in what the caller
		// gave: a mistake of the request, not a malformed token.
		return nil, fmt.Errorf("%w: dc: Claims: %v", jose.ErrInvalidArgument, err)
	}
	return m, nil
}

// check applies the rules of IssueRequest to req, claims being its Claims as
// copyClaims returns them, in the order of REQ-21.
func (req IssueRequest) check(claims map[string]any) error {
	if req.VCT == "" {
		return fmt.Errorf("%w: dc: VCT is required (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3)", jose.ErrInvalidArgument)
	}
	for _, c := range requestClaims {
		if _, ok := claims[c.name]; !ok {
			continue
		}
		if c.fieldOnly {
			return fmt.Errorf("%w: dc: Claims holds %q, which only IssueRequest.%s may set", jose.ErrInvalidArgument, c.name, c.field)
		}
		if c.set(req) {
			return fmt.Errorf("%w: dc: Claims holds %q and IssueRequest.%s is set; give it in one place", jose.ErrInvalidArgument, c.name, c.field)
		}
	}
	// A Verifier refuses exp and nbf of another type (jwt.CheckExpNbf), and
	// iat is a NumericDate too (RFC 7519 §4.1.4-4.1.6).
	for _, name := range []string{"iat", "nbf", "exp"} {
		if v, ok := claims[name]; ok {
			if _, err := jwt.NumericDate(v); err != nil {
				return fmt.Errorf("%w: dc: Claims %q is not a NumericDate (RFC 7519 §2); give a number of seconds, or set the field", jose.ErrInvalidArgument, name)
			}
		}
	}
	if v, ok := claims["aka_vcts"]; ok {
		if err := checkAkaVCTs(v, req.VCT); err != nil {
			return fmt.Errorf("%w: dc: Claims aka_vcts %v (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.2)", jose.ErrInvalidArgument, err)
		}
	}
	if v, ok := claims["vct#integrity"]; ok {
		if s, _ := v.(string); !sri.WellFormed(s) {
			return fmt.Errorf("%w: dc: Claims vct#integrity is not integrity metadata (sha256-, sha384- or sha512- and base64, tokens separated by spaces; W3C SRI §3.5, draft-ietf-oauth-sd-jwt-vc-19 §5.3); take it from typemeta.Encoded.Integrity", jose.ErrInvalidArgument)
		}
	}
	if req.Status != nil {
		if err := req.Status.Validate(); err != nil {
			return fmt.Errorf("dc: Status: %w", err)
		}
	}
	for i, p := range req.Disclose {
		// An empty path or one starting with an index is Conceal's to refuse.
		if len(p) == 0 {
			continue
		}
		if name, _ := p[0].(string); neverDisclosable[name] {
			return fmt.Errorf("%w: dc: Disclose[%d] %s: draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 forbids concealing %s", jose.ErrInvalidArgument, i, p, name)
		}
	}
	// draft 19 §2.2.2.5: with no selectively disclosable claim the credential
	// MUST NOT contain _sd, and decoys alone would add one.
	if len(req.Disclose) == 0 && req.MinDigests > 0 {
		return fmt.Errorf("%w: dc: MinDigests %d with no Disclose path: draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.5 forbids _sd when no claim is selectively disclosable", jose.ErrInvalidArgument, req.MinDigests)
	}
	if m := req.TypeMetadata; m != nil {
		// The zero Metadata has VCT() "" and VCT is not empty here.
		if m.VCT() != req.VCT {
			return fmt.Errorf("%w: dc: TypeMetadata is not the Type Metadata of VCT made by typemeta.Load", jose.ErrInvalidArgument)
		}
		if s, ok := claims["vct#integrity"].(string); ok {
			if err := typemeta.CheckIntegrity(m.Documents()[0], s); err != nil {
				return fmt.Errorf("%w: dc: Claims vct#integrity does not match the document TypeMetadata was loaded from (draft-ietf-oauth-sd-jwt-vc-19 §6): %v", jose.ErrInvalidArgument, err)
			}
		}
	}
	// RFC 7800 §3: "At least one of the sub and iss claims MUST be present"
	// beside cnf. draft-ietf-oauth-sd-jwt-vc-20 §2.2.2.3 lifts this; drop the
	// check when the pin moves past draft 19.
	if _, hasCnf := claims["cnf"]; hasCnf || req.HolderKey != nil {
		if _, hasSub := claims["sub"]; !hasSub && req.Issuer == "" {
			return fmt.Errorf("%w: dc: a credential with cnf needs iss or sub (RFC 7800 §3); set Issuer, or sub in Claims", jose.ErrInvalidArgument)
		}
	}
	return nil
}

// checkAkaVCTs: draft 19 §2.2.2.2, aka_vcts MUST be a non-empty array of
// strings and MUST NOT contain the value of vct, compared exactly. An empty
// string identifies no type (§2.2.2.1). That each is a Collision-Resistant
// Name is the Issuer's to keep. v is a value as copyClaims returns it.
func checkAkaVCTs(v any, vct string) error {
	a, ok := v.([]any)
	if !ok {
		return fmt.Errorf("is not an array")
	}
	if len(a) == 0 {
		return fmt.Errorf("is empty")
	}
	for i, e := range a {
		s, ok := e.(string)
		switch {
		case !ok:
			return fmt.Errorf("element %d is not a string", i)
		case s == "":
			return fmt.Errorf("element %d is empty", i)
		case s == vct:
			return fmt.Errorf("element %d is the value of VCT", i)
		}
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
