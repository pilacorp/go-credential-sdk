// Verifying an SD-JWT VC on the Verifier side: draft-ietf-oauth-sd-jwt-vc-19
// §2.4 (verification), §2.2.2.1-2.2.2.3 (claims) and §2.5 (issuer key); RFC
// 9901 §4, §7.1 (the SD-JWT), §7.3 (Key Binding) and §9.5; RFC 7519
// §4.1.3-4.1.5; draft-ietf-oauth-status-list-21 §6.2, §7.1 and §8.3 (status).

package dc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/jsonint"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuerkey"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/statuslist"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/typemeta"
	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
	"github.com/pilacorp/go-credential-sdk/jose/jwt"
	"github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

// KeyBindingMode says when Verify requires Key Binding. RFC 9901 §7.3 step 1
// leaves it to the Verifier's policy, never to whether a Key Binding JWT came,
// and §9.5 asks for the decision per use case. When Key Binding is required,
// a missing Key Binding JWT is rejected (§7.3 step 2) and the key is the
// credential's cnf (draft-ietf-oauth-sd-jwt-vc-19 §2.4).
type KeyBindingMode uint8

const (
	// KeyBindingIfCnf, the default, requires Key Binding exactly when the
	// credential has cnf, the key it binds; only the presence of cnf is
	// read. A credential without cnf passes with Result.KeyBound false: if
	// your use case requires Key Binding, reject when KeyBound is false, or
	// use KeyBindingRequired.
	KeyBindingIfCnf KeyBindingMode = iota
	// KeyBindingRequired requires Key Binding for every credential, so one
	// without cnf is rejected too, as KB_UNSUPPORTED.
	KeyBindingRequired
	// KeyBindingNotRequired checks no Key Binding JWT: for a Holder checking
	// what it received (RFC 9901 §7.2), or a Verifier that expects an SD-JWT
	// (§4). Both MUST reject one that comes; a Verifier that only does not
	// need it adds WithIgnoreUncheckedKBJWT. cnf stays in Result.Claims as
	// received.
	KeyBindingNotRequired
)

// StatusChecker returns the raw status of the Referenced Token ref points to
// (draft-ietf-oauth-status-list-21 §8), from the Status List Token of iss; a
// *statuslist.Checker is one. Verify reads an error of Status in this order:
//   - one wrapping statuslist.ErrIndexOutOfBounds is MALFORMED (§8.3 step 6:
//     MUST be rejected), whatever ctx says;
//   - when ctx is done, Verify returns an error wrapping ctx.Err();
//   - one wrapping jose.ErrInvalidArgument is ErrPolicy; a statuslist.Checker
//     wraps it also when its resolver returned a key it cannot verify with;
//   - any other is STATUS_UNAVAILABLE.
//
// statuslist.List.Get reports an index outside the list as
// jose.ErrInvalidArgument; a checker built on it compares the index with the
// list size itself and returns ErrIndexOutOfBounds. Status may be called from
// several goroutines at once and should return when ctx is done.
type StatusChecker interface {
	Status(ctx context.Context, ref statuslist.Ref, iss string) (uint8, error)
}

// Result is a credential Verify accepted.
type Result struct {
	// Claims is the processed payload (RFC 9901 §7.1): the Issuer-signed JWT
	// claims with the disclosed ones in place and _sd, _sd_alg and digests
	// removed, numbers as json.Number. It must not be modified.
	Claims map[string]any
	// Issuer is the iss the issuer key was resolved for, "" when the
	// credential has none. That this issuer may issue this type
	// (draft-ietf-oauth-sd-jwt-vc-19 §7.7) is the caller's to check.
	Issuer string
	// VCT is the credential's vct, and AKAVCTs its aka_vcts, nil when absent
	// (draft 19 §2.2.2.1, §2.2.2.2).
	VCT     string
	AKAVCTs []string
	// KeyBound: a Key Binding JWT was checked against the credential's cnf.
	KeyBound bool
	// KeyBindingClaims are the claims of that Key Binding JWT, every one,
	// numbers as json.Number; nil when KeyBound is false. Verify checks iat,
	// aud, nonce, sd_hash, exp and nbf (RFC 9901 §7.3 step 5) and no other:
	// the claims a protocol adds, such as transaction_data_hashes of
	// OpenID4VP 1.0 Appendix B.3.3.1, are the caller's to check.
	KeyBindingClaims map[string]any
	// Status is the status value checked, nil when the credential has no
	// status or WithoutStatusCheck skipped it.
	Status *uint8
	// StatusSkipped: the credential has status and WithoutStatusCheck
	// skipped it.
	StatusSkipped bool
	// TypeMetadata is the credential's Type Metadata, fully processed and
	// the payload checked against it (draft 19 §5.7); nil when no Type
	// Metadata option is passed or WithOptionalTypeMetadata skipped it.
	TypeMetadata *typemeta.Metadata
	// TypeMetadataSkipped is why WithOptionalTypeMetadata skipped Type
	// Metadata, for logs; nil otherwise.
	TypeMetadataSkipped error
}

// neverDisclosableSorted holds neverDisclosable in a fixed order, so one
// token always gives the same error.
var neverDisclosableSorted = slices.Sorted(maps.Keys(neverDisclosable))

// Verify checks the credential, as received, against issuers and opts
// (draft-ietf-oauth-sd-jwt-vc-19 §2.4), and returns its claims. In order,
// each step returning at its first failure:
//  1. the receiver, ctx, issuers and opts: ErrPolicy;
//  2. the compact form (RFC 9901 §4) and the Issuer-signed JWT header:
//     MALFORMED; typ dc+sd-jwt (§2.2.1, RFC 9901 §9.11): TYP_INVALID;
//  3. the key: iss is the one claim read before the signature, and only as
//     a string (jose.DecodeJSONStringMember: nothing else is built). An iss
//     that is not a string, or a payload that is not one JSON object, is
//     MALFORMED; iss may be absent ("" to the resolver, §2.2.2.3). It goes
//     to issuers, and issuerkey.Select picks the key by kid:
//     ISSUER_NOT_SUPPORTED, ISSUER_KEY_UNAVAILABLE, ISSUER_KEY_NOT_FOUND;
//  4. the signature with WithAllowedAlgs (RFC 9901 §7.1 step 2):
//     ALG_NOT_ALLOWED, SIGNATURE_INVALID; then the signed payload, decoded
//     in full under jose.DecodeJSON's rules, with the iss of step 3:
//     MALFORMED. A payload fault the scan of step 3 does not see, such as a
//     duplicate claim other than iss, is SIGNATURE_INVALID when the
//     signature is bad too;
//  5. the Disclosures (RFC 9901 §7.1 steps 3-5), and none of a claim §2.2.2.3
//     keeps out of them: DISCLOSURE_INVALID;
//  6. exp, nbf (RFC 7519 §4.1.4, §4.1.5) and aud (§4.1.3): EXPIRED,
//     NOT_YET_VALID, AUDIENCE_MISMATCH;
//  7. vct, aka_vcts, vct#integrity (§2.2.2.1-2.2.2.3, §5.3) and the shape of
//     status (draft-ietf-oauth-status-list-21 §6.2): MALFORMED. idx is read
//     by its value (RFC 8259 §6), so 1.0, 1e3 and -0 are the indexes 1, 1000
//     and 0. With WithAcceptedVCTs and without WithExtendedVCTMatch, the
//     types: VCT_NOT_ACCEPTED;
//  8. Key Binding, per WithKeyBinding (RFC 9901 §7.3): the KB_ codes;
//  9. with WithTypeMetadata or WithOptionalTypeMetadata, Type Metadata
//     (§5.7): typemeta.Load for vct and vct#integrity, then the payload as
//     issued against its claim metadata (§5.6): the TYPE_METADATA_ codes.
//     With WithExtendedVCTMatch, the types, the extends chain included:
//     VCT_NOT_ACCEPTED;
//  10. status last (draft-ietf-oauth-status-list-21 §8.3), unless
//     WithoutStatusCheck: the status codes, MALFORMED for an idx outside the
//     list.
//
// A credential that conceals a claim and is presented without its
// Disclosure shows no sign of it: a withheld cnf reads as no cnf, and a
// withheld aud as no aud.
//
// Errors fall in three classes; test them in this order:
//   - *Error (errors.As): the token is rejected, and Code says why;
//   - ErrPolicy (errors.Is): the caller's arguments, options or
//     dependencies are at fault;
//   - anything else: ctx ended while issuers, the typemeta.Resolver or the
//     StatusChecker ran, and
//     the error wraps ctx.Err(); nothing is known about the token.
//     ErrIssuerNotSupported or ErrNoUsableKey from issuers, and
//     statuslist.ErrIndexOutOfBounds from the StatusChecker, are definite
//     answers and win over ctx.
//
// Work is linear in the length of the credential, which sdjwt.Split caps at
// 1 MiB. Before the issuer's signature is checked, Verify parses the header,
// at most 64 KiB, up to three times and scans the payload, decoding nothing
// but an iss that is a string. It then hashes every Disclosure and parses
// only those a digest references, and decodes a Key Binding JWT payload only
// after the holder's signature. A service should still bound request size
// and concurrency.
//
// This package's own texts quote no token content except bounded values from
// jose. ISSUER_NOT_SUPPORTED, ISSUER_KEY_NOT_FOUND from
// issuerkey.ErrNoUsableKey, ISSUER_KEY_UNAVAILABLE, STATUS_UNAVAILABLE and
// the errors that wrap ctx.Err() carry the error of issuers or the
// StatusChecker as it was returned. Texts are for logs, not for the Holder.
func (c *Credential) Verify(ctx context.Context, issuers issuerkey.Resolver, opts ...VerifyOption) (*Result, error) {
	if c == nil || c.compact == "" {
		return nil, policyErr("Verify of a nil or zero Credential; make one with Parse")
	}
	if ctx == nil {
		return nil, policyErr("Verify needs a non-nil context")
	}
	if issuers == nil {
		return nil, policyErr("Verify needs an issuerkey.Resolver for the issuers you accept")
	}
	cfg, err := newVerifyConfig(opts)
	if err != nil {
		return nil, err
	}

	issuerJWT, encoded, kbJWT, err := sdjwt.Split(c.compact)
	if err != nil {
		return reject(CodeMalformed, err)
	}
	header, err := jws.UnverifiedHeader(issuerJWT)
	if errors.Is(err, jws.ErrUnsupportedHeader) {
		return reject(CodeMalformed, fmt.Errorf("%w: the Issuer-signed JWT header uses crit or b64, which this SDK does not implement (RFC 7515 §4.1.11, RFC 7797 §3, §6)", jws.ErrUnsupportedHeader))
	}
	if err != nil {
		return reject(CodeMalformed, err)
	}
	if !header.TypIs(typDCSDJWT) {
		if header.TypIs("vc+sd-jwt") {
			return reject(CodeTypInvalid, errors.New("typ is vc+sd-jwt, not dc+sd-jwt: a W3C VC secured with SD-JWT (verify it with credential/vc), or an SD-JWT VC from a draft before dc+sd-jwt, which draft-ietf-oauth-sd-jwt-vc-19 §2.2.1 no longer allows (the issuer reissues it as dc+sd-jwt)"))
		}
		return reject(CodeTypInvalid, errors.New("typ is not dc+sd-jwt (draft-ietf-oauth-sd-jwt-vc-19 §2.2.1)"))
	}

	// draft 19 §2.5 leaves to the Verifier how the key is found. This SDK
	// resolves iss through issuers and never takes a key from the header (no
	// x5c). Only a string iss is decoded before the signature, so an unsigned
	// payload, whatever its iss holds, costs a scan, not a decode.
	raw, err := jws.UnverifiedPayload(issuerJWT)
	if err != nil {
		return reject(CodeMalformed, err)
	}
	// RFC 7519 §4.1.1: iss is a StringOrURI, so a JSON string.
	iss, hasIss, err := jose.DecodeJSONStringMember(raw, "iss")
	if err != nil {
		return reject(CodeMalformed, fmt.Errorf("Issuer-signed JWT payload: %w", err))
	}
	keys, err := issuers.Keys(ctx, iss)
	switch {
	case errors.Is(err, issuerkey.ErrIssuerNotSupported):
		return reject(CodeIssuerNotSupported, err)
	// A definite answer, like ErrIssuerNotSupported, whatever ctx says.
	case errors.Is(err, issuerkey.ErrNoUsableKey):
		return reject(CodeIssuerKeyNotFound, err)
	case err != nil && ctx.Err() != nil:
		return nil, fmt.Errorf("dc: resolving the issuer keys: %w (resolver: %v)", ctx.Err(), err)
	// The resolver's wiring, such as a resolver not made by its constructor.
	case errors.Is(err, jose.ErrInvalidArgument):
		return nil, policyErr("the issuerkey.Resolver: %v", err)
	case err != nil:
		return reject(CodeIssuerKeyUnavailable, fmt.Errorf("the issuerkey.Resolver could not return the issuer keys: %w", err))
	}
	key, err := issuerkey.Select(keys, header)
	if err != nil {
		return reject(CodeIssuerKeyNotFound, err)
	}
	_, signed, err := jws.Verify(issuerJWT, key, cfg.algs)
	switch {
	case err == nil:
	// The resolver returned a key jws does not verify with: the caller's
	// resolver, not the token, so ErrPolicy, which keeps the key's class.
	case errors.Is(err, jose.ErrUnsupportedKey), errors.Is(err, jws.ErrBadKey):
		return nil, fmt.Errorf("%w: dc: the issuerkey.Resolver returned a key that cannot verify: %w", ErrPolicy, err)
	case errors.Is(err, jws.ErrAlgNotAllowed):
		return reject(CodeAlgNotAllowed, err)
	case errors.Is(err, jws.ErrAlgKeyMismatch), errors.Is(err, jws.ErrBadSignature):
		return reject(CodeSignatureInvalid, err)
	default:
		return reject(CodeMalformed, err)
	}
	payload, err := jose.DecodeJSONObject(signed)
	if err != nil {
		return reject(CodeMalformed, fmt.Errorf("Issuer-signed JWT payload: %w", err))
	}
	// The key was chosen for this iss; the full decode must read the same.
	if v, ok := payload["iss"]; ok != hasIss || (ok && v != iss) {
		return reject(CodeMalformed, errors.New("the Issuer-signed JWT payload's iss differs from the one its key was resolved for"))
	}

	given := make([]sdjwt.Disclosure, len(encoded))
	for i, e := range encoded {
		given[i] = sdjwt.Disclosure{Encoded: e}
	}
	r, err := sdjwt.Recreate(payload, given)
	if err != nil {
		return reject(CodeDisclosureInvalid, err)
	}
	// draft 19 §2.2.2.3: these claims, "including any of their sub-claims",
	// MUST NOT be included in Disclosures. Checked before any is read.
	for _, name := range neverDisclosableSorted {
		if r.Disclosed(sdjwt.Path{name}) {
			return reject(CodeDisclosureInvalid, fmt.Errorf("claim %q, or a sub-claim of it, came in a Disclosure, which draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 forbids", name))
		}
	}
	claims := r.Claims

	if err := jwt.CheckExpNbf(claims, cfg.now, cfg.skew); err != nil {
		switch {
		case errors.Is(err, jwt.ErrExpired):
			return reject(CodeExpired, err)
		case errors.Is(err, jwt.ErrNotYetValid):
			return reject(CodeNotYetValid, err)
		default:
			return reject(CodeMalformed, err)
		}
	}
	if err := jwt.CheckAud(claims, cfg.credAudience); err != nil {
		if errors.Is(err, jwt.ErrAudience) {
			return reject(CodeAudienceMismatch, fmt.Errorf("WithCredentialAudience: %w", err))
		}
		return reject(CodeMalformed, err)
	}
	res := &Result{Claims: claims, Issuer: iss}
	if res.VCT, res.AKAVCTs, err = readTypes(claims); err != nil {
		return reject(CodeMalformed, err)
	}
	st, err := readStatus(claims)
	if err != nil {
		return reject(CodeMalformed, err)
	}
	if cfg.acceptedVCTs != nil && !cfg.extendedVCT && !cfg.typeAccepted(res) {
		return reject(CodeVCTNotAccepted, errors.New("neither vct nor aka_vcts is a type in WithAcceptedVCTs"))
	}

	if res.KeyBindingClaims, err = cfg.checkKeyBinding(c.compact, kbJWT, payload, r); err != nil {
		return nil, err
	}
	res.KeyBound = res.KeyBindingClaims != nil

	if err := cfg.checkTypeMetadata(ctx, r, kbJWT, res); err != nil {
		return nil, err
	}
	if cfg.extendedVCT && !cfg.typeAccepted(res) {
		return reject(CodeVCTNotAccepted, errors.New("neither vct, aka_vcts nor a type its Type Metadata extends is a type in WithAcceptedVCTs"))
	}

	if !st.present {
		return res, nil
	}
	if cfg.skipStatus {
		res.StatusSkipped = true
		return res, nil
	}
	v, err := cfg.checkStatus(ctx, st, iss)
	if err != nil {
		return nil, err
	}
	if slices.Contains(cfg.accepted, v) {
		res.Status = &v
		return res, nil
	}
	// draft-ietf-oauth-status-list-21 §7.1: 0x01 INVALID, 0x02 SUSPENDED.
	switch v {
	case 0x01:
		return reject(CodeRevoked, errors.New("the issuer revoked the credential (status 0x01)"))
	case 0x02:
		return reject(CodeSuspended, errors.New("the issuer suspended the credential (status 0x02)"))
	default:
		return reject(CodeStatusNotAccepted, fmt.Errorf("status 0x%02x is not in WithAcceptedStatus", v))
	}
}

// readTypes reads vct and aka_vcts from claims, the processed payload, and
// checks that vct#integrity is a string (draft 19 §2.2.2.1-2.2.2.3, §5.3). An
// error is a claim of the wrong shape.
func readTypes(claims map[string]any) (vct string, akaVCTs []string, err error) {
	if vct, _ = claims["vct"].(string); vct == "" {
		return "", nil, errors.New("vct is absent, which draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 forbids, or not a non-empty string as §2.2.2.1 requires")
	}
	if v, ok := claims["aka_vcts"]; ok {
		if err := checkAkaVCTs(v, vct); err != nil {
			return "", nil, fmt.Errorf("aka_vcts %v (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.2)", err)
		}
		for _, e := range v.([]any) {
			akaVCTs = append(akaVCTs, e.(string))
		}
	}
	if v, ok := claims["vct#integrity"]; ok {
		if _, ok := v.(string); !ok {
			return "", nil, errors.New("vct#integrity is not a string (draft-ietf-oauth-sd-jwt-vc-19 §5.3)")
		}
	}
	return vct, akaVCTs, nil
}

// checkKeyBinding applies the Key Binding mode to kbJWT, "" when none came,
// for the credential compact with payload, its Issuer-signed JWT payload, and
// r recreated from it. It returns the claims of the Key Binding JWT it
// checked, nil when it checked none. Its errors are *Error or ErrPolicy.
func (cfg verifyConfig) checkKeyBinding(compact, kbJWT string, payload map[string]any, r *sdjwt.Recreated) (map[string]any, error) {
	_, hasCnf := payload["cnf"]
	required := hasCnf
	switch cfg.keyBinding {
	case KeyBindingRequired:
		required = true
	case KeyBindingNotRequired:
		required = false
	}
	if !required {
		if kbJWT == "" || cfg.ignoreUncheckedKB {
			return nil, nil
		}
		if cfg.keyBinding == KeyBindingNotRequired {
			return nil, &Error{Code: CodeKBUnexpected, Err: errors.New("a Key Binding JWT came under KeyBindingNotRequired: a Holder (RFC 9901 §7.2) or a verifier expecting an SD-JWT (§4) MUST reject it; add WithIgnoreUncheckedKBJWT if this verifier only does not need it")}
		}
		return nil, &Error{Code: CodeKBUnexpected, Err: errors.New("a Key Binding JWT came with a credential that has no cnf claim, so no key checks it (draft-ietf-oauth-sd-jwt-vc-19 §2.4); add WithIgnoreUncheckedKBJWT to ignore it")}
	}
	// The credential first: when its cnf gives no key, no presentation of it
	// passes, so asking the holder for a Key Binding JWT would not help.
	if !hasCnf {
		return nil, &Error{Code: CodeKBUnsupported, Err: errors.New("Key Binding is required (KeyBindingRequired) and the credential has no cnf claim, the key a Key Binding JWT is checked with (draft-ietf-oauth-sd-jwt-vc-19 §2.4)")}
	}
	holder, err := holderKey(payload, r)
	if errors.Is(err, ErrKeyBindingUnsupported) {
		return nil, &Error{Code: CodeKBUnsupported, Err: err}
	}
	if err != nil {
		return nil, &Error{Code: CodeMalformed, Err: err}
	}
	if kbJWT == "" {
		if cfg.keyBinding == KeyBindingRequired {
			return nil, &Error{Code: CodeKBMissing, Err: errors.New("Key Binding is required (KeyBindingRequired) and no Key Binding JWT came: the holder must send an SD-JWT+KB (RFC 9901 §7.3 step 2)")}
		}
		return nil, &Error{Code: CodeKBMissing, Err: errors.New("the credential binds a holder key and no Key Binding JWT came: the holder must send an SD-JWT+KB, or pass WithKeyBinding(KeyBindingNotRequired) if this verifier does not require Key Binding (RFC 9901 §7.3 step 2, §9.5)")}
	}
	if cfg.audience == "" || cfg.nonce == "" {
		return nil, policyErr("this presentation has a Key Binding JWT: pass WithAudience and WithNonce, or WithKeyBinding(KeyBindingNotRequired) with WithIgnoreUncheckedKBJWT if this verifier does not check Key Binding (RFC 9901 §7.3 step 5f)")
	}
	kbClaims, err := sdjwt.VerifyKBJWT(kbJWT, holder, sdjwt.KBVerifyParams{
		Audience: cfg.audience,
		Nonce:    cfg.nonce,
		// RFC 9901 §4.3.1: over the SD-JWT as received, up to the last ~.
		SDHash:      sdjwt.SDHash(compact[:len(compact)-len(kbJWT)]),
		Now:         cfg.now,
		MaxAge:      cfg.maxKBAge,
		ClockSkew:   cfg.skew,
		AllowedAlgs: cfg.algs,
	})
	switch {
	case err == nil:
		return kbClaims, nil
	case errors.Is(err, jose.ErrInvalidArgument):
		return nil, policyErr("checking the Key Binding JWT: %v", err)
	case errors.Is(err, sdjwt.ErrKBAudience):
		return nil, &Error{Code: CodeKBAudienceMismatch, Err: err}
	case errors.Is(err, sdjwt.ErrKBNonce):
		return nil, &Error{Code: CodeKBNonceMismatch, Err: err}
	case errors.Is(err, sdjwt.ErrKBSDHash):
		return nil, &Error{Code: CodeKBSDHashMismatch, Err: err}
	default:
		return nil, &Error{Code: CodeKBInvalid, Err: err}
	}
}

// checkTypeMetadata is step 9: with a Type Metadata option, it processes the
// Type Metadata of res.VCT (draft 19 §5.7) and checks r, the payload as
// issued, against it (§5.6), setting res.TypeMetadata or, when
// WithOptionalTypeMetadata skips it, res.TypeMetadataSkipped. Its errors are
// *Error, ErrPolicy, or wrap ctx.Err().
func (cfg verifyConfig) checkTypeMetadata(ctx context.Context, r *sdjwt.Recreated, kbJWT string, res *Result) error {
	if cfg.types == nil {
		return nil
	}
	if cfg.allDisclosures && kbJWT != "" {
		return policyErr("WithAllDisclosures with a presentation that has a Key Binding JWT: a Verifier is never sure to hold every Disclosure (draft-ietf-oauth-sd-jwt-vc-19 §5.6); drop WithAllDisclosures")
	}
	integrity, present := res.Claims["vct#integrity"].(string) // step 7 checked its type
	var m *typemeta.Metadata
	var err error
	if present && integrity == "" {
		// §6: an integrity property that is present must be verified, and
		// an empty one names no hash, so the document cannot be accepted.
		err = fmt.Errorf("%w: dc: vct#integrity is present and empty, so no hash can check the Type Metadata document; the issuer writes typemeta.Integrity(doc) or leaves it out (draft-ietf-oauth-sd-jwt-vc-19 §6)", typemeta.ErrInvalid)
	} else {
		m, err = typemeta.Load(ctx, cfg.types, typemeta.Ref{VCT: res.VCT, Integrity: integrity})
	}
	switch {
	case err == nil:
	case ctx.Err() != nil:
		return fmt.Errorf("dc: processing the Type Metadata: %w (%v)", ctx.Err(), err)
	// The resolver's wiring, such as one not made by its constructor.
	case errors.Is(err, jose.ErrInvalidArgument):
		return policyErr("the typemeta.Resolver: %v", err)
	// §5.7: claim metadata that cannot be processed MUST reject, whatever
	// the policy; so must a cycle (§7.4).
	case errors.Is(err, typemeta.ErrClaims), errors.Is(err, typemeta.ErrCycle):
		return &Error{Code: CodeTypeMetadataInvalid, Err: err}
	case cfg.typesOptional:
		res.TypeMetadataSkipped = err
		return nil
	case errors.Is(err, typemeta.ErrNotFound):
		return &Error{Code: CodeTypeMetadataNotFound, Err: err}
	case errors.Is(err, typemeta.ErrInvalid):
		return &Error{Code: CodeTypeMetadataInvalid, Err: err}
	default:
		return &Error{Code: CodeTypeMetadataUnavailable, Err: fmt.Errorf("the typemeta.Resolver could not return the Type Metadata: %w", err)}
	}
	if err := m.ValidateClaims(r.Issued(), typemeta.ValidateOptions{AllDisclosures: cfg.allDisclosures}); err != nil {
		// ErrClaims: claim metadata the SDK cannot check on this payload.
		if errors.Is(err, typemeta.ErrClaims) {
			return &Error{Code: CodeTypeMetadataInvalid, Err: err}
		}
		return &Error{Code: CodeTypeMetadataViolated, Err: err}
	}
	res.TypeMetadata = m
	return nil
}

// typeAccepted reports whether a type of res is in WithAcceptedVCTs: vct,
// aka_vcts and, with WithExtendedVCTMatch, the extends chain of its Type
// Metadata (draft 19 §2.2.2.1, §2.2.2.2, §5.4), compared byte for byte.
func (cfg verifyConfig) typeAccepted(res *Result) bool {
	types := append([]string{res.VCT}, res.AKAVCTs...)
	if cfg.extendedVCT {
		types = append(types, res.TypeMetadata.Chain()...) // nil when skipped
	}
	return slices.ContainsFunc(types, func(t string) bool { return slices.Contains(cfg.acceptedVCTs, t) })
}

// statusClaim is the status claim as Verify reads it.
type statusClaim struct {
	present bool // the credential has status
	list    bool // status has status_list; ref is set
	ref     statuslist.Ref
	pastInt bool // idx is an integer too large for an int; ref.Index is 0
}

// readStatus reads the status claim (draft-ietf-oauth-status-list-21 §6.2).
// An error is a status of the wrong shape.
func readStatus(claims map[string]any) (statusClaim, error) {
	v, ok := claims["status"]
	if !ok {
		return statusClaim{}, nil
	}
	// §6.2: a JSON object with at least one status mechanism.
	obj, ok := v.(map[string]any)
	if !ok || len(obj) == 0 {
		return statusClaim{}, errors.New("status is not a JSON object holding a status mechanism (draft-ietf-oauth-status-list-21 §6.2)")
	}
	sl, ok := obj["status_list"]
	if !ok {
		return statusClaim{present: true}, nil
	}
	list, _ := sl.(map[string]any) // nil, so no uri, when not an object
	uri, ok := list["uri"].(string)
	if !ok {
		return statusClaim{}, errors.New("status.status_list is not a JSON object with a string uri (draft-ietf-oauth-status-list-21 §6.2)")
	}
	// §6.2: idx is a non-negative Integer, a value, so every RFC 8259 §6
	// form of it counts: 1.0, 1e3 and -0 too. jsonint reads it exactly.
	n, _ := list["idx"].(json.Number) // any other type reads as "" and fails
	st := statusClaim{present: true, list: true}
	idx, err := jsonint.NonNegative(string(n))
	switch {
	case errors.Is(err, jsonint.ErrTooLarge):
		st.pastInt, idx = true, 0
	case err != nil:
		return statusClaim{}, errors.New("status.status_list.idx is absent or not a non-negative integer (draft-ietf-oauth-status-list-21 §6.2)")
	}
	st.ref = statuslist.Ref{URI: uri, Index: idx}
	// %v: the cause is the token's, so it must not match
	// jose.ErrInvalidArgument.
	if err := st.ref.Validate(); err != nil {
		return statusClaim{}, fmt.Errorf("status.status_list: %v", err)
	}
	return st, nil
}

// checkStatus asks the StatusChecker for the status st refers to. Its errors
// are *Error, ErrPolicy, or wrap ctx.Err().
func (cfg verifyConfig) checkStatus(ctx context.Context, st statusClaim, iss string) (uint8, error) {
	if !st.list {
		return 0, &Error{Code: CodeStatusUnavailable, Err: errors.New("status has no status_list, the one mechanism this SDK checks (draft-ietf-oauth-status-list-21 §8.3 step 1); WithoutStatusCheck accepts it unchecked")}
	}
	// No list holds more entries than an int counts.
	if st.pastInt {
		return 0, &Error{Code: CodeMalformed, Err: fmt.Errorf("status_list idx is past every status list: %w", statuslist.ErrIndexOutOfBounds)}
	}
	if cfg.status == nil {
		return 0, policyErr("the credential has a status_list: pass WithStatus, such as with a statuslist.Checker, or WithoutStatusCheck")
	}
	v, err := cfg.status.Status(ctx, st.ref, iss)
	switch {
	case err == nil:
		return v, nil
	// A definite answer: §8.3 step 6 says MUST reject, whatever ctx says.
	case errors.Is(err, statuslist.ErrIndexOutOfBounds):
		return 0, &Error{Code: CodeMalformed, Err: err}
	case ctx.Err() != nil:
		return 0, fmt.Errorf("dc: checking the status: %w (StatusChecker: %v)", ctx.Err(), err)
	// Verify validated the Ref, so this is the checker's wiring, such as a
	// statuslist.Checker not made by NewChecker, or one whose resolver
	// returned a key it cannot verify with.
	case errors.Is(err, jose.ErrInvalidArgument):
		return 0, policyErr("WithStatus: %v", err)
	// Never by jose.ErrMalformed: a fetch can fail with it too.
	default:
		return 0, &Error{Code: CodeStatusUnavailable, Err: fmt.Errorf("StatusChecker: %w", err)}
	}
}

func reject(c Code, err error) (*Result, error) {
	return nil, &Error{Code: c, Err: err}
}
