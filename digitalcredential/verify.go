// Verifying an SD-JWT VC on the verifier side: draft-ietf-oauth-sd-jwt-vc-19
// §2.4 (verification), §2.2.2.3 (claims) and §2.5 (issuer key); RFC 9901 §4,
// §7.1 (the SD-JWT), §7.3 (Key Binding) and §9.5; RFC 7519 §4.1.3-§4.1.5;
// draft-ietf-oauth-status-list-21 §6.2, §7.1 and §8.3 (status).

package digitalcredential

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/jsonint"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuerkey"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/statuslist"
	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
	"github.com/pilacorp/go-credential-sdk/jose/jwt"
	"github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

// Code is why Verify refused a token, for the caller to branch on. Codes are
// stable strings; the text of Error.Err is not.
type Code string

const (
	// CodeMalformed: the token is not a well-formed SD-JWT VC: not an SD-JWT
	// (RFC 9901 §4), a JWS or JSON this SDK does not read, a header with
	// crit or b64, an iss, exp, nbf or aud of the wrong type, no vct, or a
	// status claim of the wrong shape (draft-ietf-oauth-status-list-21 §6.2).
	// When Key Binding is required, so cnf is read, also a cnf or cnf.jwk
	// that is not a JSON object (RFC 7800 §3), a cnf.jwk that jwk.ToPublicKey
	// refuses as broken or that holds a symmetric key in this unencrypted JWT
	// (§3.2), or a cnf with more than one of jwk, jwe and jku (§3.1). Or its
	// status_list idx is outside the issuer's Status List, where
	// draft-ietf-oauth-status-list-21 §8.3 step 6 says the token MUST be
	// rejected; Err then wraps statuslist.ErrIndexOutOfBounds. The idx is
	// compared with a list only when status is checked. A list cached before
	// the issuer published a longer one gives this until the cached list
	// expires.
	CodeMalformed Code = "MALFORMED"
	// CodeTypInvalid: the Issuer-signed JWT typ is not dc+sd-jwt. The Issuer
	// MUST write it (draft-ietf-oauth-sd-jwt-vc-19 §2.2.1), so a token without
	// it is not an SD-JWT VC; RFC 9901 §9.11 RECOMMENDS that verifiers check
	// it, and Verify always does.
	CodeTypInvalid Code = "TYP_INVALID"
	// CodeAlgNotAllowed: the Issuer-signed JWT alg is none, not ES256 or
	// ES256K, or not in Policy.AllowedAlgs (RFC 9901 §7.1 step 2a).
	CodeAlgNotAllowed Code = "ALG_NOT_ALLOWED"
	// CodeIssuerNotSupported: Policy.Issuers answered
	// issuerkey.ErrIssuerNotSupported: this verifier does not accept iss.
	CodeIssuerNotSupported Code = "ISSUER_NOT_SUPPORTED"
	// CodeIssuerKeyNotFound: no single key verifies the token
	// (issuerkey.Select). Err keeps Select's text, which tells the cases
	// apart: the issuer publishes no key or none with the header kid (rotated
	// or revoked, never this issuer's, or skipped by the resolver as a key it
	// cannot use); two keys share the kid, or there is no kid and several
	// keys (the issuer's metadata or header is at fault); the resolver
	// returned a nil Key (the caller's resolver). It is also Policy.Issuers
	// answering issuerkey.ErrNoUsableKey: the issuer's document gives no
	// usable key, and Err says why.
	CodeIssuerKeyNotFound Code = "ISSUER_KEY_NOT_FOUND"
	// CodeIssuerKeyUnavailable: Policy.Issuers could not find out the
	// issuer's keys, and draft-ietf-oauth-sd-jwt-vc-19 §2.5 says to reject
	// when the key cannot be validated. Err wraps the resolver's error; a
	// later call may succeed.
	CodeIssuerKeyUnavailable Code = "ISSUER_KEY_UNAVAILABLE"
	// CodeSignatureInvalid: the Issuer-signed JWT signature does not verify
	// with the issuer key, or its alg does not match that key (RFC 9901 §7.1
	// step 2b; RFC 8725 §3.1).
	CodeSignatureInvalid Code = "SIGNATURE_INVALID"
	// CodeDisclosureInvalid: a Disclosure is malformed, unreferenced or
	// duplicated, _sd_alg is not sha-256 (RFC 9901 §7.1 steps 2d-5), or a
	// Disclosure carries a claim draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 never
	// allows in one (iss, nbf, exp, cnf, vct, vct#integrity, aka_vcts,
	// status), or a sub-claim of one.
	CodeDisclosureInvalid Code = "DISCLOSURE_INVALID"
	// CodeExpired: the time of the check is at or after exp plus
	// Policy.ClockSkew (RFC 7519 §4.1.4).
	CodeExpired Code = "EXPIRED"
	// CodeNotYetValid: the time of the check is before nbf minus
	// Policy.ClockSkew (RFC 7519 §4.1.5).
	CodeNotYetValid Code = "NOT_YET_VALID"
	// CodeAudienceMismatch: the Issuer-signed JWT has aud and it does not
	// list Policy.CredentialAudience, or that is empty (RFC 7519 §4.1.3).
	CodeAudienceMismatch Code = "AUDIENCE_MISMATCH"
	// CodeKBMissing: Key Binding is required, the credential's cnf holds a
	// key this SDK checks Key Binding with, and no Key Binding JWT came (RFC
	// 9901 §7.3 step 2): the holder can present it again with one.
	CodeKBMissing Code = "KB_MISSING"
	// CodeKBUnexpected: a Key Binding JWT came that Policy does not check,
	// and Policy.IgnoreUncheckedKBJWT is false. Under KeyBindingNotRequired,
	// a Holder (RFC 9901 §7.2) or a verifier expecting an SD-JWT (§4) MUST
	// reject it. Under KeyBindingIfCnf, with a credential that has no cnf, no
	// key can check it (draft-ietf-oauth-sd-jwt-vc-19 §2.4); refusing it is
	// this SDK's default, which IgnoreUncheckedKBJWT turns off.
	CodeKBUnexpected Code = "KB_UNEXPECTED"
	// CodeKBUnsupported: Key Binding is required and cannot be checked for
	// this credential: Policy.KeyBinding is KeyBindingRequired and the
	// credential has no cnf (draft-ietf-oauth-sd-jwt-vc-19 §2.4), or its cnf
	// is not one this SDK checks Key Binding with (ErrKeyBindingUnsupported:
	// no jwk, or a key type jose/jwk does not convert). No presentation of
	// this credential passes, with a Key Binding JWT or without; the code says
	// nothing about whether the credential is otherwise valid.
	CodeKBUnsupported Code = "KB_UNSUPPORTED"
	// CodeKBInvalid: the Key Binding JWT fails RFC 9901 §7.3 step 5 other
	// than by a differing aud, nonce or sd_hash (sdjwt.ErrKBInvalid).
	CodeKBInvalid Code = "KB_INVALID"
	// CodeKBAudienceMismatch: the Key Binding JWT aud is a string other than
	// Policy.Audience (RFC 9901 §7.3 step 5f): made for another verifier.
	CodeKBAudienceMismatch Code = "KB_AUDIENCE_MISMATCH"
	// CodeKBNonceMismatch: the Key Binding JWT nonce is a string other than
	// Policy.Nonce (RFC 9901 §7.3 step 5f): made for another transaction.
	CodeKBNonceMismatch Code = "KB_NONCE_MISMATCH"
	// CodeKBSDHashMismatch: the Key Binding JWT sd_hash is a string that does
	// not match the SD-JWT received (RFC 9901 §7.3 step 5g): Disclosures were
	// dropped or added after it was signed.
	CodeKBSDHashMismatch Code = "KB_SD_HASH_MISMATCH"
	// CodeRevoked: the status is 0x01, INVALID in
	// draft-ietf-oauth-status-list-21 §7.1, and not in Policy.AcceptedStatus.
	CodeRevoked Code = "REVOKED"
	// CodeSuspended: the status is 0x02, SUSPENDED in
	// draft-ietf-oauth-status-list-21 §7.1, and not in Policy.AcceptedStatus.
	CodeSuspended Code = "SUSPENDED"
	// CodeStatusNotAccepted: any other status not in Policy.AcceptedStatus.
	CodeStatusNotAccepted Code = "STATUS_NOT_ACCEPTED"
	// CodeStatusUnavailable: No statement about the status could be made
	// (draft-ietf-oauth-status-list-21 §8.3, SHOULD be rejected): a failed
	// fetch, a list token failing its checks, a uri the checker does not
	// fetch, or a status mechanism other than status_list. Verify rejected
	// the token; some causes pass on retry, others do not. A caller whose own
	// policy accepts such a token calls Verify again with SkipStatus.
	CodeStatusUnavailable Code = "STATUS_UNAVAILABLE"
)

// Error is a token Verify refused. Branch on Code; Err is the cause, for
// logs only, and is never nil. errors.Is and errors.As reach through Err, so
// a resolver's or checker's own error stays matchable, and so do
// context.DeadlineExceeded from a checker's own fetch bound and jwt.ErrExpired
// from an expired Status List Token.
type Error struct {
	Code Code
	Err  error
}

func (e *Error) Error() string {
	// Texts of this package's helpers already start with the prefix.
	return "digitalcredential: " + string(e.Code) + ": " + strings.TrimPrefix(e.Err.Error(), "digitalcredential: ")
}

func (e *Error) Unwrap() error { return e.Err }

// ErrPolicy: Verify was called with a Policy, or a dependency in it, that
// cannot verify: the caller's code or configuration is at fault, not the
// token. Some cases show only for some tokens and only after the caller's own
// network calls: an AllowedAlgs entry this SDK does not support, a resolver
// key on another curve (after Policy.Issuers, or inside Policy.Status), no
// Audience or Nonce when a Key Binding JWT must be checked, no Status for a
// credential with status_list, or a resolver or checker error wrapping
// jose.ErrInvalidArgument. So do not treat it as a startup-only error. It
// wraps no cause.
var ErrPolicy = errors.New("digitalcredential: invalid verify policy")

// StatusChecker returns the raw status of the Referenced Token ref points to
// (draft-ietf-oauth-status-list-21 §8), from the Status List Token of iss; a
// *statuslist.Checker is one. Verify reads an error of Status in this order:
//   - one wrapping statuslist.ErrIndexOutOfBounds is MALFORMED (§8.3 step 6:
//     MUST be rejected), whatever ctx says;
//   - when ctx is done, Verify returns an error wrapping ctx.Err();
//   - one wrapping jose.ErrInvalidArgument or jws.ErrBadKey is ErrPolicy;
//   - any other is STATUS_UNAVAILABLE.
//
// List.Get reports an index outside the list as jose.ErrInvalidArgument; a
// checker built on it compares the index with the list size itself and
// returns ErrIndexOutOfBounds. A wrapper that accepts tokens whose status it
// cannot read passes ErrIndexOutOfBounds through unchanged. Status should
// return when ctx is done.
type StatusChecker interface {
	Status(ctx context.Context, ref statuslist.Ref, iss string) (uint8, error)
}

// KeyBindingMode says when Verify requires Key Binding. RFC 9901 §7.3 step 1
// leaves it to the verifier's policy, never to whether a Key Binding JWT came,
// and §9.5 asks for the decision per use case. When Key Binding is required,
// a missing Key Binding JWT is rejected (§7.3 step 2) and the key is the
// credential's cnf (draft-ietf-oauth-sd-jwt-vc-19 §2.4).
type KeyBindingMode uint8

const (
	// KeyBindingIfCnf, the default, requires Key Binding exactly when the
	// credential has cnf, the key it binds. A credential without cnf passes
	// with Result.KeyBound false: if your use case requires Key Binding,
	// reject when KeyBound is false, or use KeyBindingRequired.
	KeyBindingIfCnf KeyBindingMode = iota
	// KeyBindingRequired requires Key Binding for every credential, so one
	// without cnf is rejected too, as KB_UNSUPPORTED.
	KeyBindingRequired
	// KeyBindingNotRequired checks no Key Binding JWT: for a Holder checking
	// what it received (RFC 9901 §7.2), or a verifier that expects an SD-JWT
	// (§4). Both MUST reject one that comes; a verifier that only does not
	// need it sets IgnoreUncheckedKBJWT.
	KeyBindingNotRequired
)

// defaultClockSkew is Policy.ClockSkew when zero, for exp, nbf and the Key
// Binding JWT's iat alike.
const defaultClockSkew = time.Minute

// Policy is what Verify checks a token against.
type Policy struct {
	// Issuers returns the keys of the issuers this verifier accepts
	// (draft-ietf-oauth-sd-jwt-vc-19 §2.5); required, and it must not be a
	// typed nil, which Verify cannot detect. issuermeta.NewResolver returns
	// one that reads JWT VC Issuer Metadata (§4).
	Issuers issuerkey.Resolver
	// AllowedAlgs are the algorithms accepted for the Issuer-signed JWT and
	// the Key Binding JWT (RFC 8725 §3.1; RFC 9901 §7.1 step 2a, §7.3 step
	// 5b); nil or empty means ES256 and ES256K. Another entry is ErrPolicy.
	AllowedAlgs []string
	// KeyBinding says when Key Binding is required; zero is KeyBindingIfCnf.
	KeyBinding KeyBindingMode
	// IgnoreUncheckedKBJWT accepts a Key Binding JWT that KeyBinding does not
	// check, and ignores it (RFC 9901 §7.3 then skips step 5): KeyBound stays
	// false. A Holder, or a verifier expecting an SD-JWT, leaves it false.
	IgnoreUncheckedKBJWT bool
	// Audience and Nonce are the aud and nonce of this transaction, which the
	// Key Binding JWT must carry (RFC 9901 §7.3 step 5f); needed whenever one
	// is checked. Verify compares them byte for byte and keeps no state:
	// issuing a fresh nonce for each transaction and accepting it once, the
	// replay detection of step 5f, is the caller's job.
	Audience string
	Nonce    string
	// CredentialAudience is how this verifier names itself in the
	// Issuer-signed JWT's aud (RFC 7519 §4.1.3), read only when the
	// credential has aud; empty refuses any credential with aud. An aud the
	// issuer concealed and the holder withheld is absent, which Verify cannot
	// tell apart.
	CredentialAudience string
	// MaxKBAge is how old the Key Binding JWT iat may be (RFC 9901 §7.3 step
	// 5e); zero is 5 minutes. ClockSkew is the leeway on exp and nbf (RFC 7519
	// §4.1.4, §4.1.5: a small leeway MAY be allowed) and on the Key Binding
	// JWT's iat (RFC 9901 §7.3 step 5e); zero is 1 minute. Negative is
	// ErrPolicy.
	MaxKBAge  time.Duration
	ClockSkew time.Duration
	// Status checks a credential's status_list; needed when one has it,
	// unless SkipStatus. Like Issuers, it must not be a typed nil, which
	// Verify cannot detect; a nil *statuslist.Checker reports ErrPolicy.
	Status StatusChecker
	// SkipStatus accepts a credential with status without checking it:
	// Result.StatusSkipped says so. draft-ietf-oauth-sd-jwt-vc-19 §2.4 says
	// the status SHOULD be checked and leaves it to verifier policy, while
	// draft-ietf-oauth-status-list-21 §8.3 says the Relying Party MUST check
	// it; this module follows the -19 profile. The shape of status is
	// checked anyway: a status claim that breaks the MUSTs of
	// draft-ietf-oauth-status-list-21 §6.2 makes the token malformed.
	SkipStatus bool
	// AcceptedStatus are the status values accepted; nil is {0x00}, VALID
	// (draft-ietf-oauth-status-list-21 §7.1). Empty, not nil, accepts none:
	// that is the caller's policy.
	AcceptedStatus []uint8
	// Now is the time of the check; zero is time.Now(), read once, for exp,
	// nbf and the Key Binding JWT alike. It does not reach Status, which
	// checks the Status List Token with its own clock.
	Now time.Time
}

// Result is a token Verify accepted.
type Result struct {
	// Claims is the processed payload (RFC 9901 §7.1): the Issuer-signed JWT
	// claims with the disclosed ones in place and _sd, _sd_alg and digests
	// removed, numbers as json.Number. aka_vcts is not read
	// (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.2); draft 20 adds a SHOULD for
	// whoever matches types against it.
	Claims map[string]any
	// KeyBound: a Key Binding JWT was checked against the credential's cnf.
	KeyBound bool
	// Status is the status value checked, nil when the credential has none
	// or SkipStatus skipped it.
	Status *uint8
	// StatusSkipped: the credential has status and SkipStatus skipped it.
	StatusSkipped bool
}

// neverDisclosableSorted holds neverDisclosable in a fixed order, so one
// token always gives the same error.
var neverDisclosableSorted = slices.Sorted(maps.Keys(neverDisclosable))

// Verify checks compact, an SD-JWT or SD-JWT+KB holding an SD-JWT VC
// (draft-ietf-oauth-sd-jwt-vc-19 §2.4), against p, and returns its claims. In
// order, each step returning at its first failure:
//  1. p: ctx, Issuers, MaxKBAge, ClockSkew, KeyBinding and, with
//     KeyBindingRequired, Audience and Nonce; else ErrPolicy;
//  2. the compact form (RFC 9901 §4) and the Issuer-signed JWT header:
//     MALFORMED; typ dc+sd-jwt (§2.2.1, RFC 9901 §9.11): TYP_INVALID;
//  3. the key: iss is the one claim read before the signature, and only as
//     a string (jose.DecodeJSONStringMember: nothing else is built). An iss
//     that is not a string, or a payload that is not one JSON object, is
//     MALFORMED; iss may be absent ("" to the resolver). It goes to
//     Policy.Issuers, and issuerkey.Select picks the key by kid:
//     ISSUER_NOT_SUPPORTED, ISSUER_KEY_UNAVAILABLE, ISSUER_KEY_NOT_FOUND;
//  4. the signature with AllowedAlgs (RFC 9901 §7.1 step 2): ALG_NOT_ALLOWED,
//     SIGNATURE_INVALID; then the signed payload, decoded in full under
//     jose.DecodeJSON's rules, with the iss of step 3: MALFORMED. A payload
//     fault the scan of step 3 does not see, such as a duplicate claim
//     other than iss, is SIGNATURE_INVALID when the signature is bad too;
//  5. the Disclosures (RFC 9901 §7.1 steps 3-5), and none of a claim §2.2.2.3
//     keeps out of them: DISCLOSURE_INVALID;
//  6. exp, nbf (RFC 7519 §4.1.4, §4.1.5) and aud (§4.1.3): EXPIRED,
//     NOT_YET_VALID, AUDIENCE_MISMATCH;
//  7. vct (§2.2.2.3) and the shape of status (draft-ietf-oauth-status-list-21
//     §6.2): MALFORMED. idx is read by its value (RFC 8259 §6), so 1.0, 1e3
//     and -0 are the indexes 1, 1000 and 0;
//  8. Key Binding, per p.KeyBinding (RFC 9901 §7.3): the KB_ codes;
//  9. status last (draft-ietf-oauth-status-list-21 §8.3), unless SkipStatus:
//     the status codes, MALFORMED for an idx outside the list.
//
// A credential that conceals a claim and is presented without its
// Disclosure shows no sign of it: a withheld cnf reads as no cnf, and a
// withheld aud as no aud. With KeyBindingNotRequired, an aud-bearing
// credential still needs CredentialAudience (RFC 7519 §4.1.3).
//
// Errors fall in three classes; test them in this order:
//   - *Error (errors.As): the token is refused, and Code says why;
//   - ErrPolicy (errors.Is): the caller's Policy is at fault;
//   - anything else: ctx ended while Policy.Issuers or Policy.Status ran, and
//     the error wraps ctx.Err(); nothing is known about the token.
//     ErrIssuerNotSupported or ErrNoUsableKey from Policy.Issuers, and
//     statuslist.ErrIndexOutOfBounds from Policy.Status, are definite answers
//     and win over ctx; a resolver's answer reached through Policy.Status,
//     such as a Checker's, does not, and with ctx live it is
//     STATUS_UNAVAILABLE.
//
// Work is linear in len(compact), which sdjwt.Split caps at 1 MiB. Before
// the issuer's signature is checked, Verify parses the header, at most 64
// KiB, up to three times and scans the payload, decoding nothing but an iss
// that is a string. It then hashes every Disclosure and parses only those a
// digest references, and decodes a Key Binding JWT payload, sized by the
// holder, only after the holder's signature. A service should still bound
// request size and concurrency.
//
// This package's own texts quote no token content except bounded values
// from jose. ISSUER_NOT_SUPPORTED, ISSUER_KEY_NOT_FOUND from
// issuerkey.ErrNoUsableKey, ISSUER_KEY_UNAVAILABLE, STATUS_UNAVAILABLE and
// the errors that wrap ctx.Err() carry the error of Policy.Issuers or
// Policy.Status as it was returned. Texts are for logs, not for the holder.
func Verify(ctx context.Context, compact string, p Policy) (*Result, error) {
	if ctx == nil {
		return nil, policyErr("Verify needs a non-nil context")
	}
	if p.Issuers == nil {
		return nil, policyErr("Policy.Issuers is required: an issuerkey.Resolver for the issuers you accept")
	}
	if p.MaxKBAge < 0 || p.ClockSkew < 0 {
		return nil, policyErr("Policy.MaxKBAge and Policy.ClockSkew must not be negative")
	}
	switch p.KeyBinding {
	case KeyBindingIfCnf, KeyBindingNotRequired:
	case KeyBindingRequired:
		if p.Audience == "" || p.Nonce == "" {
			return nil, policyErr("Policy.KeyBinding is KeyBindingRequired: set Policy.Audience and Policy.Nonce, which every Key Binding JWT is checked against (RFC 9901 §7.3 step 5f)")
		}
	default:
		return nil, policyErr("Policy.KeyBinding %d is none of KeyBindingIfCnf, KeyBindingRequired and KeyBindingNotRequired", p.KeyBinding)
	}
	now := p.Now
	if now.IsZero() {
		now = time.Now()
	}
	skew := p.ClockSkew
	if skew == 0 {
		skew = defaultClockSkew
	}

	issuerJWT, encoded, kbJWT, err := sdjwt.Split(compact)
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
			return reject(CodeTypInvalid, errors.New("typ is vc+sd-jwt, not dc+sd-jwt: a W3C VC secured with SD-JWT (verify it with credential/vc), or an SD-JWT VC from a draft before dc+sd-jwt (the issuer reissues it as dc+sd-jwt)"))
		}
		return reject(CodeTypInvalid, errors.New("typ is not dc+sd-jwt (draft-ietf-oauth-sd-jwt-vc-19 §2.2.1)"))
	}

	// draft 19 §2.5 leaves to verifier policy how the key is found. This SDK
	// resolves iss through Policy.Issuers and never takes a key from the
	// header (no x5c). Only a string iss is decoded before the signature, so
	// an unsigned payload, whatever its iss holds, costs a scan, not a decode.
	raw, err := jws.UnverifiedPayload(issuerJWT)
	if err != nil {
		return reject(CodeMalformed, err)
	}
	// RFC 7519 §4.1.1: iss is a StringOrURI, so a JSON string.
	iss, hasIss, err := jose.DecodeJSONStringMember(raw, "iss")
	if err != nil {
		return reject(CodeMalformed, fmt.Errorf("Issuer-signed JWT payload: %w", err))
	}
	keys, err := p.Issuers.Keys(ctx, iss)
	switch {
	case errors.Is(err, issuerkey.ErrIssuerNotSupported):
		return reject(CodeIssuerNotSupported, err)
	// A definite answer, like ErrIssuerNotSupported, whatever ctx says.
	case errors.Is(err, issuerkey.ErrNoUsableKey):
		return reject(CodeIssuerKeyNotFound, err)
	case err != nil && ctx.Err() != nil:
		return nil, fmt.Errorf("digitalcredential: resolving the issuer keys: %w (Policy.Issuers: %v)", ctx.Err(), err)
	// The resolver's wiring, such as a Resolver not made by its constructor.
	case errors.Is(err, jose.ErrInvalidArgument):
		return nil, policyErr("Policy.Issuers: %v", err)
	case err != nil:
		return reject(CodeIssuerKeyUnavailable, fmt.Errorf("Policy.Issuers could not return the issuer keys: %w", err))
	}
	key, err := issuerkey.Select(keys, header)
	if err != nil {
		return reject(CodeIssuerKeyNotFound, err)
	}
	_, signed, err := jws.Verify(issuerJWT, key, p.AllowedAlgs)
	if err != nil {
		switch {
		case errors.Is(err, jose.ErrInvalidArgument):
			return nil, policyErr("Policy.AllowedAlgs: %v", err)
		case errors.Is(err, jws.ErrBadKey):
			return nil, policyErr("Policy.Issuers returned a key that is not P-256 or secp256k1 (issuerkey.Key): %v", err)
		case errors.Is(err, jws.ErrAlgNotAllowed):
			return reject(CodeAlgNotAllowed, err)
		case errors.Is(err, jws.ErrAlgKeyMismatch), errors.Is(err, jws.ErrBadSignature):
			return reject(CodeSignatureInvalid, err)
		default:
			return reject(CodeMalformed, err)
		}
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

	if err := jwt.CheckExpNbf(claims, now, skew); err != nil {
		switch {
		case errors.Is(err, jwt.ErrExpired):
			return reject(CodeExpired, err)
		case errors.Is(err, jwt.ErrNotYetValid):
			return reject(CodeNotYetValid, err)
		default:
			return reject(CodeMalformed, err)
		}
	}
	if err := jwt.CheckAud(claims, p.CredentialAudience); err != nil {
		if errors.Is(err, jwt.ErrAudience) {
			return reject(CodeAudienceMismatch, fmt.Errorf("Policy.CredentialAudience: %w", err))
		}
		return reject(CodeMalformed, err)
	}
	if vct, _ := claims["vct"].(string); vct == "" {
		return reject(CodeMalformed, errors.New("vct is absent, which draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 forbids, or not a non-empty string as §2.2.2.1 requires"))
	}
	st, err := readStatus(claims)
	if err != nil {
		return reject(CodeMalformed, err)
	}

	keyBound, err := checkKeyBinding(compact, kbJWT, payload, p, now, skew)
	if err != nil {
		return nil, err
	}

	res := &Result{Claims: claims, KeyBound: keyBound}
	if !st.present {
		return res, nil
	}
	if p.SkipStatus {
		res.StatusSkipped = true
		return res, nil
	}
	v, err := checkStatus(ctx, st, iss, p)
	if err != nil {
		return nil, err
	}
	accepted := p.AcceptedStatus
	if accepted == nil {
		accepted = []uint8{0x00}
	}
	if slices.Contains(accepted, v) {
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
		return reject(CodeStatusNotAccepted, fmt.Errorf("status 0x%02x is not in Policy.AcceptedStatus", v))
	}
}

// checkKeyBinding applies p.KeyBinding to the Key Binding JWT kbJWT, "" when
// none came, and reports whether one was checked. Its errors are *Error or
// ErrPolicy.
func checkKeyBinding(compact, kbJWT string, payload map[string]any, p Policy, now time.Time, skew time.Duration) (bool, error) {
	_, hasCnf := payload["cnf"]
	required := hasCnf
	switch p.KeyBinding {
	case KeyBindingRequired:
		required = true
	case KeyBindingNotRequired:
		required = false
	}
	if !required {
		if kbJWT == "" || p.IgnoreUncheckedKBJWT {
			return false, nil
		}
		if p.KeyBinding == KeyBindingNotRequired {
			return false, &Error{Code: CodeKBUnexpected, Err: errors.New("a Key Binding JWT came and Policy.KeyBinding is KeyBindingNotRequired: a Holder (RFC 9901 §7.2) or a verifier expecting an SD-JWT (§4) MUST reject it; set Policy.IgnoreUncheckedKBJWT if this verifier only does not need it")}
		}
		return false, &Error{Code: CodeKBUnexpected, Err: errors.New("a Key Binding JWT came with a credential that has no cnf claim, so no key checks it (draft-ietf-oauth-sd-jwt-vc-19 §2.4); set Policy.IgnoreUncheckedKBJWT to ignore it")}
	}
	// The credential first: when its cnf gives no key, no presentation of it
	// passes, so asking the holder for a Key Binding JWT would not help.
	if !hasCnf {
		return false, &Error{Code: CodeKBUnsupported, Err: errors.New("Policy.KeyBinding is KeyBindingRequired and the credential has no cnf claim, the key a Key Binding JWT is checked with (draft-ietf-oauth-sd-jwt-vc-19 §2.4)")}
	}
	holder, err := holderKey(payload)
	if errors.Is(err, ErrKeyBindingUnsupported) {
		return false, &Error{Code: CodeKBUnsupported, Err: err}
	}
	if err != nil {
		return false, &Error{Code: CodeMalformed, Err: err}
	}
	if kbJWT == "" {
		if p.KeyBinding == KeyBindingRequired {
			return false, &Error{Code: CodeKBMissing, Err: errors.New("Policy.KeyBinding is KeyBindingRequired and no Key Binding JWT came: the holder must send an SD-JWT+KB (RFC 9901 §7.3 step 2)")}
		}
		return false, &Error{Code: CodeKBMissing, Err: errors.New("the credential binds a holder key and no Key Binding JWT came: the holder must send an SD-JWT+KB, or set Policy.KeyBinding = KeyBindingNotRequired if this verifier does not require Key Binding (RFC 9901 §7.3 step 2, §9.5)")}
	}
	if p.Audience == "" || p.Nonce == "" {
		return false, policyErr("this presentation has a Key Binding JWT: set Policy.Audience and Policy.Nonce, or Policy.KeyBinding = KeyBindingNotRequired together with Policy.IgnoreUncheckedKBJWT if this verifier does not check Key Binding (RFC 9901 §7.3 step 5f)")
	}
	err = sdjwt.VerifyKBJWT(kbJWT, holder, sdjwt.KBWant{
		Audience: p.Audience,
		Nonce:    p.Nonce,
		// RFC 9901 §4.3.1: over the SD-JWT as received, up to the last ~.
		SDHash:      sdjwt.SDHash(compact[:len(compact)-len(kbJWT)]),
		Now:         now,
		MaxAge:      p.MaxKBAge,
		ClockSkew:   skew,
		AllowedAlgs: p.AllowedAlgs,
	})
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, jose.ErrInvalidArgument):
		return false, policyErr("checking the Key Binding JWT: %v", err)
	case errors.Is(err, sdjwt.ErrKBAudience):
		return false, &Error{Code: CodeKBAudienceMismatch, Err: err}
	case errors.Is(err, sdjwt.ErrKBNonce):
		return false, &Error{Code: CodeKBNonceMismatch, Err: err}
	case errors.Is(err, sdjwt.ErrKBSDHash):
		return false, &Error{Code: CodeKBSDHashMismatch, Err: err}
	default:
		return false, &Error{Code: CodeKBInvalid, Err: err}
	}
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

// checkStatus asks p.Status for the status st refers to. Its errors are
// *Error, ErrPolicy, or wrap ctx.Err().
func checkStatus(ctx context.Context, st statusClaim, iss string, p Policy) (uint8, error) {
	if !st.list {
		return 0, &Error{Code: CodeStatusUnavailable, Err: errors.New("status has no status_list, the one mechanism this SDK checks (draft-ietf-oauth-status-list-21 §8.3 step 1); Policy.SkipStatus accepts it unchecked")}
	}
	// No list holds more entries than an int counts.
	if st.pastInt {
		return 0, &Error{Code: CodeMalformed, Err: fmt.Errorf("status_list idx is past every status list: %w", statuslist.ErrIndexOutOfBounds)}
	}
	if p.Status == nil {
		return 0, policyErr("the credential has a status_list: set Policy.Status, such as a statuslist.Checker, or Policy.SkipStatus")
	}
	v, err := p.Status.Status(ctx, st.ref, iss)
	switch {
	case err == nil:
		return v, nil
	// A definite answer: §8.3 step 6 says MUST reject, whatever ctx says.
	case errors.Is(err, statuslist.ErrIndexOutOfBounds):
		return 0, &Error{Code: CodeMalformed, Err: err}
	case ctx.Err() != nil:
		return 0, fmt.Errorf("digitalcredential: checking the status: %w (Policy.Status: %v)", ctx.Err(), err)
	// Verify validated the Ref, so this is the checker's wiring, such as a
	// statuslist.Checker not made by NewChecker, or its resolver returning a
	// key not on P-256 or secp256k1, as the credential path reports it.
	case errors.Is(err, jose.ErrInvalidArgument), errors.Is(err, jws.ErrBadKey):
		return 0, policyErr("Policy.Status: %v", err)
	// Never by jose.ErrMalformed: a fetch can fail with it too.
	default:
		return 0, &Error{Code: CodeStatusUnavailable, Err: fmt.Errorf("Policy.Status: %w", err)}
	}
}

func reject(c Code, err error) (*Result, error) {
	return nil, &Error{Code: c, Err: err}
}

// policyErr is ErrPolicy with the fix, in Policy's words; a cause goes in
// with %v, so ErrPolicy matches nothing else.
func policyErr(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrPolicy}, a...)...)
}
