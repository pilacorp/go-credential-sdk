// The error model of package dc: codes for a rejected token, and the
// sentinels that are not codes.

package dc

import (
	"errors"
	"strings"
)

// Code names why Parse or Credential.Verify rejected a token. The strings are
// part of the API: a caller may branch on them and store them. New codes may
// be added; a code is never renamed or removed.
type Code string

const (
	// CodeMalformed: the token is not a well-formed SD-JWT VC. From Parse,
	// the string is not an SD-JWT in compact form (RFC 9901 §4): see
	// sdjwt.Split for the structural rules and the size limits. From Verify
	// also: a JWS or JSON this SDK does not read, a header with crit or b64,
	// an iss, exp, nbf or aud of the wrong type, a vct, aka_vcts or
	// vct#integrity of the wrong shape (draft-ietf-oauth-sd-jwt-vc-19
	// §2.2.2.1-2.2.2.3, §5.3), or a status claim of the wrong shape
	// (draft-ietf-oauth-status-list-21 §6.2). When Key Binding is required,
	// so cnf is read, also a cnf or cnf.jwk that is not a JSON object (RFC
	// 7800 §3), a cnf.jwk that jwk.ToPublicKey refuses as broken or that
	// holds a symmetric key in this unencrypted JWT (§3.2), or a cnf with more
	// than one of jwk, jwe and jku (§3.1). Or its status_list idx is outside
	// the issuer's Status List, where draft-ietf-oauth-status-list-21 §8.3
	// step 6 says the token MUST be rejected; Err then wraps
	// statuslist.ErrIndexOutOfBounds. The idx is compared with a list only
	// when status is checked.
	CodeMalformed Code = "MALFORMED"
	// CodeTypInvalid: the Issuer-signed JWT typ is not dc+sd-jwt. The Issuer
	// MUST write it (draft-ietf-oauth-sd-jwt-vc-19 §2.2.1), so a token without
	// it is not an SD-JWT VC; RFC 9901 §9.11 RECOMMENDS that verifiers check
	// it, and Verify always does. vc+sd-jwt is refused too: draft 19
	// Appendix C removed the text that allowed it during the transition.
	CodeTypInvalid Code = "TYP_INVALID"
	// CodeIssuerNotSupported: the issuerkey.Resolver given to Verify answered
	// issuerkey.ErrIssuerNotSupported: this verifier does not accept iss.
	CodeIssuerNotSupported Code = "ISSUER_NOT_SUPPORTED"
	// CodeIssuerKeyNotFound: no single key verifies the token
	// (issuerkey.Select). Err keeps Select's text, which tells the cases
	// apart: the issuer publishes no key or none with the header kid (rotated
	// or revoked, never this issuer's, or skipped by the resolver as a key it
	// cannot use); two keys share the kid, or there is no kid and several
	// keys (the issuer's metadata or header is at fault); the resolver
	// returned a nil key (the caller's resolver). It is also the resolver
	// answering issuerkey.ErrNoUsableKey: the issuer's document gives no
	// usable key, and Err says why.
	CodeIssuerKeyNotFound Code = "ISSUER_KEY_NOT_FOUND"
	// CodeIssuerKeyUnavailable: the resolver could not find out the issuer's
	// keys while ctx was live, and draft-ietf-oauth-sd-jwt-vc-19 §2.5 says to
	// reject when the key cannot be validated. Err wraps the resolver's
	// error; a later call may succeed.
	CodeIssuerKeyUnavailable Code = "ISSUER_KEY_UNAVAILABLE"
	// CodeAlgNotAllowed: the Issuer-signed JWT alg is none, not ES256 or
	// ES256K, or not in WithAllowedAlgs (RFC 9901 §7.1 step 2a).
	CodeAlgNotAllowed Code = "ALG_NOT_ALLOWED"
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
	// CodeExpired: the time of the check is at or after exp plus the clock
	// skew (RFC 7519 §4.1.4).
	CodeExpired Code = "EXPIRED"
	// CodeNotYetValid: the time of the check is before nbf minus the clock
	// skew (RFC 7519 §4.1.5).
	CodeNotYetValid Code = "NOT_YET_VALID"
	// CodeAudienceMismatch: the Issuer-signed JWT has aud and it does not
	// list the value of WithCredentialAudience, or that option is not passed
	// (RFC 7519 §4.1.3).
	CodeAudienceMismatch Code = "AUDIENCE_MISMATCH"
	// CodeVCTNotAccepted: neither vct nor any aka_vcts element, nor with
	// WithExtendedVCTMatch any type of the extends chain, is in
	// WithAcceptedVCTs (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.1, §2.2.2.2,
	// §5.4).
	CodeVCTNotAccepted Code = "VCT_NOT_ACCEPTED"
	// CodeKBMissing: Key Binding is required, the credential's cnf holds a
	// key this SDK checks Key Binding with, and no Key Binding JWT came (RFC
	// 9901 §7.3 step 2): the holder can present it again with one.
	CodeKBMissing Code = "KB_MISSING"
	// CodeKBUnexpected: a Key Binding JWT came that Verify does not check,
	// and WithIgnoreUncheckedKBJWT is not passed. Under
	// KeyBindingNotRequired, a Holder (RFC 9901 §7.2) or a verifier expecting
	// an SD-JWT (§4) MUST reject it. Under KeyBindingIfCnf, with a credential
	// that has no cnf, no key can check it (draft-ietf-oauth-sd-jwt-vc-19
	// §2.4); refusing it is this SDK's default, which
	// WithIgnoreUncheckedKBJWT turns off.
	CodeKBUnexpected Code = "KB_UNEXPECTED"
	// CodeKBUnsupported: Key Binding is required and cannot be checked for
	// this credential: the mode is KeyBindingRequired and the credential has
	// no cnf (draft-ietf-oauth-sd-jwt-vc-19 §2.4), or its cnf is not one this
	// SDK checks Key Binding with (ErrKeyBindingUnsupported: no jwk, or a key
	// type jose/jwk does not convert). No presentation of this credential
	// passes, with a Key Binding JWT or without; the code says nothing about
	// whether the credential is otherwise valid.
	CodeKBUnsupported Code = "KB_UNSUPPORTED"
	// CodeKBInvalid: the Key Binding JWT fails RFC 9901 §7.3 step 5 other
	// than by a differing aud, nonce or sd_hash (sdjwt.ErrKBInvalid).
	CodeKBInvalid Code = "KB_INVALID"
	// CodeKBAudienceMismatch: the Key Binding JWT aud is a string other than
	// the value of WithAudience (RFC 9901 §7.3 step 5f): made for another
	// verifier.
	CodeKBAudienceMismatch Code = "KB_AUDIENCE_MISMATCH"
	// CodeKBNonceMismatch: the Key Binding JWT nonce is a string other than
	// the value of WithNonce (RFC 9901 §7.3 step 5f): made for another
	// transaction.
	CodeKBNonceMismatch Code = "KB_NONCE_MISMATCH"
	// CodeKBSDHashMismatch: the Key Binding JWT sd_hash is a string that does
	// not match the SD-JWT received (RFC 9901 §7.3 step 5g): Disclosures were
	// dropped or added after it was signed.
	CodeKBSDHashMismatch Code = "KB_SD_HASH_MISMATCH"
	// CodeTypeMetadataNotFound: under WithTypeMetadata, no resolver has Type
	// Metadata for the credential's vct (typemeta.ErrNotFound).
	CodeTypeMetadataNotFound Code = "TYPE_METADATA_NOT_FOUND"
	// CodeTypeMetadataUnavailable: under WithTypeMetadata, the resolver
	// failed while ctx was live; a later call may pass.
	CodeTypeMetadataUnavailable Code = "TYPE_METADATA_UNAVAILABLE"
	// CodeTypeMetadataInvalid: the Type Metadata cannot be processed
	// (draft-ietf-oauth-sd-jwt-vc-19 §5.7). Under WithTypeMetadata, a document
	// fails its integrity, its structure or its vct, or the extends chain
	// cannot be completed (typemeta.ErrInvalid); under either option, the
	// claim metadata breaks §5.6 or extends loops (typemeta.ErrClaims,
	// typemeta.ErrCycle).
	CodeTypeMetadataInvalid Code = "TYPE_METADATA_INVALID"
	// CodeTypeMetadataViolated: the payload breaks the claim metadata of its
	// Type Metadata (draft 19 §5.6, typemeta.ErrViolated): a path error, a
	// mandatory claim certainly missing, or a claim against its sd.
	CodeTypeMetadataViolated Code = "TYPE_METADATA_VIOLATED"
	// CodeRevoked: the status is 0x01, INVALID in
	// draft-ietf-oauth-status-list-21 §7.1, and not in WithAcceptedStatus.
	CodeRevoked Code = "REVOKED"
	// CodeSuspended: the status is 0x02, SUSPENDED in
	// draft-ietf-oauth-status-list-21 §7.1, and not in WithAcceptedStatus.
	CodeSuspended Code = "SUSPENDED"
	// CodeStatusNotAccepted: any other status not in WithAcceptedStatus.
	CodeStatusNotAccepted Code = "STATUS_NOT_ACCEPTED"
	// CodeStatusUnavailable: no statement about the status could be made
	// (draft-ietf-oauth-status-list-21 §8.3, SHOULD be rejected): a failed
	// fetch, a list token failing its checks, a uri the checker does not
	// fetch, or a status mechanism other than status_list. Some causes pass
	// on retry, others do not. A caller whose own policy accepts such a token
	// calls Verify again with WithoutStatusCheck.
	CodeStatusUnavailable Code = "STATUS_UNAVAILABLE"
)

// Error is a token that Parse or Credential.Verify rejected. Code says why,
// and Err holds the cause, for logs only, never nil in an Error the SDK
// returns. errors.Is and errors.As reach through Err, so the sentinel of the
// package that refused it, such as jose.ErrMalformed, and a resolver's or
// checker's own error stay matchable.
type Error struct {
	Code Code
	Err  error
}

func (e *Error) Error() string {
	// An Error a caller builds may leave Err nil.
	if e.Err == nil {
		return "dc: " + string(e.Code)
	}
	return "dc: " + string(e.Code) + ": " + strings.TrimPrefix(e.Err.Error(), "dc: ")
}

func (e *Error) Unwrap() error { return e.Err }

// ErrKeyBindingUnsupported: the credential's cnf is in a form this SDK cannot
// use for Key Binding, when Present makes a Key Binding JWT: a cnf without
// jwk, or a cnf.jwk of a key type or curve jose/jwk does not convert (then
// jose.ErrUnsupportedKey too). A symmetric cnf.jwk (kty oct) is not one of
// them: RFC 7800 §3.2 forbids it in a JWS, so it is jose.ErrMalformed. draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 lets
// cnf hold any RFC 7800 confirmation method and recommends a JWK; binding
// only to cnf.jwk with an EC key on P-256 or secp256k1 is this SDK's limit.
// The SDK does not check a cnf it cannot use, so the error says neither that
// the credential is valid nor that it is broken, and wraps neither
// jose.ErrMalformed nor jose.ErrInvalidArgument.
var ErrKeyBindingUnsupported = errors.New("dc: this SDK cannot use this credential's cnf for Key Binding")

// ErrPolicy: Credential.Verify was called with arguments, options or a
// dependency that cannot verify: the caller's code or configuration is at
// fault, not the token. Some cases show only for some tokens and only after
// the caller's own network calls: a resolver key on a curve this SDK does not
// verify with (the error then also wraps the jws.Verify error), no
// WithAudience or WithNonce when a Key Binding JWT must be checked, no
// WithStatus for a credential with status_list, or a resolver or checker
// error wrapping jose.ErrInvalidArgument. So do not treat it as a
// startup-only error. Apart from those key errors and a WithAllowedAlgs alg
// this SDK does not implement (jose.ErrUnsupportedAlg), it wraps no other
// sentinel.
var ErrPolicy = errors.New("dc: invalid verify policy")
