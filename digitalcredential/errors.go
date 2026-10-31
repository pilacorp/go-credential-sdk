// The error model of package dc: codes for a rejected token, and the
// sentinels that are not codes.

package dc

import (
	"errors"
	"strings"
)

// Code names why Parse rejected a token. The strings are part of the API: a
// caller may branch on them and store them. New codes may be added; a code is
// never renamed or removed.
type Code string

// CodeMalformed: the string is not an SD-JWT in compact form (RFC 9901 §4):
// see sdjwt.Split for the structural rules and the size limits.
const CodeMalformed Code = "MALFORMED"

// Error is a token that Parse rejected. Code says why, and Err holds the
// cause, so errors.Is still finds the sentinel of the package that refused
// it, such as jose.ErrMalformed.
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
