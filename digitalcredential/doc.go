// Package dc implements IETF SD-JWT VC (dc+sd-jwt,
// draft-ietf-oauth-sd-jwt-vc-19) on RFC 9901 SD-JWT, for the three roles of
// the standard. Import it as github.com/pilacorp/go-credential-sdk/digitalcredential;
// for a W3C VC secured with SD-JWT (vc+sd-jwt) use credential/vc.
//
// A Credential holds one SD-JWT VC string and never changes. The Issuer makes
// one with Issue, signing through a jws.Signer it supplies; the Holder reads
// what it receives with Parse and builds what it sends to a Verifier with
// Credential.Present, choosing the claims to disclose and, when asked, adding
// a Key Binding JWT (RFC 9901 §4.3). Parse checks only the structure of the
// string. The Verifier checks what it receives with Credential.Verify, which
// resolves the Issuer's key through an issuerkey.Resolver and reads the
// credential's status through a StatusChecker such as a *statuslist.Checker
// (draft-ietf-oauth-status-list-21).
//
// Errors of Parse are *Error, with a Code a caller can branch on and store;
// Verify returns *Error for a rejected token and ErrPolicy for a fault of
// the caller (see Credential.Verify). Issue and Present return errors
// wrapping the classes of package jose:
// jose.ErrInvalidArgument for a caller mistake, jose.ErrMalformed for a
// credential that is not well formed, jose.ErrUnsupportedKey or
// jose.ErrUnsupportedAlg for what this SDK does not implement, plus the
// sentinels of jws, jwk and ErrKeyBindingUnsupported. Error text is for logs,
// not for display to the Holder.
package dc
