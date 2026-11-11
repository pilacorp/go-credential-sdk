package statuslist

import (
	"errors"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/safehttp"
)

// The failures Checker.Status finds in a Ref's uri or in a Status List
// Token. An error of Status wraps at most one of them, and so does an error
// of dc.Verify through it; none is jose.ErrInvalidArgument.
var (
	// ErrURINotSupported: the uri is not an https URL with a host and no
	// userinfo, nor, with Config.InsecureHTTP, an http one; no request is
	// sent. Draft 21 §6.2 leaves this rule to the Relying Party.
	ErrURINotSupported = errors.New("statuslist: status list uri not supported")
	// ErrTokenType: the typ of the Status List Token is not statuslist+jwt
	// (§5.1; RFC 8725 §3.11).
	ErrTokenType = errors.New("statuslist: token typ is not statuslist+jwt")
	// ErrSubjectMismatch: the sub of the token is not the uri of the
	// Referenced Token (§5.1, §8.3 step 4a).
	ErrSubjectMismatch = errors.New("statuslist: token sub is not the uri of the Referenced Token")
	// ErrIssuerMismatch: the token has an iss other than the issuer of the
	// Referenced Token (RFC 8725 §3.8).
	ErrIssuerMismatch = errors.New("statuslist: token iss is not the issuer of the Referenced Token")
	// ErrIssuedInFuture: the iat of the token is later than now plus the
	// clock skew. An SDK policy that draft 21 §5.1 rule 4 leaves to the
	// Relying Party: Config.MaxAge counts age from iat and the cache keeps the
	// list with the later iat, so a future iat would escape both.
	// Config.ClockSkew sets the leeway.
	ErrIssuedInFuture = errors.New("statuslist: token iat is in the future")
	// ErrTooOld: the iat of the token is older than Config.MaxAge plus the
	// clock skew (§8.3 step 4b).
	ErrTooOld = errors.New("statuslist: token is older than Config.MaxAge")
)

// The causes of a failed fetch of a Status List Token that Status itself
// finds (draft 21 §8.2, §11.4). An error of Status, and of dc.Verify through
// it, wraps one when it applies. Packages issuermeta and typemeta export the
// same values, and a Config.Issuers from issuermeta wraps them for its own
// retrievals; the error text names the retrieval that failed.
var (
	// ErrRedirectTargetNotAllowed: Status refused, before sending it, a
	// redirect to a URL that is not https with a host and no userinfo, nor,
	// with Config.InsecureHTTP, an http one.
	ErrRedirectTargetNotAllowed = safehttp.ErrRedirectTargetNotAllowed
	// ErrTooManyRedirects: the fetch met more than 3 redirects (RFC 9110
	// §15.4).
	ErrTooManyRedirects = safehttp.ErrTooManyRedirects
	// ErrBodyTooLarge: the body of the final response is over 1 MiB.
	ErrBodyTooLarge = safehttp.ErrBodyTooLarge
	// ErrAddressBlocked: the default client refused to connect to an
	// address that is not globally reachable. A Config.HTTPClient has its
	// own rules.
	ErrAddressBlocked = safehttp.ErrBlockedAddress
)

// StatusError: the final response has a status that is not 2xx (§8.2), held
// in Code; errors.As on an error of Status reaches it. It is the same type as
// issuermeta.StatusError and typemeta.StatusError, so one errors.As target
// matches all three.
type StatusError = safehttp.StatusError
