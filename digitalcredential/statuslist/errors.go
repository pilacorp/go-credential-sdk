package statuslist

import (
	"errors"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/safehttp"
)

// Every error the package returns wraps one of these, so a caller maps it with
// errors.Is and keeps the wrapped detail for logs. A Checker failure of any kind
// is an error, never a status value: Verify turns it into STATUS_UNAVAILABLE.
var (
	// ErrInvalidArgument: a size, bit width, value, claim or key that the
	// caller passed is not allowed.
	ErrInvalidArgument = errors.New("statuslist: invalid argument")
	// ErrIndexOutOfRange: the index is negative or not below the list size.
	ErrIndexOutOfRange = errors.New("statuslist: index out of range")
	// ErrMalformed: an lst, a token or a chain list id that does not have the
	// required shape.
	ErrMalformed = errors.New("statuslist: malformed")
	// ErrTooLarge: a list that inflates past the limit, or one built larger
	// than DefaultMaxListBytes.
	ErrTooLarge = errors.New("statuslist: too large")
	// ErrSelfCheck: SignToken produced a token that does not verify with
	// SigningKey.Public (the signer holds another key).
	ErrSelfCheck = errors.New("statuslist: signed token does not verify with the public key")
	// ErrFetch: the status list token could not be fetched (network, status,
	// Content-Type, size, redirect, blocked address).
	ErrFetch = errors.New("statuslist: fetch failed")
	// ErrIssuerKey: the resolver did not return a key for the credential's
	// issuer and the token's kid.
	ErrIssuerKey = errors.New("statuslist: issuer key")
	// ErrTokenInvalid: the status list token failed a check (signature, typ,
	// sub, iat, exp).
	ErrTokenInvalid = errors.New("statuslist: token invalid")
	// ErrBlockedAddress: a fetch would connect to an internal address. It is
	// the same value issuermeta returns, so one errors.Is covers both.
	ErrBlockedAddress = safehttp.ErrBlockedAddress
)
