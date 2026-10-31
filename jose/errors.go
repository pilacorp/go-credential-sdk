// Error sentinels of jose. No standard defines them.

package jose

import "errors"

// Every error the packages of this module return wraps one of these, or a
// sentinel of the package itself, so a caller maps it with errors.Is and keeps
// the wrapped detail for logs. Each package lists in its own errors when it
// returns which. A key of a supported kind that is broken (nil, coordinates
// out of range, a point off its curve) is the package's ErrBadKey, never
// ErrUnsupportedKey, so no error matches both.
var (
	// ErrMalformed: the input does not have the shape a standard requires,
	// such as a base64url segment or a JSON value.
	ErrMalformed = errors.New("jose: malformed")
	// ErrInvalidArgument: a caller mistake rather than bad input data, such as
	// a value EncodeJSON cannot encode.
	ErrInvalidArgument = errors.New("jose: invalid argument")
	// ErrUnsupportedAlg: an alg the caller supplies (a Signer's alg,
	// DigestSigner's alg, an entry of an allowed list) that the SDK does not
	// implement. The text names it and the algs supported. An alg read from a
	// received token is never this error: jws.Verify refuses it with
	// jws.ErrAlgNotAllowed.
	ErrUnsupportedAlg = errors.New("jose: unsupported alg")
	// ErrUnsupportedKey: a key type or curve the SDK does not implement. The
	// text names what was received and what is supported.
	ErrUnsupportedKey = errors.New("jose: unsupported key")
)
