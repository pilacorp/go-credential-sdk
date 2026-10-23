// Error sentinels of jose. No standard defines them.

package jose

import "errors"

// Every error jose returns wraps one of these, so a caller maps it with
// errors.Is and keeps the wrapped detail for logs. jose/jws returns these too;
// see its errors for when. jose/jwk has its own ErrBadKey.
var (
	// ErrMalformed: a base64url segment or a JSON value does not have the
	// required shape.
	ErrMalformed = errors.New("jose: malformed")
	// ErrInvalidArgument: a caller mistake rather than bad input data: a value
	// EncodeJSON cannot encode.
	ErrInvalidArgument = errors.New("jose: invalid argument")
)
