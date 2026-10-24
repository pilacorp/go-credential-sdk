// Error sentinels of jose. No standard defines them.

package jose

import "errors"

// Every error jose returns wraps one of these, so a caller maps it with
// errors.Is and keeps the wrapped detail for logs. jose/jws returns these too;
// see its errors for when. jose/jwt returns ErrMalformed. jose/sdjwt returns
// both, plus its four ErrKB* errors when a Key Binding JWT fails and the
// jose/jws errors when signing one fails. VerifyKBJWT wraps the jws or jose
// cause under ErrKBInvalid, so a malformed KB-JWT matches both ErrKBInvalid
// and ErrMalformed, and a caller tests the ErrKB* errors first. jose/jwk has
// its own ErrBadKey.
var (
	// ErrMalformed: a base64url segment or a JSON value does not have the
	// required shape.
	ErrMalformed = errors.New("jose: malformed")
	// ErrInvalidArgument: a caller mistake rather than bad input data, such as
	// a value EncodeJSON cannot encode.
	ErrInvalidArgument = errors.New("jose: invalid argument")
)
