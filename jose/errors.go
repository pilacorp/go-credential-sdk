// Error sentinels of jose. No standard defines them.

package jose

import "errors"

// Every error jose returns wraps one of these, so a caller maps it with
// errors.Is and keeps the wrapped detail for logs. jose/jws returns these too;
// see its errors for when. jose/jwt returns ErrMalformed for a value that is
// not a NumericDate or an aud of the wrong type and ErrInvalidArgument for a
// negative skew; an exp, nbf or aud that fails its check wraps jwt.ErrExpired,
// jwt.ErrNotYetValid or jwt.ErrAudience. jose/sdjwt returns
// both, plus its four ErrKB* errors when a Key Binding JWT fails and the
// jose/jws errors when signing one fails. VerifyKBJWT wraps the jws or jose
// cause under ErrKBInvalid, so a malformed KB-JWT matches both ErrKBInvalid
// and ErrMalformed, and a caller tests the ErrKB* errors first. jose/jwk has
// its own ErrBadKey, and ErrUnsupportedKey, apart from it, for a valid JWK of
// a key type it does not convert.
var (
	// ErrMalformed: a base64url segment or a JSON value does not have the
	// required shape.
	ErrMalformed = errors.New("jose: malformed")
	// ErrInvalidArgument: a caller mistake rather than bad input data, such as
	// a value EncodeJSON cannot encode.
	ErrInvalidArgument = errors.New("jose: invalid argument")
)
