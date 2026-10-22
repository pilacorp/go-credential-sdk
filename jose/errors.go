package jose

import "errors"

// Every error the package returns wraps one of these, so a caller maps it with
// errors.Is and keeps the wrapped detail for logs.
var (
	// ErrMalformed: the token, a segment or a JSON value does not have the
	// required shape.
	ErrMalformed = errors.New("jose: malformed")
	// ErrAlgNotAllowed: alg is not ES256 or ES256K, or not in the allowed list.
	ErrAlgNotAllowed = errors.New("jose: alg not allowed")
	// ErrAlgKeyMismatch: the header alg does not match the curve of the key.
	ErrAlgKeyMismatch = errors.New("jose: alg does not match the key")
	// ErrSignatureFormat: a signature that is not 64-byte r||s (65 with a
	// trailing recovery id is accepted from a signer only), or a signer that
	// returned r or s outside [1, n-1].
	ErrSignatureFormat = errors.New("jose: signature format")
	// ErrBadSignature: the signature does not verify.
	ErrBadSignature = errors.New("jose: bad signature")
	// ErrBadKey: a key that is nil, on an unsupported curve, not on its curve,
	// or a JWK that is not a public EC key on P-256 or secp256k1.
	ErrBadKey = errors.New("jose: bad key")
	// ErrUnsupportedHeader: a header with crit, or with b64 other than true.
	ErrUnsupportedHeader = errors.New("jose: unsupported header")
)
