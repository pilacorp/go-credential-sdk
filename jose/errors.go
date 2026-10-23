// Error sentinels of jose, jose/jws and jose/jwk. No standard defines them.

package jose

import "errors"

// Every error jose, jose/jws and jose/jwk return wraps one of these, so a
// caller maps it with errors.Is and keeps the wrapped detail for logs.
var (
	// ErrMalformed: the token, a segment or a JSON value does not have the
	// required shape.
	ErrMalformed = errors.New("jose: malformed")
	// ErrAlgNotAllowed: alg is not ES256 or ES256K, or not in the allowed list.
	// A header alg that differs from the alg passed to Sign is
	// ErrInvalidArgument.
	ErrAlgNotAllowed = errors.New("jose: alg not allowed")
	// ErrAlgKeyMismatch: the header alg does not match the curve of the key.
	ErrAlgKeyMismatch = errors.New("jose: alg does not match the key")
	// ErrSignatureFormat (Sign only): the signer returned something that is not
	// 64-byte r||s (or 65-byte r||s||v under ES256K), r or s outside [1, n-1],
	// or a signature that does not verify with its own public key.
	ErrSignatureFormat = errors.New("jose: signature format")
	// ErrBadSignature (Verify only): the token's signature is not 64-byte
	// r||s, has r or s outside [1, n-1], or does not verify.
	ErrBadSignature = errors.New("jose: bad signature")
	// ErrSigner: the Signer returned an error (Vault, HSM or network down); the
	// signer's own error is wrapped too.
	ErrSigner = errors.New("jose: signer failed")
	// ErrInvalidArgument: a caller mistake rather than bad input data: a nil
	// signer, a header alg that differs from the alg argument, or a value
	// EncodeJSON cannot encode.
	ErrInvalidArgument = errors.New("jose: invalid argument")
	// ErrBadKey: a key that is nil, on an unsupported curve, not on its curve,
	// or a JWK that is not a public EC key on P-256 or secp256k1.
	ErrBadKey = errors.New("jose: bad key")
	// ErrUnsupportedHeader: a header with crit, or with b64 other than true.
	ErrUnsupportedHeader = errors.New("jose: unsupported header")
)
