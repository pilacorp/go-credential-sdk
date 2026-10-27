// Error sentinels of jose/jws. No standard defines them.

package jws

import "errors"

// Sign, Verify, UnverifiedHeader and UnverifiedPayload wrap one of these, or a
// jose sentinel, so a caller maps every error with errors.Is:
//   - jose.ErrMalformed (Verify, UnverifiedHeader, UnverifiedPayload): not
//     three dot-separated parts, a part that is not strict base64url, a
//     header over 64 KiB or not a JSON object read by
//     jose.DecodeJSONObject, or an alg that is not a string;
//   - jose.ErrInvalidArgument (Sign): a nil signer, a header alg that differs
//     from the alg of pub, or a header EncodeJSON cannot write, over 64 KiB,
//     or Verify could not read back; (Verify) an allowed entry other than
//     ES256 and ES256K.
var (
	// ErrAlgNotAllowed (Verify only): the header alg is not ES256 or ES256K,
	// or not in the allowed list.
	ErrAlgNotAllowed = errors.New("jws: alg not allowed")
	// ErrAlgKeyMismatch (Verify only): the header alg does not match the
	// curve of the key.
	ErrAlgKeyMismatch = errors.New("jws: alg does not match the key")
	// ErrBadSignature (Verify only): the signature is not 64-byte r||s, has r
	// or s outside [1, n-1], or does not verify.
	ErrBadSignature = errors.New("jws: bad signature")
	// ErrBadKey: the key given to Sign or Verify is nil, on a curve other than
	// P-256 or secp256k1, or not on its curve.
	ErrBadKey = errors.New("jws: bad key")
	// ErrUnsupportedHeader: a header with crit or b64.
	ErrUnsupportedHeader = errors.New("jws: unsupported header")
	// ErrSigner (Sign only): the Signer returned an error (its key store or the
	// network is down); the signer's own error is wrapped too.
	ErrSigner = errors.New("jws: signer failed")
	// ErrSelfCheck (Sign only): the token does not verify with pub: the
	// signer used another key, or answered something other than 64-byte r||s.
	ErrSelfCheck = errors.New("jws: signature does not verify with the signer's key")
)
