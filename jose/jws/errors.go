// Error sentinels of jose/jws. No standard defines them.

package jws

import "errors"

// Every function of this package wraps one of these, or a jose sentinel, so a
// caller maps every error with errors.Is:
//   - jose.ErrMalformed (Verify, UnverifiedHeader, UnverifiedPayload): not
//     three dot-separated parts, a part that is not strict base64url, a
//     header over 64 KiB or not a JSON object read by
//     jose.DecodeJSONObject, or an alg that is not a string;
//   - jose.ErrInvalidArgument (Sign): a nil signer or context, a header alg
//     that differs from the signer's, or a header EncodeJSON cannot write,
//     over 64 KiB, or Verify could not read back; (DigestSigner) a nil sign
//     function;
//   - jose.ErrUnsupportedAlg: a signer alg (Sign, DigestSigner) or an allowed
//     entry (Verify) other than ES256 and ES256K; never an alg read from a
//     token, which is ErrAlgNotAllowed;
//   - jose.ErrUnsupportedKey: a key that is not an ECDSA key on P-256 or
//     secp256k1 (Sign, Verify, PrivateKeySigner).
//
// ErrSignerFailed wraps the Signer's own error too, so errors.Is also matches
// what that error wraps (context.Canceled, or an SDK sentinel a Signer
// returns): check ErrSignerFailed before this package's other sentinels.
var (
	// ErrAlgNotAllowed (Verify only): the header alg is not ES256 or ES256K,
	// or not in the allowed list. For an alg the SDK does not implement the
	// text names the algs it supports.
	ErrAlgNotAllowed = errors.New("jws: alg not allowed")
	// ErrAlgKeyMismatch: the signer alg (Sign) or the header alg (Verify)
	// does not match the curve of the key.
	ErrAlgKeyMismatch = errors.New("jws: alg does not match the key")
	// ErrBadSignature (Verify only): the signature is not 64-byte r||s, has r
	// or s outside [1, n-1], or does not verify.
	ErrBadSignature = errors.New("jws: bad signature")
	// ErrBadKey: an ECDSA key on a supported curve that is broken: nil, a
	// coordinate out of range or a point off its curve (Sign, Verify,
	// PrivateKeySigner), or a d outside [1, n-1] or not matching its public
	// key (PrivateKeySigner).
	ErrBadKey = errors.New("jws: bad key")
	// ErrUnsupportedHeader: a header with crit or b64.
	ErrUnsupportedHeader = errors.New("jws: unsupported header")
	// ErrSignerFailed (Sign only): the Signer returned an error (its key store
	// or the network is down, or ctx ended); the signer's own error is wrapped
	// too, so check ErrSignerFailed before this package's other sentinels.
	ErrSignerFailed = errors.New("jws: signer failed")
	// ErrSelfCheck (Sign only): the token does not verify with pub: the
	// signer used another key, or answered something other than 64-byte r||s.
	ErrSelfCheck = errors.New("jws: signature does not verify with the signer's key")
)
