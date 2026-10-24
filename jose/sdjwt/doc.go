// Package sdjwt implements the SD-JWT format of RFC 9901 (Selective
// Disclosure for JSON Web Tokens, November 2025): disclosures and their
// digests (§4.2), concealing claims on the issuer side (Conceal), splitting
// the compact form (Split, §4), recreating the payload on the holder and
// verifier side (Recreate, §7.1 steps 3 to 5), and the Key Binding JWT
// (SDHash, NewKBJWT and VerifyKBJWT, §4.3 and §7.3 step 5).
//
// It does not sign or verify the Issuer-signed JWT (jose/jws does), check
// validity claims of the Issuer-signed JWT such as exp or nbf (§7.1 step 6),
// or read the claims of an SD-JWT profile such as vct or iss. It supports
// only the sha-256 digest algorithm (§4.1.1) and only the compact
// serialization, not JWS JSON (§8).
//
// Bad input wraps jose.ErrMalformed, a caller mistake wraps
// jose.ErrInvalidArgument, and the message says what is wrong; NewKBJWT also
// passes on the errors of jws.Sign. The only sentinels of this package are
// the four ErrKB* errors of VerifyKBJWT, one per kind of Key Binding JWT
// failure, so a verifier can report each apart. ErrKBInvalid wraps the
// jws.Verify or jose cause, so a malformed KB-JWT matches both ErrKBInvalid
// and jose.ErrMalformed, and a caller tests the ErrKB* errors first.
package sdjwt
