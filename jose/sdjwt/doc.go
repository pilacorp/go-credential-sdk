// Package sdjwt implements the SD-JWT format of RFC 9901 (Selective
// Disclosure for JSON Web Tokens, November 2025): disclosures and their
// digests (§4.2), concealing claims on the issuer side (Conceal), splitting
// the compact form (Split, §4) and recreating the payload on the holder and
// verifier side (Recreate, §7.1 steps 3 to 5).
//
// It does not sign or verify the Issuer-signed JWT (jose/jws does), check
// validity claims such as exp or nbf (§7.1 step 6), or read the claims of an
// SD-JWT profile such as vct or iss. It supports only the sha-256 digest
// algorithm (§4.1.1) and only the compact serialization, not JWS JSON (§8).
//
// Errors carry no sentinel of this package: bad input wraps jose.ErrMalformed,
// a caller mistake wraps jose.ErrInvalidArgument, and the message says what is
// wrong.
package sdjwt
