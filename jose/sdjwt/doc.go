// Package sdjwt is the core of Selective Disclosure for JWTs (RFC 9901,
// sections 4 and 7.1): disclosures and their digests, concealing claims on the
// issuer side (Conceal), recreating the payload on the holder and verifier side
// (Recreate), splitting the tilde-separated form (Split), and the Key Binding
// JWT (SDHash, NewKBJWT, VerifyKBJWT).
//
// It knows nothing about vct, iss or validity: dc+sd-jwt (module
// digitalcredential) adds those. Signing and strict decoding come from package
// jose, so everything a token carries is read under the same rules.
//
// Digests are always computed over the received base64url string of a
// disclosure, never over re-encoded JSON: the same value may legitimately be
// written several ways (spaces, "ö" or "\u00f6"), and each way has its own
// digest.
//
// The code is ported from sd-jwt-python and eudi-lib-jvm-sdjwt-kt (both
// Apache-2.0); each ported file names its sources, and jose/NOTICE lists them.
// Deliberate differences from them:
//   - Conceal takes paths instead of marked-up claims, adds a fixed number of
//     decoys to every _sd array only (sd-jwt-python adds 2 to 5 to every
//     object), and asks its SaltProvider for the salt of each path;
//   - Recreate refuses any object holding ... that is not an array element
//     placeholder, _sd_alg below the top level, and the same disclosure twice,
//     and bounds the number of disclosures and the nesting depth (Limits);
//     like the Kotlin library, the claim name _sd_alg is refused too;
//   - Split refuses empty and repeated disclosures, a last part that is not a
//     JWT, and input over Limits.MaxBytes;
//   - VerifyKBJWT always checks aud and nonce (sd-jwt-python skips the KB-JWT
//     when the caller passes neither), requires them to be strings, and checks
//     iat against a window.
package sdjwt
