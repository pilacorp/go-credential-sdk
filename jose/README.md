# `jose` — compact JWS with ES256 and ES256K

Module `github.com/pilacorp/go-credential-sdk/jose`, tagged `jose/v0.x.y`. Shared by the SD-JWT formats:
`digitalcredential` (IETF SD-JWT VC, `dc+sd-jwt`) uses it now, and `vc+sd-jwt` can move onto it later.

It imports neither go-ethereum nor the root module of go-credential-sdk.

## What it does

One package per standard:

- `jose/jws`: `jws.Sign(ctx, signer, pub, header, payload)` builds a compact JWS (RFC 7515) with the alg of `signer`,
  `ES256` (P-256, RFC 7518 §3.4) or `ES256K` (secp256k1, RFC 8812 §3.2), which must match the curve of `pub`. The
  private key stays with the signer. `jws.Verify(token, key, allowed)` checks it against a key the caller supplies
  (never one taken from the header) and returns the header and the original payload bytes; an `allowed` entry other
  than `ES256` and `ES256K` is `jose.ErrUnsupportedAlg`, returned before the token is read, while a token whose alg is
  not supported or not allowed is `jws.ErrAlgNotAllowed`. `jws.UnverifiedHeader(token)`
  reads the header with the structural checks of `Verify`, so the caller can pick the key by `kid`; alg is checked only
  by `Verify`, and nothing in the header is trusted until `Verify` succeeds. `jws.UnverifiedPayload(token)` reads the
  payload with the same checks, for a reader that needs the claims before or without `Verify`; nothing in it is
  trusted either. `Header.TypIs(mediaType)` compares `typ` as RFC 7515 §4.1.9 says (explicit typing, RFC 8725 §3.11).
- `jose/jwt`: `jwt.NumericDate(v)` turns an `exp`, `nbf` or `iat` value into a `time.Time` (RFC 7519 §2), fractions
  included; a non-number, NaN, ±Inf or a value `time.Time` cannot hold is `jose.ErrMalformed`. `jwt.DateClaim`
  reads one such claim from a payload. `jwt.CheckExpNbf(claims, now, skew)` checks `exp` and `nbf` when present
  (RFC 7519 §4.1.4, §4.1.5) and wraps `jwt.ErrExpired` or `jwt.ErrNotYetValid`; the skew is the caller's policy. `jwt.CheckAud(claims, audience)` checks `aud` when present (RFC 7519 §4.1.3):
  a string or an array of strings that lists `audience`, else `jwt.ErrAudience` (`jose.ErrMalformed` for another
  type). `CheckExpNbf`, `DateClaim` and `CheckAud` read claims as `jose.DecodeJSONObject` yields them from a
  received token; a Go `[]string` for `aud` is `jose.ErrMalformed`.
- `jose/jwk`: `jwk.ToPublicKey` / `jwk.FromPublicKey` convert EC public keys (`kty: EC`, `crv: P-256 | secp256k1`,
  RFC 7517, RFC 7518, RFC 8812). A secp256k1 JWK that carries `alg`, `use` or `key_ops` must have `ES256K`, `sig`, or
  a list including `verify` (RFC 8812 §3.2). `ToPublicKey` reads the map as `jose.DecodeJSONObject` yields it, where a
  JSON array is `[]any`: for a secp256k1 key a Go `[]string` for `key_ops` is not that `[]any`, so the key is refused;
  P-256 does not read `key_ops`.
  `ToPublicKey` refuses a public JWK whose `kty`, or `crv` of an EC key, is a string it does not convert with
  `jose.ErrUnsupportedKey`, without checking the rest of the key, which may be valid or broken. Every other refusal, a
  JWK carrying `d` included, is `jwk.ErrBadKey`; no error matches both.
- `jose/sdjwt`: the SD-JWT format of RFC 9901. `sdjwt.Conceal(claims, paths, opts)` makes the claims at `paths`
  selectively disclosable and returns the payload to sign and the disclosures, with decoy digests up to
  `opts.MinDigests` in every object and array (only in objects with `opts.NoArrayDecoys`, for a payload whose arrays
  are addressed by index); `sdjwt.Split` separates the compact form; `sdjwt.Recreate(payload, disclosures)` rebuilds
  the claims (§7.1 steps 3 to 5) and tells which disclosures each claim needs. It neither signs the Issuer-signed JWT
  nor checks its validity claims. `Recreated.Disclosed(path)` tells whether a claim, an ancestor or a descendant came
  from a disclosure; `Recreated.Issued()` gives the payload as issued, each array element in its place at issuance
  and a hidden one marked `Hidden`.
- `jose/sdjwt`, Key Binding JWT (RFC 9901 §4.3, §7.3): `SDHash`, `NewKBJWT` and `VerifyKBJWT` (check order in its
  godoc), which returns `ErrKBInvalid`, `ErrKBAudience`, `ErrKBNonce` or `ErrKBSDHash` for the token;
  `jose.ErrInvalidArgument` for caller mistakes, `jose.ErrUnsupportedAlg` or `jose.ErrUnsupportedKey` for an
  `AllowedAlgs` entry or a holder key the SDK does not support, and `jws.ErrBadKey` for a broken holder key. The
  caller's inputs are checked before the token is read, so their class never depends on the token. `VerifyKBJWT`
  accepts only the alg of the holder key (ES256 or ES256K, never none), and only one in `KBVerifyParams.AllowedAlgs` (§7.3 step 5b; nil means both). It has
  no default window: `MaxAge` must be positive and a `ClockSkew` of 0 allows no skew (§7.3 step 5e leaves both to
  the Verifier). An `aud`, `nonce` or `sd_hash` that is missing or not a string is `ErrKBInvalid`; the other three
  mean a well-formed value that differs. `KBClaims.Extra` adds the claims a protocol defines, such as
  `transaction_data_hashes` of OpenID4VP 1.0 Appendix B.3.3.1, never in place of `iat`, `aud`, `nonce` or `sd_hash`,
  and `VerifyKBJWT` returns every claim of a KB-JWT it accepts, for the caller to check the protocol's own.
  A Holder that receives an SD-JWT+KB must reject it (§7.2): `Split` returns a non-empty `kbJWT` for one, and
  that check is the receiving Holder's, not `Recreate`'s.
- `jose`: `EncodeSegment` / `DecodeSegment` and `EncodeJSON` / `DecodeJSON` (the strict encodings every part of a token
  is read with), `DecodeJSONStringMember` (one top-level string member, such as `iss` before the signature is checked,
  without building any other value), and the errors every package returns: `ErrMalformed` for bad input,
  `ErrInvalidArgument` for a caller mistake, `ErrUnsupportedAlg` for an alg the caller supplies (Signer, `DigestSigner`,
  allowed list) that the SDK does not implement, and `ErrUnsupportedKey` for a key type or curve it does not implement.
  An alg read from a received token is never `ErrUnsupportedAlg`. A broken key of a supported kind is the package's own
  `ErrBadKey`. Each package lists its own errors in its godoc.

| Work | Done by |
|---|---|
| Keep the private key, compute the signature (RFC 7515 §5.1 step 5) | The caller's `jws.Signer` |
| Check the signer's alg against its public key, write the header, verify the token once more before returning it | `jws.Sign` |
| Find the verification key from a source the caller trusts (RFC 7515 §6, §10.3) | The caller |
| Check structure, alg, key and signature of a received token | `jws.Verify` |
| Decide which claims a token must carry, the clock and the skew | The caller, with `jose/jwt` for the checks |
| Accept each KB-JWT `nonce` once per transaction (RFC 9901 §7.3 step 5f) | The caller; `VerifyKBJWT` keeps no state |

```go
package example

import (
	"context"
	"crypto/ecdsa"

	"github.com/pilacorp/go-credential-sdk/jose/jws"
)

// priv is the issuer key; payloadJSON is the claims object as JSON.
func signAndVerify(ctx context.Context, priv *ecdsa.PrivateKey, kid string, payloadJSON []byte) (jws.Header, []byte, error) {
	signer, err := jws.PrivateKeySigner(priv)
	if err != nil {
		return nil, nil, err
	}
	token, err := jws.Sign(ctx, signer, &priv.PublicKey, jws.Header{"typ": "dc+sd-jwt", "kid": kid}, payloadJSON)
	if err != nil {
		return nil, nil, err
	}
	// A verifier takes the key from its own trusted source, never from the token.
	return jws.Verify(token, &priv.PublicKey, []string{jws.AlgES256, jws.AlgES256K})
}
```

## Signers

`jws.Signer` has two methods. `Alg()` names the alg it signs with; `Sign(ctx, signingInput)` returns the JWS
Signature over `base64url(header) "." base64url(payload)`, which for `ES256` and `ES256K` is 64-byte `r||s` over its
SHA-256 (RFC 7518 §3.4, RFC 8812 §3.2). `ctx` is the caller's, passed on by `jws.Sign`: a Signer that calls a key
store passes it to that call, so the caller's deadline and cancel reach it. An error from the Signer is
`jws.ErrSignerFailed` wrapping that error, so `errors.Is(err, context.DeadlineExceeded)` holds too; check
`jws.ErrSignerFailed` before the other sentinels. Two Signers come with the package:

- `jws.PrivateKeySigner(priv)` signs with an `*ecdsa.PrivateKey` held in memory, on P-256 (`ES256`) or secp256k1
  (`ES256K`), and checks that `priv.PublicKey` belongs to `priv.D`. It is safe for concurrent use, does no I/O and
  ignores `ctx`, and is the model to follow when writing a Signer for a key store.
- `jws.DigestSigner(alg, sign)` is for a key store that signs a 32-byte digest, as most HSM and KMS APIs do: it hashes
  the signing input and passes `ctx` and the digest to `sign(ctx, digest)`.

`jws.Sign` puts the Signer's answer into the token unchanged, then verifies the token with `pub` before returning, so
a Signer holding another key, or answering DER or 65-byte `r||s||v`, gets `jws.ErrSelfCheck` instead of a token
nobody can verify. A secp256k1 signer that appends a recovery byte, as Ethereum signers do, must be wrapped to return
the first 64 bytes.

## Strict reading

One token has one reading:

- base64url without padding, without line breaks (Go's decoder skips `\r` and `\n` silently) and without non-zero
  trailing bits;
- JSON without duplicate keys at any depth (Go's decoder keeps the last one silently), without data after the value,
  in valid UTF-8, with numbers kept as `json.Number`;
- a header with `crit` or `b64` is refused (RFC 7797 §6 requires `crit` with `b64`);
- a header over 64 KiB is refused before it is decoded, by `jws.Verify`, `UnverifiedHeader` and `UnverifiedPayload`
  (`jose.ErrMalformed`) and by `jws.Sign` (`jose.ErrInvalidArgument`); no standard sets a size, this bounds the work
  done before a signature is checked;
- the signature is exactly 64-byte `r||s`; low-S and high-S both verify, since RFC 7518 §3.4 and RFC 8812 §3.2 put no
  limit on `s` beyond ECDSA verification, which accepts any `s` in `[1, n-1]` (FIPS 186-5 §6.4.2 step 1).

## Algorithms

`jws` has no default algorithm: the Signer names it and the key's curve must match (P-256 ⇒ `ES256`, secp256k1 ⇒
`ES256K`). Prefer P-256: HAIP 1.0
(Final, 24 December 2025) §7 makes `ES256` the minimum that issuers, wallets and verifiers support for validating the
signatures it lists, such as the KB-JWT and the Status List Token (§6.1), and names no other algorithm; further suites
are left to ecosystem profiles. A KB-JWT or Status List Token signed with `ES256K` is therefore accepted only by
verifiers that support secp256k1, by their own choice or because their ecosystem requires it.

`none`, `HS*`, `RS*`, `PS*` and `EdDSA` are always refused. The key decides the algorithm: a P-256 key verifies only
`ES256`, a secp256k1 key only `ES256K`.
