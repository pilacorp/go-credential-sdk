# `jose` — compact JWS with ES256 and ES256K

Module `github.com/pilacorp/go-credential-sdk/jose`, tagged `jose/v0.x.y`. Shared by the SD-JWT formats:
`digitalcredential` (IETF SD-JWT VC, `dc+sd-jwt`) uses it now, and `vc+sd-jwt` can move onto it later.

It imports neither go-ethereum nor the root module of go-credential-sdk.

## What it does

One package per standard:

- `jose/jws`: `jws.Sign(signer, pub, header, payload)` builds a compact JWS (RFC 7515) with `ES256` (P-256, RFC 7518)
  or `ES256K` (secp256k1, RFC 8812), chosen by the curve of `pub`. The private key stays with the signer.
  `jws.Verify(token, key, allowed)` checks it against a key the caller supplies (never one taken from the header) and
  returns the header and the original payload bytes; an `allowed` entry other than `ES256` and `ES256K` is the caller's
  mistake, `jose.ErrInvalidArgument`, returned before the token is read. `jws.UnverifiedHeader(token)` reads the header with the
  structural checks of `Verify`, so the caller can pick the key by `kid`; alg is checked only by `Verify`, and nothing
  in the header is trusted until `Verify` succeeds. `jws.UnverifiedPayload(token)` reads the payload with the same
  checks, for a reader that needs the claims before or without `Verify`; nothing in it is trusted either. `Header.TypIs(mediaType)` compares `typ` as RFC 7515 §4.1.9 says
  (explicit typing, RFC 8725 §3.11).
- `jose/jwt`: `jwt.NumericDate(v)` turns an `exp`, `nbf` or `iat` value into a `time.Time` (RFC 7519 §2), fractions
  included; a non-number, NaN, ±Inf or a value `time.Time` cannot hold is `jose.ErrMalformed`. `jwt.DateClaim`
  reads one such claim from a payload. `jwt.CheckExpNbf(claims, now, skew)` checks `exp` and `nbf` when present
  (RFC 7519 §4.1.4, §4.1.5) and wraps `jwt.ErrExpired` or `jwt.ErrNotYetValid`; `VerifyKBJWT` takes the rule from it,
  and the skew is the caller's policy. `jwt.CheckAud(claims, audience)` checks `aud` when present (RFC 7519 §4.1.3):
  a string or an array of strings that lists `audience`, else `jwt.ErrAudience` (`jose.ErrMalformed` for another
  type).
- `jose/jwk`: `jwk.ToPublicKey` / `jwk.FromPublicKey` convert EC public keys (`kty: EC`, `crv: P-256 | secp256k1`,
  RFC 7517, RFC 7518, RFC 8812). A secp256k1 JWK that carries `alg`, `use` or `key_ops` must have `ES256K`, `sig`, or
  a list including `verify` (RFC 8812 §3.2). `ToPublicKey` refuses a public JWK whose `kty`, or `crv` of an EC key,
  is a string it does not convert with `jwk.ErrUnsupportedKey`, without checking the rest of the key, which may be
  valid or broken. Every other refusal, a JWK carrying `d` included, is `jwk.ErrBadKey`; no error matches both.
- `jose/sdjwt`: the SD-JWT format of RFC 9901. `sdjwt.Conceal(claims, paths, opts)` makes the claims at `paths`
  selectively disclosable and returns the payload to sign and the disclosures, with decoy digests up to
  `opts.MinDigests` in every object and array; `sdjwt.Split` separates the compact form; `sdjwt.Recreate(payload,
  disclosures)` rebuilds the claims (§7.1 steps 3 to 5) and tells which disclosures each claim needs. It neither
  signs the Issuer-signed JWT nor checks its validity claims. `Recreated.Disclosed(path)` tells whether a claim, an
  ancestor or a descendant came from a disclosure.
- `jose/sdjwt`, Key Binding JWT (RFC 9901 §4.3, §7.3): `SDHash`, `NewKBJWT` and `VerifyKBJWT` (check order in its
  godoc), which returns `ErrKBInvalid`, `ErrKBAudience`, `ErrKBNonce` or `ErrKBSDHash`, and `jose.ErrInvalidArgument`
  for caller mistakes. `VerifyKBJWT` accepts only the alg of the holder key (ES256 or ES256K, never none), and only
  one in `KBWant.AllowedAlgs` (§7.3 step 5b; nil means both). An `aud`, `nonce` or `sd_hash` that is missing or not a
  string is `ErrKBInvalid`; the other three mean a well-formed value that differs.
- `jose`: `EncodeSegment` / `DecodeSegment` and `EncodeJSON` / `DecodeJSON` (the strict encodings every part of a
  token is read with), and `ErrMalformed` / `ErrInvalidArgument`, which `jose/jws` returns too. Each other package
  has its own errors.

```go
token, err := jws.Sign(signer, issuerPub, jws.Header{"typ": "dc+sd-jwt", "kid": kid}, payloadJSON)
header, payload, err := jws.Verify(token, issuerKey, []string{jws.AlgES256, jws.AlgES256K})
```

## Signers

`jws.Signer` has one method, `Sign(digest []byte) ([]byte, error)`. It receives the 32-byte SHA-256 digest and returns
64-byte `r||s` (RFC 7518 §3.4, RFC 8812 §3.2). `jws.Sign` puts that answer into the token unchanged, so DER or
`r||s||v` fails with `jws.ErrSelfCheck`.

The caller passes the signer's public key. `jws.Sign` takes the alg from its curve and verifies the token with it
before returning, so a signer holding another key, or answering in another format, gets `jws.ErrSelfCheck` instead of
a token nobody can verify.

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

`jws` has no default algorithm: the key decides (P-256 ⇒ `ES256`, secp256k1 ⇒ `ES256K`). Prefer P-256: HAIP 1.0
(Final, 24 December 2025) §7 makes `ES256` the minimum that issuers, wallets and verifiers support for validating the
signatures it lists, such as the KB-JWT and the Status List Token (§6.1), and names no other algorithm; further suites
are left to ecosystem profiles. A KB-JWT or Status List Token signed with `ES256K` is therefore accepted only by
verifiers that support secp256k1, by their own choice or because their ecosystem requires it.

`none`, `HS*`, `RS*`, `PS*` and `EdDSA` are always refused. The key decides the algorithm: a P-256 key verifies only
`ES256`, a secp256k1 key only `ES256K`.
