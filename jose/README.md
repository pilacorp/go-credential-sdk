# `jose` — compact JWS with ES256 and ES256K

Module `github.com/pilacorp/go-credential-sdk/jose`, tagged `jose/v0.x.y`. Shared by the SD-JWT formats:
`digitalcredential` (IETF SD-JWT VC, `dc+sd-jwt`) uses it now, and `vc+sd-jwt` can move onto it later.

It imports neither go-ethereum nor the root module of go-credential-sdk.

## What it does

One package per standard:

- `jose/jws`: `jws.Sign(signer, alg, header, payload)` builds a compact JWS (RFC 7515) with `ES256` (P-256, RFC 7518)
  or `ES256K` (secp256k1, RFC 8812). The private key stays with the signer. `jws.Verify(token, key, allowed)` checks it
  against a key the caller supplies (never one taken from the header) and returns the header and the original payload
  bytes.
- `jose/jwk`: `jwk.ToPublicKey` / `jwk.FromPublicKey` convert EC public keys (`kty: EC`, `crv: P-256 | secp256k1`,
  RFC 7517, RFC 7518, RFC 8812).
- `jose`: `EncodeSegment` / `DecodeSegment` and `EncodeJSON` / `DecodeJSON` (the strict encodings every part of a
  token is read with), and the error sentinels.

```go
token, err := jws.Sign(signer, jws.AlgES256, jws.Header{"typ": "dc+sd-jwt", "kid": kid}, payloadJSON)
header, payload, err := jws.Verify(token, issuerKey, []string{jws.AlgES256, jws.AlgES256K})
```

## Signers

`jws.Signer` has one method, `Sign(digest []byte) ([]byte, error)` — the same as
`credential/common/signer.SignerProvider`, so existing providers (in-memory, Vault callback) work as they are. The signer
receives the 32-byte SHA-256 digest and may answer `r||s` (64 bytes) or, under ES256K only, `r||s||v` (65 bytes,
go-ethereum style; the last byte is dropped). DER and any other length are refused. `jws.Sign` always emits a low-S
signature, so a signed token has one encoding.

A bare `Signer` does not say which curve its key is on, so a key on the wrong curve for `alg` (a secp256k1 Vault key
called with ES256) would give a token nobody can verify. A signer that also has `Public() *ecdsa.PublicKey`
(`jws.KeyedSigner`, which `signer.P256Provider` satisfies) closes that: `jws.Sign` refuses a key on the other curve
before calling it (`ErrAlgKeyMismatch`) and verifies the token with the key before returning it.

## Strict reading

One token has one reading:

- base64url without padding, without line breaks (Go's decoder skips `\r` and `\n` silently) and without non-zero
  trailing bits;
- JSON without duplicate keys at any depth (Go's decoder keeps the last one silently), without data after the value,
  in valid UTF-8, with numbers kept as `json.Number`;
- a header with `crit`, or with `b64` other than `true`, is refused;
- the signature is exactly 64-byte `r||s` on the verify side; low-S and high-S both verify.

## Algorithms

`ES256` is the default. HAIP 1.0 (Final, 24 December 2025) §7 makes `ES256` the minimum that issuers, wallets and
verifiers support for validating the signatures it lists, such as the KB-JWT and the Status List Token (§6.1), and
names no other algorithm; further suites are left to ecosystem profiles. A KB-JWT or Status List Token signed with
`ES256K` is therefore accepted only by verifiers that support secp256k1, by their own choice or because their
ecosystem requires it.

`none`, `HS*`, `RS*`, `PS*` and `EdDSA` are always refused. The key decides the algorithm: a P-256 key verifies only
`ES256`, a secp256k1 key only `ES256K`.
