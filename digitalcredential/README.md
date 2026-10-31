# `digitalcredential` — IETF SD-JWT VC

IETF SD-JWT VC (`dc+sd-jwt`, draft-ietf-oauth-sd-jwt-vc-19). For a W3C VC secured with SD-JWT (`vc+sd-jwt`), use
`credential/vc` of the root module.

Module `github.com/pilacorp/go-credential-sdk/digitalcredential`, tagged `digitalcredential/v0.x.y`; the Go package
is `dc`. It imports module `jose` of this repository and neither go-ethereum nor the root module.

```go
import dc "github.com/pilacorp/go-credential-sdk/digitalcredential"
```

## Roles

| Role | Does | With |
|---|---|---|
| Issuer | Signs a credential for a Holder | `dc.Issue(ctx, req, key)`, `req.Validate()` |
| Holder | Stores the credential, then presents only the claims it chooses, with a Key Binding JWT when the Verifier asks for one | `dc.Parse(s)`, `cred.Present(ctx, req)` |
| Verifier | Finds the Issuer's keys | `issuermeta.NewResolver(cfg)`, `issuerkey.Multi`, `issuerkey.Select` |
| Any | Names a credential, for example to record or anchor it | `cred.Hash()` |

## What the SDK does and what the caller does

| The SDK | The caller |
|---|---|
| Builds the payload, conceals the claims in `Disclose` (RFC 9901 §4.2), keeps the claims draft 19 §2.2.2.3 forbids concealing in the Issuer-signed JWT | Chooses the claims, `vct`, the paths to conceal and the number of decoys |
| Signs through `jws.Signer` and checks the signature with `SigningKey.Public` before returning (`jose`) | Holds the private key: a `jws.Signer` over a key in memory, or `jws.DigestSigner` over a remote signing service |
| Selects the disclosures of the claims in `Reveal` by OpenID4VP 1.0 §7.1.1 claims path pointers, with their concealed ancestors (RFC 9901 §4.2.6) | Asks the user which claims to present; RFC 9901 §7.2 leaves consent out of scope |
| Writes the Key Binding JWT with `sd_hash` over exactly the SD-JWT sent (RFC 9901 §4.3.1), signed by the key of `cnf.jwk` | Sets `KeyBinding` when the Verifier requires Key Binding, with the Verifier's `aud` and `nonce` |
| Retrieves JWT VC Issuer Metadata with the bounds of draft 19 §3 and refuses addresses that are not globally reachable (§7.1) | Lists the issuers it trusts (`Config.Allowed`, §2.5), blocks hosts of its own network with its egress policy |

## Object model

| Object | Package | What it is |
|---|---|---|
| `Credential` | `dc` | An SD-JWT VC in compact form: as issued, as kept or as presented (RFC 9901 §4, §4.3). It never changes; `Serialize` returns its string as given |
| `IssueRequest` | `dc` | The content of one credential: `vct`, `iss`, `iat`, `nbf`, `exp`, the holder key, other claims, paths to conceal |
| `PresentRequest`, `KeyBinding` | `dc` | Which claims to present, and the content of the Key Binding JWT |
| `Error`, `Code` | `dc` | Why `Parse` refused a string; `Code` is a fixed value to branch on and store |
| `SigningKey` | `issuerkey` | The Issuer's `jws.Signer`, its public key and `kid` |
| `PublicKey` | `issuerkey` | A key an Issuer publishes for verifying, with its `kid` (RFC 7517 §4.5) |
| `Config` | `issuermeta` | The configuration of a `Resolver`, copied at construction; a zero field gives a safe default |

| Interface | Does | In the SDK | Written by the caller, for example |
|---|---|---|---|
| `jws.Signer` | Declares `alg` and signs the JWS Signing Input | `jws.PrivateKeySigner`, `jws.DigestSigner` | KMS, HSM, wallet key store |
| `issuerkey.Resolver` | Returns the keys an `iss` currently publishes | `issuermeta.Resolver` (draft 19 §4); `issuerkey.Multi` combines resolvers | DID-based resolver, fixed key table |

## Issue

`dc.Issue(ctx, req, key)` returns `<Issuer-signed JWT>~<Disclosure>~…~`, with `typ` `dc+sd-jwt` and `kid` from
`key.KID`. `req.Validate()` returns the error `Issue` would return for `req`, without signing.

- `VCT` is required (draft 19 §2.2.2.3). `Issuer`, `IssuedAt`, `NotBefore` and `Expiry` are optional; times are
  written in whole seconds. `HolderKey` is written as `cnf.jwk` (RFC 7800 §3.2).
- A claim whose field is unset may come in `Claims` instead, in any form the standards allow: `iat`, `nbf`, `exp` as
  a NumericDate with a fraction (RFC 7519 §2), `cnf` in any form of RFC 7800, `status`. `iss` and `vct` come only from
  their fields, and a claim set both ways is refused.
- `aka_vcts` must be a non-empty array of strings without the value of `vct` (§2.2.2.2). A credential with `cnf`
  needs `iss` or `sub` (RFC 7800 §3). Decoys (`MinDigests`) need at least one `Disclose` path (§2.2.2.5).
- `Issue` caps no size. `sdjwt.Conceal` refuses work that is too large for one call; Holders and Verifiers built on
  this SDK refuse a credential over 1 MiB, with more than 1000 disclosures or nested deeper than 32 levels.

Prefer P-256 for the signing key and for `HolderKey`. No standard here requires a Verifier to support `ES256K`. HAIP 1.0
§7 requires `ES256` for the KB-JWT and the Status List Token, which a secp256k1 `HolderKey` or status key would sign
with `ES256K` (see Algorithms in the `jose` README).

## Present

`cred.Present(ctx, req)` builds what the Holder sends (RFC 9901 §7.2). Each path in `Reveal` is a claims path pointer:
a string selects a key, a non-negative int an index, `nil` every element of an array. Naming a claim inside a
concealed object sends that object's disclosure too, which shows its other plain members. `Present` does not verify
the Issuer's signature: check the credential when you receive it. It refuses an SD-JWT+KB.

With `KeyBinding` set, the key comes from `cnf.jwk`. A credential with no `cnf` is `jose.ErrInvalidArgument`. A `cnf`
this SDK cannot bind (no `jwk`, or a key type other than EC P-256 or secp256k1) is `dc.ErrKeyBindingUnsupported`. A
`cnf` the Issuer got wrong (concealed, more than one key, not an object, symmetric, broken) is `jose.ErrMalformed`.

For OpenID4VP 1.0 transaction data (§8.4), put the claim its type defines, such as `transaction_data_hashes`
(Appendix B.3.3.1), in `KeyBinding.Claims`.

## Hash

`cred.Hash()` returns the hex SHA-256 of the Issuer-signed JWT exactly as given, the part before the first `~`
(RFC 9901 §4). A credential and every presentation of it have one hash. Any other serialization, the same token with
its signature's S flipped included, has another. `Hash` verifies nothing, so hash the credential `Issue` returned or
one you verified.

## Issuer keys

`issuermeta.NewResolver(issuermeta.Config{Allowed: …})` returns an `issuerkey.Resolver` that reads the keys of an https
issuer from its JWT VC Issuer Metadata (draft 19 §4): the metadata at the well-known location, its `issuer` identical
to `iss`, and the JWK Set in `jwks` or at `jwks_uri`.

- `Allowed` is your trust list (§2.5). An entry ending in `/` covers every `iss` that starts with it, except one with
  a `.` or `..` path segment; any other entry covers only the `iss` equal to it. Matching is byte for byte.
- An `iss` outside the list is `issuerkey.ErrIssuerNotSupported`, with no request made. Metadata or a JWK Set that
  must not be used is `issuerkey.ErrNoUsableKey`. A failed retrieval is any other error, or one wrapping `ctx.Err()`.
- Only P-256 and secp256k1 keys whose `use`, `alg` and `key_ops`, if present, allow verifying are returned.
- Answers are cached as RFC 9111 allows, at most 24 hours. A key the issuer removes still verifies while its answer
  is cached; `DisableCache` retrieves every time. Share one `Resolver`.
- `HTTPClient` passes your own client, for an egress proxy or an internal host. That client is trusted code: the
  address check exists only in the default one, which cannot know hosts reachable only inside your network.

`issuerkey.Multi(r1, r2, …)` asks resolvers in order and moves to the next only on `ErrIssuerNotSupported`, so a
failed retrieval never sends an issuer to another key source. `issuerkey.Select(keys, header)` picks the key the JWS
header names: a `kid` must match exactly one key, and a token without `kid` needs exactly one key; keys are never
tried in turn.

## HAIP

This module does not meet HAIP 1.0: §6.1.1 requires issuer key resolution through an `x5c` certificate chain and
every SD-JWT VC to carry that chain. Keys come only from an `issuerkey.Resolver` by `iss` and `kid`, and `Issue` writes
no `x5c`.
