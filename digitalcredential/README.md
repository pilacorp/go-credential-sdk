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
| Verifier | Checks a presented credential and reads its claims | `dc.Parse(s)`, `cred.Verify(ctx, issuers, opts...)`, `issuermeta.NewResolver(cfg)`, `statuslist.NewChecker(cfg)` |
| Status Issuer | Publishes the status of the credentials it issued | `statuslist.New(size, bits)`, `list.Set(i, v)`, `list.IssueToken(ctx, claims, key)` |
| Any | Names a credential, for example to record or anchor it | `cred.Hash()` |

## What the SDK does and what the caller does

| The SDK | The caller |
|---|---|
| Builds the payload, conceals the claims in `Disclose` (RFC 9901 §4.2), keeps the claims draft 19 §2.2.2.3 forbids concealing in the Issuer-signed JWT | Chooses the claims, `vct`, the paths to conceal and the number of decoys |
| Signs through `jws.Signer` and checks the signature with `SigningKey.Public` before returning (`jose`) | Holds the private key: a `jws.Signer` over a key in memory, or `jws.DigestSigner` over a remote signing service |
| Selects the disclosures of the claims in `Reveal` by OpenID4VP 1.0 §7.1.1 claims path pointers, with their concealed ancestors (RFC 9901 §4.2.6) | Asks the user which claims to present; RFC 9901 §7.2 leaves consent out of scope |
| Writes the Key Binding JWT with `sd_hash` over exactly the SD-JWT sent (RFC 9901 §4.3.1), signed by the key of `cnf.jwk` | Sets `KeyBinding` when the Verifier requires Key Binding, with the Verifier's `aud` and `nonce` |
| Retrieves JWT VC Issuer Metadata with the bounds of draft 19 §3 and refuses addresses that are not globally reachable (§7.1) | Lists the issuers it trusts (`Config.Allowed`, §2.5), blocks hosts of its own network with its egress policy |
| Verifies the signature, the Disclosures, the times, Key Binding and status (draft 19 §2.4, RFC 9901 §7.1, §7.3) | Sets `aud` and a fresh `nonce` per transaction and accepts each nonce once; checks that the issuer may issue this `vct` (§7.7) and the claims a protocol adds to the KB-JWT |
| Retrieves, checks, merges and caches Type Metadata, and checks the payload against its claim metadata (draft 19 §5, §6) | Decides whether Type Metadata is processed and required, and which publishers it trusts (`typemeta.Config.Allowed`, §5.7, §7.8); renders the credential |
| Fetches, verifies and caches Status List Tokens (draft-ietf-oauth-status-list-21 §8) | Chooses the issuers whose status keys it trusts (`statuslist.Config.Issuers`) and how old a list may be (`MaxAge`) |

## Object model

| Object | Package | What it is |
|---|---|---|
| `Credential` | `dc` | An SD-JWT VC in compact form: as issued, as kept or as presented (RFC 9901 §4, §4.3). It never changes; `Serialize` returns its string as given |
| `IssueRequest` | `dc` | The content of one credential: `vct`, `iss`, `iat`, `nbf`, `exp`, the holder key, other claims, paths to conceal |
| `PresentRequest`, `KeyBinding` | `dc` | Which claims to present, and the content of the Key Binding JWT |
| `Error`, `Code` | `dc` | Why `Parse` or `Verify` refused a token; `Code` is a fixed value to branch on and store |
| `VerifyOption`, `Result` | `dc` | One choice the standards leave to the Verifier, and what `Verify` returns for an accepted credential |
| `List`, `Ref`, `TokenClaims` | `statuslist` | A Status List (draft 21 §4), the `status_list` reference of a credential (§6.2), the claims of a Status List Token (§5.1) |
| `Checker`, `Config` | `statuslist` | Reads a credential's status from its issuer's Status List Token; share one, it caches by `ttl` |
| `SigningKey` | `issuerkey` | The Issuer's `jws.Signer`, its public key and `kid` |
| `PublicKey` | `issuerkey` | A key an Issuer publishes for verifying, with its `kid` (RFC 7517 §4.5) |
| `Config` | `issuermeta` | The configuration of a `Resolver`, copied at construction; `Allowed` is required, and any other zero field gives a safe default |

| Interface | Does | In the SDK | Written by the caller, for example |
|---|---|---|---|
| `jws.Signer` | Declares `alg` and signs the JWS Signing Input | `jws.PrivateKeySigner`, `jws.DigestSigner` | KMS, HSM, wallet key store |
| `issuerkey.Resolver` | Returns the keys an `iss` currently publishes | `issuermeta.Resolver` (draft 19 §4); `issuerkey.Multi` combines resolvers | DID-based resolver, fixed key table |
| `dc.StatusChecker` | Returns the raw status of the entry a credential points to | `*statuslist.Checker` | Another status mechanism, a local mirror of the lists |

## Issue

`dc.Issue(ctx, req, key)` returns `<Issuer-signed JWT>~<Disclosure>~…~`, with `typ` `dc+sd-jwt` and `kid` from
`key.KID`. `req.Validate()` returns the error `Issue` would return for `req`, without signing.

- `VCT` is required (draft 19 §2.2.2.3). `Issuer`, `IssuedAt`, `NotBefore` and `Expiry` are optional; times are
  written in whole seconds. `HolderKey` is written as `cnf.jwk` (RFC 7800 §3.2).
- A claim whose field is unset may come in `Claims` instead, in any form the standards allow: `iat`, `nbf`, `exp` as
  a NumericDate with a fraction (RFC 7519 §2), `cnf` in any form of RFC 7800, `status`. `iss` and `vct` come only from
  their fields, and a claim set both ways is refused.
- `Status` is written as `status.status_list` `{"idx", "uri"}` (draft-ietf-oauth-status-list-21 §6.2) and must pass
  `statuslist.Ref.Validate`. Another status mechanism goes in `Claims`, with `Status` nil.
- `aka_vcts` must be a non-empty array of strings without the value of `vct` (§2.2.2.2). A credential with `cnf`
  needs `iss` or `sub` (RFC 7800 §3). Decoys (`MinDigests`) need at least one `Disclose` path (§2.2.2.5).
- `Issue` caps no size. `sdjwt.Conceal` refuses work that is too large for one call; Holders and Verifiers built on
  this SDK refuse a credential over 1 MiB, with more than 1000 disclosures or nested deeper than 32 levels.
- `TypeMetadata`, from `typemeta.Load`, makes `Issue` check the payload against the claim metadata before signing
  (draft 19 §5.6): a missing `mandatory` claim, an `sd: always` claim in the clear or an `sd: never` claim concealed
  is `jose.ErrInvalidArgument` wrapping `typemeta.ErrViolated`, and a check over the SDK's limit wraps
  `typemeta.ErrClaims`. Arrays then get no decoys, since §5.6 counts array
  elements as issued. Its `VCT()` must be `VCT`, and a `vct#integrity` in `Claims` must match the document it was
  loaded from.

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

## Verify

`cred.Verify(ctx, issuers, opts...)` checks a credential as received (draft 19 §2.4) and returns a `*dc.Result`: the
processed claims (RFC 9901 §7.1), `Issuer`, `VCT`, `AKAVCTs`, whether a Key Binding JWT was checked (`KeyBound`) and its
claims, and the status value.

```go
cred, err := dc.Parse(presented)
if err != nil { /* *dc.Error */ }
res, err := cred.Verify(ctx, resolver,
	dc.WithAudience("https://verifier.example"), // the Verifier's client_id
	dc.WithNonce(nonce),                         // fresh per transaction
	dc.WithStatus(checker))                      // a *statuslist.Checker
var e *dc.Error
switch {
case errors.As(err, &e): // rejected: e.Code, such as dc.CodeRevoked
case errors.Is(err, dc.ErrPolicy): // the caller's arguments or wiring
case err != nil: // ctx ended: nothing is known about the token
}
```

With no option, `Verify` follows the standard's rule where it sets one, and otherwise the SDK default in the table, which never accepts what the standard rejects. The options set what the standards leave to the Verifier:

| Option | Not passed |
|---|---|
| `WithAllowedAlgs(algs...)` | `ES256` and `ES256K`, for the Issuer-signed JWT and the KB-JWT |
| `WithKeyBinding(mode)` | `KeyBindingIfCnf`: Key Binding is required exactly when the credential has `cnf` |
| `WithIgnoreUncheckedKBJWT()` | A KB-JWT that is not required is `KB_UNEXPECTED`: RFC 9901 §7.2 and §4 require that under `KeyBindingNotRequired`, and it is the SDK default for a credential without `cnf` |
| `WithAudience(aud)`, `WithNonce(n)` | Needed whenever a KB-JWT is checked, compared byte for byte (§7.3 step 5f) |
| `WithCredentialAudience(aud)` | A credential with `aud` is `AUDIENCE_MISMATCH` (RFC 7519 §4.1.3) |
| `WithMaxKBAge(d)` | 5 minutes for the KB-JWT `iat` (§7.3 step 5e) |
| `WithClockSkew(d)` | 1 minute on `exp`, `nbf` and the KB-JWT `iat` |
| `WithStatus(checker)` | A credential with `status_list` is `ErrPolicy`, so a forgotten checker never accepts a revoked credential |
| `WithoutStatusCheck()` | Status is checked, as -19 §2.4 says it SHOULD be; with this option it is not, and `Result.StatusSkipped` says so |
| `WithAcceptedStatus(v...)` | Only `0x00`, VALID (draft 21 §7.1) |
| `WithNow(t)` | `time.Now()`, read once |
| `WithAcceptedVCTs(vcts...)` | Types are not compared; read `Result.VCT` and `Result.AKAVCTs`. Passed, a credential whose `vct` and `aka_vcts` match none is `VCT_NOT_ACCEPTED` (§2.2.2.1, §2.2.2.2) |
| `WithExtendedVCTMatch()` | `WithAcceptedVCTs` matches `vct` and `aka_vcts` only; with it, the types the credential's type `extends` too (§5.4) |
| `WithTypeMetadata(r)`, `WithOptionalTypeMetadata(r)` | Type Metadata is not processed (§5.7 leaves it to the Verifier); see Type Metadata below |
| `WithAllDisclosures()` | The claim metadata is checked as a Verifier must, never reading a claim it was not shown as one left out (§5.6) |

Each option may be passed once per call. An option the call cannot use (no alg, a negative duration, `WithStatus` with
`WithoutStatusCheck`, `KeyBindingRequired` without `WithAudience` and `WithNonce`, both Type Metadata options,
`WithAllDisclosures` or `WithExtendedVCTMatch` without a Type Metadata option) is `dc.ErrPolicy`, before the token is
read.

`Verify` keeps no state: accepting each nonce once is the caller's (§7.3 step 5f). It does not check that the issuer may
issue the credential's type (draft 19 §7.7), nor the claims a protocol adds to the KB-JWT, such as OpenID4VP 1.0
`transaction_data_hashes`: read them from `Result.KeyBindingClaims`. A claim the Issuer concealed and the Holder
withheld is absent, so a withheld `cnf` reads as no `cnf`; use `KeyBindingRequired` when your use case always needs Key
Binding.

## Type Metadata

Package `typemeta` implements SD-JWT VC Type Metadata (draft 19 §5, §6). A publisher builds a `typemeta.Document` and
serves the bytes of `Encode`; `Encoded.Integrity()` is the value an Issuer writes as `vct#integrity`. Issuer, Holder
and Verifier get a type's documents through a `typemeta.Resolver`:

```go
types, err := typemeta.NewHTTPResolver(typemeta.Config{
	Allowed: []string{"https://types.example/"}, // the publishers you trust (§7.8)
})
if err != nil { /* ... */ }
res, err := cred.Verify(ctx, resolver, dc.WithTypeMetadata(types))
```

`NewHTTPResolver` fetches a `vct` that is an https URL under `Allowed` (§5.3.1), with the bounds of §3 and the address
check of the issuer metadata resolver, and caches a document for its HTTP freshness, at most 24 hours; a document
whose integrity was checked stays until evicted. Redirects follow the rule of the issuer metadata resolver: a `vct` or
`extends` that only an entry ending in `/` covers is followed only within its origin, integrity or not, unless
`AllowCrossOriginRedirects` is set; one listed exactly follows any https redirect. Integrity does not lift the rule,
because the issuer writes the hash as well as the path, while `Allowed` trusts the publisher.
`typemeta.Static(docs...)` serves documents you ship, and `typemeta.Multi(r1, r2, …)` asks resolvers in order, moving
on only on `typemeta.ErrNotFound`.

`typemeta.Load` follows `extends` up to 8 documents, checks each `#integrity` (§6, W3C SRI), the structure and the
`vct`, and merges display and claim metadata (§5.5.2, §5.6.5). `Verify` then checks the payload as issued against the
claim metadata (§5.6) and returns the merged `*typemeta.Metadata` in `Result.TypeMetadata`:

| Outcome | `WithTypeMetadata` | `WithOptionalTypeMetadata` |
|---|---|---|
| No resolver has the type | `TYPE_METADATA_NOT_FOUND` | skipped, `Result.TypeMetadataSkipped` says why |
| Retrieval failed | `TYPE_METADATA_UNAVAILABLE` | skipped |
| A document is not usable: hash, structure, `vct`, broken chain | `TYPE_METADATA_INVALID` | skipped |
| Claim metadata breaks §5.6 or needs more work than the SDK's limit, or an `extends` cycle (§7.4) | `TYPE_METADATA_INVALID` | `TYPE_METADATA_INVALID` (§5.7) |
| The payload violates the claim metadata | `TYPE_METADATA_VIOLATED` | `TYPE_METADATA_VIOLATED` |

A Verifier sees only the Disclosures it was sent, so a `mandatory` claim that an undisclosed digest may hold passes
(§5.6). The Holder, which received every Disclosure, passes `dc.WithAllDisclosures()` to see a missing one; with a Key
Binding JWT it is `ErrPolicy`. Choosing a locale, rendering, and fetching the images and SVG templates a document
names are the display application's; `typemeta.CheckIntegrity` checks what it fetches.

## Status

The Status Issuer keeps one `statuslist.List` per set of credentials, sets an entry per credential and publishes the
list as a Status List Token (draft-ietf-oauth-status-list-21 §5):

```go
list, err := statuslist.New(1<<17, 1) // 131072 entries of 1 bit
if err != nil { /* ... */ }
if err := list.Set(7, 0x01); err != nil { /* ... */ } // entry 7 INVALID (§7.1)
token, err := list.IssueToken(ctx, statuslist.TokenClaims{
	Sub: "https://status.example/lists/1", IssuedAt: time.Now(), TTL: 12 * time.Hour,
}, key) // an issuerkey.SigningKey; serve token as application/statuslist+jwt (§8.2)
```

The Issuer writes `Status: &statuslist.Ref{URI: "https://status.example/lists/1", Index: 7}` in the `IssueRequest`.
Choose each index at random among the unused ones and add decoy entries, so the list does not show how many
credentials exist (§12.4, §12.5.1).

The Verifier builds one `statuslist.Checker` and passes it with `dc.WithStatus`. It fetches the list over https only,
verifies its signature with a key of the credential's `iss` from `Config.Issuers`, checks `typ`, `sub`, `iat`, `exp`
and `aud` (§5.1, §8.3), and caches it for its `ttl`, at most 24 hours. A list without `ttl` is fetched again on every
check. `Status` returns the raw value; `Verify` maps it: `0x01` is `REVOKED`, `0x02` `SUSPENDED`, any other value not
accepted `STATUS_NOT_ACCEPTED`, and a list it cannot fetch or verify `STATUS_UNAVAILABLE`. An index outside the list is
`MALFORMED` (§8.3 step 6). `Config.AllowedAlgs`, `ClockSkew` and the clock of the Checker are its own:
`dc.WithAllowedAlgs`, `dc.WithClockSkew` and `dc.WithNow` do not reach it.

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
- Redirects are not matched against `Allowed`. For an `iss` that only an entry ending in `/` covers, the credential
  chooses the path requested, so the metadata and the JWK Set follow redirects only within the origin each retrieval
  started from; another origin fails the retrieval before it is sent. An `iss` listed exactly, or
  `AllowCrossOriginRedirects`, follows redirects to any https host, and the server they lead to supplies the keys.
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
