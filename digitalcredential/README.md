# `digitalcredential` — IETF SD-JWT VC

IETF SD-JWT VC (`dc+sd-jwt`); for a W3C VC secured with SD-JWT (`vc+sd-jwt`) use `credential/vc`.

Module `github.com/pilacorp/go-credential-sdk/digitalcredential`, tagged `digitalcredential/v0.x.y`. It imports
neither go-ethereum nor the root module of go-credential-sdk; it imports module `jose`.

`Issue(req, key)` signs an SD-JWT VC and returns it in compact form, `<JWT>~<D1>~…~<Dn>~`. `IssueRequest` sets `vct`
(required by draft 19), `iss`, `iat`, `nbf` and `exp` (each optional, the times in whole seconds), `cnf.jwk` from the
holder key (a `cnf` without `iss` or `sub` is allowed, ahead of draft 19, which this package pins: RFC 7800 §3 requires
one of them, and draft-ietf-oauth-sd-jwt-vc-20 §2.2.2.3, unchanged in -22, overrides that requirement for key-bound
SD-JWT VCs) and `status.status_list` from a `statuslist.Ref`; `Claims` holds every other claim and `Disclose` the paths
to conceal. A claim whose field is unset may come in `Claims` instead, in any form the standards allow and unchecked:
`iat`, `nbf` or `exp` as a NumericDate with a fraction (RFC 7519 §2), `cnf` in any RFC 7800 form, `status` with any
mechanism; `iss` and `vct` never. The claims draft 19 §2.2.2.3 forbids disclosing, those given in `Claims` included, are
added after the concealed claims, so they carry neither a disclosure nor a decoy, and a `Disclose` path starting at one
is refused. `aka_vcts` must be a non-empty array of strings without the value of `vct` (§2.2.2.2). Decoys need at least
one `Disclose` path (§2.2.2.5). The key is a `statuslist.SigningKey`, as for `SignToken`: `alg` follows the curve of its
`Public` and `typ` is `dc+sd-jwt`. Prefer P-256: an `ES256K` credential is accepted only by verifiers that choose to
support secp256k1 (see Algorithms in the `jose` README). Its `Signer` must return the 64-byte `r‖s` of the 32-byte
digest it gets (`jws.Signer`). The root module's `signer.P256Provider` does; `signer.DefaultProvider` returns
go-ethereum's 65-byte `r‖s‖v`, so `Issue` with it fails with `jws.ErrSelfCheck`, and it needs a wrapper that returns the
first 64 bytes. `Issue` sets no size or depth limit of its own. `sdjwt.Conceal`, which does the work, refuses more than
1000 paths, a `MinDigests` over 1000, or (objects and arrays of `Claims`, plus the top level) × `MinDigests` over 20000
digests, with `jose.ErrInvalidArgument`. Holders and verifiers built on this SDK refuse a credential over 1 MiB, with
more than 1000 disclosures, or nested deeper than 32 levels (`sdjwt.Split`, `sdjwt.Recreate`). `Issue` writes at most
1000 disclosures, but it signs a credential over 1 MiB or nested 33 to 64 levels deep, which those readers refuse.

`Present(issued, reveal, kb)` builds what the holder sends to a verifier (RFC 9901 §7.2): the issuer-signed JWT with only the
disclosures of the claims in `reveal` and of their concealed ancestors, each once and in the issued order, and, with a
`KeyBinding`, a Key Binding JWT signed with the key of `cnf.jwk`. An empty `reveal` sends no disclosure. Naming a claim
inside a concealed object sends that object's disclosure too, which shows its other plain members. `Present` does not
verify the issuer's signature: check the credential when you receive it. With a `KeyBinding`, a credential with no `cnf`,
in the Issuer-signed JWT or any Disclosure, is `jose.ErrInvalidArgument`; a `cnf` or `cnf.jwk` in a Disclosure, which
draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 forbids, is `jose.ErrMalformed`. A `cnf` with no `jwk` anywhere, or a `cnf.jwk`
whose `kty` (`oct` aside) or `crv` jose/jwk does not convert, is `ErrKeyBindingUnsupported`, which says nothing about
whether the `cnf` is valid; any other `cnf` that is not a usable public key, one that is not a JSON object (RFC 7800 §3)
and `oct` (§3.2) included, and a `cnf` with more than one of `jwk`, `jwe` and `jku` (§3.1), is `jose.ErrMalformed`.

`Verify(ctx, presented, policy)` checks what a verifier receives (draft-ietf-oauth-sd-jwt-vc-19 §2.4) and returns the
processed claims (RFC 9901 §7.1): `typ` `dc+sd-jwt`, the issuer key from `Policy.Issuers` by `iss` and `kid`, the
signature with `Policy.AllowedAlgs` (ES256 and ES256K), the Disclosures, none of a claim §2.2.2.3 keeps out of them,
`exp` and `nbf` with `Policy.ClockSkew`, `aud` against `Policy.CredentialAudience`, `vct`, Key Binding (RFC 9901
§7.3) against `Policy.Audience` and `Policy.Nonce`, and status last, through `Policy.Status` (a `statuslist.Checker`).
`Policy.KeyBinding` decides when Key Binding is required, as §7.3 step 1 leaves to the verifier: by default exactly when
the credential has `cnf`, so a credential without `cnf` passes with `KeyBound` false; `KeyBindingRequired` for every
credential; `KeyBindingNotRequired` for a holder or a verifier expecting an SD-JWT, which refuse a Key Binding JWT (RFC
9901 §7.2, §4); a verifier that merely does not need one sets `IgnoreUncheckedKBJWT` too. `SkipStatus` accepts a
credential without checking its status, and `Result.StatusSkipped` says so. A refused token is an `*Error` whose `Code`
the caller branches on; `ErrPolicy` is the caller's own mistake, and can show for some tokens only; any other error is
the caller's `ctx` ending. A claim concealed and not disclosed leaves no trace, so a withheld `cnf` reads as no `cnf`.

`Hash(token)` returns SHA-256 of the bytes of a credential's Issuer-signed JWT exactly as given, the part before the
first `~` (RFC 9901 §4), so a credential and each presentation of it have one hash: use it to name a credential, for
example to record or anchor it. Any other serialization, the same token with its signature's S flipped included, has
another hash. `Hash` verifies nothing, so take the hash of the string `Issue` returned or of a token `Verify` accepted.

For OpenID4VP 1.0 transaction data (§8.4), the holder puts the claim its transaction data type defines in
`KeyBinding.Claims`, such as `transaction_data_hashes` (Appendix B.3.3.1: the base64url hash of each `transaction_data`
string as received, by sha-256, or when the request lists `transaction_data_hashes_alg` by one of those, named in a
`transaction_data_hashes_alg` claim), and the verifier compares `Result.KeyBindingClaims` with its request. `Verify`
checks only the claims of RFC 9901 §7.3 step 5 and returns those of a Key Binding JWT only when it checked one;
`KeyBinding.Claims` cannot replace `iat`, `aud`, `nonce` or `sd_hash`. `aud` is the Client Identifier with its prefix
(Appendix B.3.6, §14.8), such as `decentralized_identifier:did:example:123`; over the Digital Credentials API it is
`origin:` followed by the Origin (Appendix A.4).

`statuslist` builds Token Status Lists (draft-ietf-oauth-status-list-21): `New(size, bits)` or `FromBytes(b, bits)`
makes a list of 1-, 2-, 4- or 8-bit entries (§4.1), `Set` and `Get` write and read entry `i`, `Encode` and
`Decode(lst, bits)` convert the byte array to and from `lst` (ZLIB, then base64url, §4.2), and `SignToken` signs a
Status List Token (§5.1) with a `jws.Signer`. The bit width is the issuer's choice. A list holds at most 16 MiB once
inflated, and `Decode` refuses a larger one, a preset dictionary and a bad checksum. `SignToken` signs a token of any
size (draft 21 sets no limit), but the `Checker` refuses one over 1 MiB, which holds only about 576 KiB of list bytes
that do not compress: a larger list reads only while it compresses well, so size or split lists for the highest change
rate expected (draft 21 §13.4, App. B).

`statuslist.Checker` reads the status of a Referenced Token (draft 21 §8): `NewChecker(issuers)` takes the
`issuerkey.Resolver` the credential is verified with, and `Status(ctx, Ref{URI, Index}, iss)` fetches the token at
`URI`, verifies it with the key of `iss` that its `kid` names, checks `typ`, `sub`, `iat`, `exp`, `nbf` and `aud` (§5.1,
§8.3) and a present `iss` (RFC 8725 §3.8), and returns the raw value at `Index` (§7); what the value means is your
decision. The Status List Token is verified with ES256 or ES256K as the key's curve decides; `Policy.AllowedAlgs` does
not reach it; to restrict it, give `NewChecker` a resolver that returns only keys on the allowed curves. Every error
means no statement about the status can be made. `Ref.Validate` applies the rules of §6.2 to a `Ref` (`uri` a URI, with
a host when it is http or https as RFC 9110 §4.2 requires, `idx` not negative), for an issuer writing one into a
credential; `Status` also requires an https `uri`, this SDK's verifier default, since §6.2 leaves restrictions on `uri`
to the Relying Party. `WithInsecureHTTP` lets `Status` fetch http too; over http an on-path attacker can serve an older
signed list, so a revoked credential reads valid until that list's `exp`, and can see which lists are fetched: keep it
to local development or a trusted network. Verified lists are cached per issuer and uri for the token's `ttl`, at most
24 hours and never past `exp`; a token without `ttl` is not cached. An index past a cached list, one another call cached
meanwhile included, is read from a fresh fetch of the token, since an issuer may grow a list (§13.4):
`ErrIndexOutOfBounds` comes only from the token fetched during that call, and when that fetch fails `Status` returns the
fetch's error instead. The cache counts 32 MiB, estimated from the lists and keys it holds, and a new list is not cached
while live entries fill it. Share one `Checker`: its cache and its bound of 4 concurrent decodes belong to the instance.
A cache miss can wait behind other issuers' decodes, so give `ctx` a deadline. `WithClockSkew` sets the leeway on the
token's `exp`, `nbf` and a future `iat`; zero is 1 minute, as `Policy.ClockSkew`, which `Verify` does not pass on, so
set both. `WithMaxAge` is your freshness policy (§8.3 step 4b): a token issued more than that plus the clock skew ago is
refused, and a cached list is fetched again at that age; zero sets no limit. `WithHTTPClient` passes your own
client (an egress proxy, an internal host, tests); that client is trusted code, and the address check below exists
only in the default one.

`issuerkey.Select` picks the key a JWS header names: a `kid` must match exactly one published key, and a token
without `kid` needs an issuer that publishes exactly one key; keys are never tried in turn.

`issuermeta.NewResolver(allowed)` returns an `issuerkey.Resolver` that reads the keys of an https issuer from its JWT VC
Issuer Metadata (draft-ietf-oauth-sd-jwt-vc-19 §4): the metadata at `MetadataURL(iss)`, its `issuer` identical to `iss`,
and the JWK Set in `jwks` or at `jwks_uri`. `allowed` is your trust list (§2.5): an entry ending in `/` covers every
`iss` that starts with it, except one with a `.` or `..` path segment, any other entry only the `iss` equal to it, and
`"https://"` covers every `iss` that starts with `https://` in lower case; matching is byte for byte, so case-sensitive.
An empty list, or an entry that does not start with `https://` (the scheme in any case), is `jose.ErrInvalidArgument`
from `NewResolver`: such an entry would match no `iss` or, like `"https:/"`, every one. An `iss` outside the list is
`issuerkey.ErrIssuerNotSupported` with no request made; metadata or a JWK Set that must not be used is
`issuerkey.ErrNoUsableKey` (`ISSUER_KEY_NOT_FOUND` from `Verify`); a failed retrieval is any other error
(`ISSUER_KEY_UNAVAILABLE` from `Verify`, or an error wrapping `ctx.Err()` once `ctx` has ended). Only P-256 and
secp256k1 keys whose `use`, `alg` and `key_ops`, if present, allow verifying are returned. Answers are cached for the
least `max-age` less `Age` over the responses read (the metadata, the JWK Set and each redirect), at most 24 hours,
within an estimated 4 MiB; if any of them has no valid `max-age`, says `no-store` or `no-cache`, has a `Vary` with a
member other than `Accept` or `Accept-Encoding` (`*` included), or quotes a directive argument, the answer is not
cached. A key the issuer removes can still verify while its answer is cached, and `WithoutCache` fetches every time.
Share one `Resolver`; a `statuslist.Checker` can take the same one. `WithHTTPClient` passes your own client, trusted
code as for the `Checker`.

This module does not meet HAIP 1.0 yet: §6.1.1 requires every entity to support issuer key resolution through an
`x5c` certificate chain and every SD-JWT VC to carry that chain, and §6.1 requires `x5c` on Status List Tokens.
`Verify` and the `Checker` take keys only from an `issuerkey.Resolver` by `iss` and `kid`, and neither `Issue` nor
`SignToken` writes `x5c`.

`internal/safehttp` fetches documents whose URL comes from a token, such as a status list or issuer metadata: HTTPS
without userinfo on every hop (RFC 9110 §4.2.4), or http too only when the caller opts in (`WithInsecureHTTP` for a
`Checker`), a bounded number of redirects, time and size bounds (draft-ietf-oauth-sd-jwt-vc-19 §3), and no connection to
an address that is not globally reachable (§7.1). Status lists get the same rules as this SDK's policy, since
draft-ietf-oauth-status-list-21 §6.2 leaves them to the Relying Party. The address check cannot know hosts reachable
only inside your own network; block those with your egress policy.
