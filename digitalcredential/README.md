# `digitalcredential` — IETF SD-JWT VC

IETF SD-JWT VC (`dc+sd-jwt`); for a W3C VC secured with SD-JWT (`vc+sd-jwt`) use `credential/vc`.

Module `github.com/pilacorp/go-credential-sdk/digitalcredential`, tagged `digitalcredential/v0.x.y`. It imports
neither go-ethereum nor the root module of go-credential-sdk; it imports module `jose`.

`Issue(req, key)` signs an SD-JWT VC and returns it in compact form, `<JWT>~<D1>~…~<Dn>~`. `IssueRequest` sets `vct`
(required by draft 19), `iss`, `iat`, `nbf` and `exp` (each optional, the times in whole seconds), `cnf.jwk` from the
holder key and `status.status_list` from a `statuslist.Ref`; `Claims` holds every other claim and `Disclose` the paths
to conceal. A claim whose field is unset may come in `Claims` instead, in any form the standards allow and unchecked:
`iat`, `nbf` or `exp` as a NumericDate with a fraction (RFC 7519 §2), `cnf` in any RFC 7800 form, `status` with any
mechanism; `iss` and `vct` never. The claims draft 19 §2.2.2.3 forbids disclosing, those given in `Claims` included, are
added after the concealed claims, so they carry neither a disclosure nor a decoy, and a `Disclose` path starting at one
is refused. `aka_vcts` must be a non-empty array of strings without the value of `vct` (§2.2.2.2). Decoys need at least
one `Disclose` path (§2.2.2.5). The key is a `statuslist.SigningKey`, as for `SignToken`: `alg` follows the curve of its
`Public` and `typ` is `dc+sd-jwt`. `Issue` sets no size limit, but holders and verifiers built on this SDK refuse a
credential over 1 MiB (`sdjwt.Split`).

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
decision. Every error means no statement about the status can be made. `Ref.Validate` applies the rules of §6.2 to a
`Ref` (`uri` a URI, with a host when it is http or https as RFC 9110 §4.2 requires, `idx` not negative), for an issuer
writing one into a credential; `Status` also requires an https `uri`, this SDK's verifier default, since §6.2 leaves
restrictions on `uri` to the Relying Party. `WithInsecureHTTP` lets `Status` fetch http too; over http an on-path
attacker can serve an older signed list, so a revoked credential reads valid until that list's `exp`, and can see which
lists are fetched: keep it to local development or a trusted network. Verified lists are cached per issuer and uri for
the token's `ttl`, at most 24 hours and never past `exp`; a token without `ttl` is not cached. The cache counts 32 MiB
of list bytes plus key lengths, and a new list is not cached while live entries fill it. Share one `Checker`: its cache
and its bound of 4 concurrent decodes belong to the instance. A cache miss can wait behind other issuers' decodes, so
give `ctx` a deadline. `WithHTTPClient` passes your own client (an egress proxy, an internal host, tests); that client
is trusted code, and the address check below exists only in the default one.

`issuerkey.Select` picks the key a JWS header names: a `kid` must match exactly one published key, and a token
without `kid` needs an issuer that publishes exactly one key; keys are never tried in turn.

`internal/safehttp` fetches documents whose URL comes from a token, such as a status list or issuer metadata: HTTPS
without userinfo on every hop (RFC 9110 §4.2.4), or http too only when the caller opts in (`WithInsecureHTTP` for a
`Checker`), a bounded number of redirects, time and size bounds (draft-ietf-oauth-sd-jwt-vc-19 §3), and no connection to
an address that is not globally reachable (§7.1). Status lists get the same rules as this SDK's policy, since
draft-ietf-oauth-status-list-21 §6.2 leaves them to the Relying Party. The address check cannot know hosts reachable
only inside your own network; block those with your egress policy.
