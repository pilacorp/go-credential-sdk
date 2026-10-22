IETF SD-JWT VC (`dc+sd-jwt`); for a W3C VC secured with SD-JWT (`vc+sd-jwt`) use `credential/vc`.

# `digitalcredential` — SD-JWT VC

Module `github.com/pilacorp/go-credential-sdk/digitalcredential`, tagged `digitalcredential/v0.x.y`. It stays at `v0`
while SD-JWT VC and Token Status List are drafts. It imports `jose` from this repository and nothing else from it: no
go-ethereum, no package of the root module.

`Issue`, `Parse`, `Present` and `Verify` come in later steps. This version carries `statuslist`.

## Algorithms

`ES256` (P-256) is the default. `ES256` is the only algorithm HAIP requires every wallet and verifier to support, so an
`ES256K` (secp256k1) credential is accepted only by verifiers that choose to support secp256k1. Issuers choosing a key
should know this.

## `statuslist` — Token Status List (draft 21)

Issuer side:

```go
l, err := statuslist.New(100_000, 2)        // 2 bits per entry: 0x00 valid, 0x01 revoked, 0x02 suspended
err = l.Set(917, 0x01)
token, err := statuslist.SignToken(l, statuslist.TokenClaims{
    Sub:      "https://issuer.example/statuslists/7", // exactly the uri written in the credentials
    IssuedAt: now,
    Expiry:   now.Add(24 * time.Hour),
    TTL:      time.Hour,
}, statuslist.SigningKey{Signer: signer, KID: kid}) // same key as the credentials
```

On chain, the issuer anchors `l.Bytes()` — exactly the inflated `lst` of the token — under
`statuslist.ChainListID(bits, listID)`, e.g. `dc-b2-15`. `FromBytes` rebuilds a list from those bytes and
`ParseChainListID` reverses the id.

Verifier side:

```go
checker, err := statuslist.NewChecker(statuslist.Options{Issuers: resolver}) // the resolver used for the credential
res, err := checker.Status(ctx, statuslist.Ref{URI: uri, Index: idx}, iss, vct)
```

`Status` fetches the token with `Accept: application/statuslist+jwt`, checks the signature first with the key of the
credential's issuer, then `typ`, `sub == uri`, `iat` and `exp`, decodes `lst` with the token's `bits` (1, 2, 4 or 8)
and returns the raw value. Every failure is an error, never a status. The list is cached per (issuer, uri) for `ttl`,
at most 24 hours and never past `exp`.

Limits: 5 s per fetch, 3 redirects (HTTPS only), 64 KB of token, 16 MB inflated. The default HTTP client refuses
loopback, private, link-local, unspecified, multicast and IPv4-mapped forms of these at the dialer
(`ErrBlockedAddress`), which also covers redirects and DNS answers. `Options.AllowPrivateNetworks` exists for tests and
local development only.

Reading a list back from the chain is a follow-up.
