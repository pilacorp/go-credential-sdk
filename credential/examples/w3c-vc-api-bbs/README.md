# w3c-vc-api-bbs

Minimal [VC API](https://w3c-ccg.github.io/vc-api/) server exposing this module's
`bbs-2023` cryptosuite for the
[w3c/vc-di-bbs-test-suite](https://github.com/w3c/vc-di-bbs-test-suite).

| Endpoint | Request | Response |
|---|---|---|
| `POST /credentials/issue` | `{credential, options.mandatoryPointers}` | `{verifiableCredential}` (base proof) |
| `POST /credentials/derive` | `{verifiableCredential, options.selectivePointers}` | `{verifiableCredential}` (derived) |
| `POST /credentials/verify` | `{verifiableCredential, options}` | `200` if valid, `400` if not |

The issuer key is a BLS12-381 G2 key surfaced as a self-resolving `did:key`, so no
external DID resolver is needed. Selective disclosure (`derive`) and verification
use the zkryptium BBS engine, so the Rust bridge must be built (same prerequisite
as the BBS tests).

## Run

```sh
# from the repo root
go run ./credential/examples/w3c-vc-api-bbs/
```

The server prints its `did:key` issuer id and a ready-to-paste `localConfig.cjs`
block. Copy that into `vc-di-bbs-test-suite/localConfig.cjs`, then in the test
suite directory:

```sh
npm i
npm test
```

Override the issuer key with `ISSUER_BBS_HEX` and the port with `PORT`.
