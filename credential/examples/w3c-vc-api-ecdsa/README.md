# Minimal VC API server for the W3C ecdsa-sd-2023 test suite

A tiny HTTP server that exposes this module's `ecdsa-sd-2023` implementation
through the [VC API](https://w3c-ccg.github.io/vc-api/) endpoints that
[`w3c/vc-di-ecdsa-test-suite`](https://github.com/w3c/vc-di-ecdsa-test-suite)
drives:

| Endpoint | Body in | Body out |
|---|---|---|
| `POST /credentials/issue` | `{credential, options.mandatoryPointers}` | `{verifiableCredential}` (base proof) |
| `POST /credentials/derive` | `{verifiableCredential, options.selectivePointers}` | `{verifiableCredential}` (derived) |
| `POST /credentials/verify` | `{verifiableCredential, options}` | `200` if valid, `400` if not |

The issuer key is a P-256 key surfaced as a self-resolving `did:key`, so no
external DID resolver is needed.

## 1. Run the server

```bash
cd go-credential-sdk
go run ./credential/examples/w3c-vc-api-ecdsa
```

It prints the issuer `did:key` and a ready-to-paste `localConfig.cjs`. To keep
the same key (and config) across restarts, copy the printed `ISSUER_P256_HEX`:

```bash
ISSUER_P256_HEX=<hex> PORT=8080 go run ./credential/examples/w3c-vc-api-ecdsa
```

## 2. Point the test suite at it

```bash
git clone https://github.com/w3c/vc-di-ecdsa-test-suite
cd vc-di-ecdsa-test-suite
npm i
# paste the snippet the server printed into localConfig.cjs (overwrite issuer.id
# with the printed did:key), then:
BASE_URL=http://localhost:8080 npm test
```

The printed config tags the issuer/verifier `['ecdsa-sd-2023']`, the vcHolder
`['vcHolder']`, key type `P-256`, and `supports.vc: ['2.0']`.

## Scope / caveats

- **Only `ecdsa-sd-2023`, `P-256`, VC 2.0.** Tests tagged `ecdsa-rdfc-2019`,
  `ecdsa-jcs-2019`, `P-384`, or VC 1.1 are intentionally out of scope and will be
  skipped by the suite given the tags above.
- The verifier resolves any `did:key` P-256 method id in the proof, so it
  verifies both the credentials it issued and the suite's own derived ones.
- The server needs outbound network only if a test credential references a
  remote JSON-LD context that isn't bundled in `credential/common/processor`
  (e.g. `credentials/examples/v2`); the standard `credentials/v2` context is
  bundled and served offline.
- `options.mandatoryPointers` / `options.selectivePointers` arrive as JSON
  Pointers and are passed straight through to the suite.

## What a green run demonstrates

Independent, externally authored conformance: the official W3C suite issues,
derives, tampers, and verifies against this server, exercising many documents
and negative cases the in-repo byte-exact gates do not.
