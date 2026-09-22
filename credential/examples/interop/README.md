# Interop: issue in Go, verify with @digitalbazaar/vc

Two files. `main.go` issues a Verifiable Credential with this SDK's
`ecdsa-rdfc-2019` cryptosuite; `verify.mjs` verifies it with
[`@digitalbazaar/vc`](https://github.com/digitalbazaar/vc), the reference
implementation — an independent check that the signing algorithm follows
[Data Integrity ECDSA Cryptosuites v1.0 § 3.2](https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-rdfc-2019).

## 1. Issue

```bash
go run ./credential/examples/interop
```

```
wrote vc.json
verify it with: node verify.mjs vc.json   (see README.md)
```

`vc.json` holds the signed credential and the issuer's public key.

## 2. Verify

`@digitalbazaar/vc` is not a dependency of this repo, so clone and install it
once — the script looks for it next to this repo, at `../vc`:

```bash
git clone https://github.com/digitalbazaar/vc ../vc && (cd ../vc && npm install)
```

Then:

```bash
node credential/examples/interop/verify.mjs
```

```
vc.json: verified
```

Paths default relative to the repo, not to your working directory, so this works
from anywhere — including from inside the `vc` checkout:

```bash
node /path/to/go-credential-sdk/credential/examples/interop/verify.mjs
```

Exit code is 0 when it verifies, 1 when it does not, 2 when the credential or
the checkout is missing. Override with `--vc-dir=PATH` (or `VC_DIR=PATH`), and
pass a different credential as a positional argument.

Nothing needs to be copied: the script resolves the library and its cryptosuite
packages out of that checkout. Its document loader has no network fallback, so a
context that is not bundled fails loudly rather than being fetched silently.

## Why P-256

The example signs with **P-256**. Data Integrity ECDSA Cryptosuites v1.0 allows
only P-256 and P-384 for `ecdsa-rdfc-2019`, and `@digitalbazaar/ecdsa-multikey`
does not implement secp256k1 (its source carries a `FIXME` saying so).

The SDK issues and verifies `ecdsa-rdfc-2019` with **P-256** (`signer.NewP256Provider`
and a P-256 Multikey verification method); this example uses that path, and the
same output is checked against the W3C test vectors in
`credential/common/jsonmap/conformance_rdfc_test.go`. A secp256k1 signer routed
to a P-256 verification method is rejected at signing time rather than producing
a proof no conformant verifier would accept. P-384 is not implemented yet.

## secp256k1 has its own suite, and the two implementations disagree

A secp256k1 key does sign JSON-LD — through `EcdsaSecp256k1Signature2019`, not
through a Data Integrity cryptosuite. That path cannot be checked the way this
example checks `ecdsa-rdfc-2019`, because the two published implementations do
not agree on the signature format.

`ecdsa-secp256k1-signature-2019` (via `secp256k1-key-pair@1.1.0`) DER-encodes the
ECDSA signature it puts in `jws`, and decodes the same way when verifying.
[RFC 7518 § 3.4](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4) is
explicit that a JWS ECDSA signature is the raw `r||s` concatenation — "The JWS
Signature value MUST be a 64-octet sequence. If it is not a 64-octet sequence,
the validation has failed." So the two do not interoperate in either direction:
that library emits ~70 DER bytes this SDK refuses, and this SDK emits the
64 raw bytes that library cannot parse.

The other implementation, `lds-ecdsa-secp256k1-2019.js` from the Decentralized
Identity Foundation, signs the compact 64-byte form and builds the same signing
input this SDK does: header `{"alg":"ES256K","b64":false,"crit":["b64"]}`,
then header + "." + hashData.

This SDK follows the RFC, so it lines up with that second implementation and
not with the Digital Bazaar one. The note exists so the next person does not
rediscover it from a confusing length error.
