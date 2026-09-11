# Provenance of the W3C `ecdsa-rdfc-2019` P-256 test vectors

The files in this directory are the **W3C worked example** for the
`ecdsa-rdfc-2019` cryptosuite with a P-256 key. Both the inputs and the expected
outputs were authored by W3C / Digital Bazaar, not by this repository. They are
used as a byte-exact conformance gate (see `conformance_rdfc_test.go`): each
phase recomputes a value from these inputs and asserts byte-for-byte equality
against the published expected value.

## Source

- Specification: *Data Integrity ECDSA Cryptosuites v1.0*, the `ecdsa-rdfc-2019`
  worked example. https://www.w3.org/TR/vc-di-ecdsa/
- Vector files: https://github.com/w3c/vc-di-ecdsa, directory
  `TestVectors/ecdsa-rdfc-2019-p256/` (the top-level set, not the `employ/`
  subdirectory) plus `TestVectors/p256KeyPair.json`.

The top-level set is used rather than `employ/` because its credential is built
only from `https://www.w3.org/ns/credentials/v2` and
`https://www.w3.org/ns/credentials/examples/v2`, both of which are embedded in
`credential/common/processor`. The tests therefore run offline. The `employ/`
set additionally requires `https://w3id.org/citizenship/v4rc1`, which is not
bundled and would make the tests depend on the network.

## File → algorithm mapping

| File | Content | Spec section |
|---|---|---|
| `signedECDSAP256.json` | The signed credential (an `AlumniCredential`) | Worked-example output |
| `p256KeyPair.json` | Issuer P-256 Multikey pair | Example key material |
| `proofConfigECDSAP256.json` | Proof options plus the document `@context` | 3.2.5 Proof Configuration |
| `canonDocECDSAP256.txt` | URDNA2015 canonical N-Quads of the credential without its proof | 3.2.3 Transformation |
| `proofCanonECDSAP256.txt` | URDNA2015 canonical N-Quads of the proof configuration | 3.2.5 |
| `docHashECDSAP256.txt` | SHA-256 of `canonDocECDSAP256.txt` | 3.2.4 Hashing |
| `proofHashECDSAP256.txt` | SHA-256 of `proofCanonECDSAP256.txt` | 3.2.4 |
| `combinedHashECDSAP256.txt` | `proofHash \|\| docHash` (the 64-byte hashData) | 3.2.4 step 3 |
| `sigHexECDSAP256.txt` | Raw signature, `r \|\| s`, 64 bytes | 3.2.2 Proof Serialization |
| `sigBTC58ECDSAP256.txt` | The same signature as multibase base58btc — the `proofValue` | 3.2.1 step 6 |

## How to verify independently

1. Open the spec at the URL above and locate the `ecdsa-rdfc-2019` worked
   example, or fetch the vector files from the `vc-di-ecdsa` repository.
2. Compare each file here against its counterpart. They must match
   character-for-character.
3. Run `go test ./credential/common/jsonmap/...`. A green run with no skips
   means this implementation reproduces the W3C example exactly.

If the spec is revised and these vectors are regenerated, update both the files
here and this provenance note in the same change.
