# Provenance of the W3C `ecdsa-sd-2023` test vectors

The files in this directory are the **W3C worked example** for the
`ecdsa-sd-2023` cryptosuite. Both the inputs and the expected outputs were
authored by W3C / Digital Bazaar, not by this repository. They are used as a
byte-exact conformance gate (see `conformance_test.go`): each phase recomputes a
value from these inputs and asserts byte-for-byte equality against the published
expected value.

## Source

- Specification: *Data Integrity ECDSA Cryptosuites v1.0*, the `ecdsa-sd-2023`
  worked example (the "Selective Disclosure" / "Representation: ecdsa-sd-2023"
  appendix and its numbered Examples).
  https://www.w3.org/TR/vc-di-ecdsa/
- Reference implementation the example tracks:
  https://github.com/digitalbazaar/ecdsa-sd-2023-cryptosuite

## File → spec mapping

| File | Content | Spec reference |
|---|---|---|
| `credential.json` | Unsigned input credential | Worked-example input document |
| `keys.json` | `baseKeyPair` + `proofKeyPair` (P-256 Multikey) | Example key material |
| `pointers.json` | Mandatory JSON pointers | Worked-example mandatory pointers |
| `reveal.json` | Selective-disclosure (reveal) pointers | Worked-example reveal document |
| `canonical.nq` | URDNA2015 canonical N-Quads of the input | Example 75 |
| `expected.json` | Expected intermediate + final values (HMAC labels, proofHash, mandatoryHash, baseProofValue, selectJsonLd, derived labelMap, derivedProofValue, baseSignature) | Examples 76, 80–82, 85, 89 and the derived-proof appendix |

## How to verify independently

1. Open the spec at the URL above and locate the numbered Examples in the
   `ecdsa-sd-2023` section.
2. Compare each value in `expected.json` (and `canonical.nq`) against the
   corresponding Example. They must match character-for-character.
3. Run `go test ./credential/common/ecdsasd/...`. A green run with no skips means
   this implementation reproduces the W3C example exactly.

If the spec is revised and these vectors are regenerated, update both the files
here and this provenance note in the same change.
