# Go Credential SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/pilacorp/go-credential-sdk.svg)](https://pkg.go.dev/github.com/pilacorp/go-credential-sdk)
[![Go Report Card](https://goreportcard.com/badge/github.com/pilacorp/go-credential-sdk?style=flat-square)](https://goreportcard.com/report/github.com/pilacorp/go-credential-sdk)
[![Release](https://img.shields.io/github/v/release/pilacorp/go-credential-sdk?include_prereleases&style=flat-square)](https://github.com/pilacorp/go-credential-sdk/releases)
[![License](https://img.shields.io/github/license/pilacorp/go-credential-sdk.svg?style=flat-square)](https://github.com/pilacorp/go-credential-sdk/blob/main/LICENSE)

This repository provides a Go SDK for working with W3C Verifiable Credentials (VCs), Verifiable Presentations (VPs), and DIDComm cryptographic utilities. It enables you to create, manage, and verify Verifiable Credentials and Presentations, as well as encrypt and decrypt messages using DIDComm standards.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Verifiable Credential (VC) Package](#verifiable-credential-vc-package)
  - [Features](#vc-features)
  - [Usage](#vc-usage)
  - [SD-JWT (Selective Disclosure)](#sd-jwt-selective-disclosure)
  - [vc-jose-cose (VC 2.0 secured as a JWT)](#vc-jose-cose)
  - [Presentations secured as a JWT (vp+jwt)](#vp-jose-cose)
  - [ecdsa-sd-2023 (Selective Disclosure for JSON-LD)](#ecdsa-sd-2023)
  - [Example](#vc-example)
- [Verifiable Presentation (VP) Package](#verifiable-presentation-vp-package)
  - [Features](#vp-features)
  - [Usage](#vp-usage)
  - [Example](#vp-example)
- [DIDComm Package](#didcomm-package)
  - [Features](#didcomm-features)
  - [Usage](#didcomm-usage)
  - [API](#didcomm-api)
- [On-Chain VC Verification (vccontract) Package](#vccontract-package)
  - [Features](#vccontract-features)
  - [Usage](#vccontract-usage)
  - [API](#vccontract-api)
- [License](#license)

## Overview

- **Verifiable Credential (VC) Package**: Create, sign, serialize, and verify W3C Verifiable Credentials in Go.
- **Verifiable Presentation (VP) Package**: Create, sign, serialize, and verify W3C Verifiable Presentations containing one or more VCs.
- **DIDComm Package**: Cryptographic utilities for key derivation, message encryption, and decryption using DIDComm and JWE standards.
- **On-Chain VC Verification (vccontract) Package**: Read-only client to verify that a VC hash is anchored on-chain in the Credential Registry smart contract (no private key, no gas).

## Prerequisites

- Go 1.18 or higher
- For VC/VP: Secure private key generation using `crypto/ecdsa` package and verification method for signing/verifying
- Internet access for DID resolution and JSON-LD context fetching
- Dependencies:
  - `github.com/xeipuuv/gojsonschema`
  - `github.com/piprate/json-gold/ld`
  - `crypto/ecdsa` (standard library)
  - `crypto/elliptic` (standard library)
  - `crypto/rand` (standard library)

## Installation

Install the package using:

```bash
go get github.com/pilacorp/go-credential-sdk
```

Ensure dependencies are installed:

```bash
go get github.com/xeipuuv/gojsonschema
go get github.com/piprate/json-gold/ld
```

---

# Verifiable Credential (VC) Package

## <a name="vc-features"></a>Features

- Create W3C Verifiable Credentials in both JSON and JWT formats
- **SD-JWT** (RFC 9901): issue and parse credentials with selective disclosure; Holder can reveal only chosen claims to Verifiers
- Add ECDSA cryptographic proofs via pluggable signer providers (Vault/HSM/local)
- Support for credential status (revocation/suspension)
- Serialize credentials to their native format (JSON object or JWT string)
- Parse and verify credentials with DID resolution
- Custom field support in credential subjects
- Flexible options for validation and verification

## <a name="vc-usage"></a>Usage

### Prerequisites for Creating a VC

To create a Verifiable Credential, you need:

1. **Issuer Private Key**: Generate securely using `crypto/ecdsa` package, then convert to hex format
2. **Verification Method**: DID identifier with key fragment (e.g., `"did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce#key-1"`)
3. **DID Resolution Endpoint**: Initialize the VC package with a DID resolver URL

### Creating a Verifiable Credential

1. Initialize the VC package with a DID resolver endpoint
2. Define credential contents using `vc.CredentialContents`
3. Create the credential using `vc.NewJSONCredential()` or `vc.NewJWTCredential()`
4. Add a cryptographic proof using `AddProof()` with a signer provider
5. Serialize and verify the credential

### Terms of Use

`CredentialContents.TermsOfUse` maps to the W3C `termsOfUse` property, which lets an
issuer state the conditions under which a credential may be used. `Type` is required,
`ID` is optional:

```go
vcc := vc.CredentialContents{
	// ... other contents ...
	TermsOfUse: []vc.TermsOfUse{
		{Type: "PresentationRequiredPolicy"},
		{ID: "https://example.com/policies/credential/4", Type: "IssuerPolicy"},
	},
}
```

Produces:

```json
"termsOfUse": [
  { "type": "PresentationRequiredPolicy" },
  {
    "id": "https://example.com/policies/credential/4",
    "type": "IssuerPolicy"
  }
]
```

Unlike `credentialStatus` and `credentialSchema`, a single entry is **not** collapsed into
a bare object — `termsOfUse` always serializes as an array. An entry with an empty `Type`
is rejected with an error. The property is omitted entirely when the slice is empty.

The spec does not define any concrete terms-of-use types; `IssuerPolicy` and `HolderPolicy`
are illustrative.

#### Declaring your policy type

Your policy type **must** be declared in `@context` — either through an `@vocab` mapping or
by using an absolute IRI as the type. The base context
`https://www.w3.org/ns/credentials/v2` defines the `termsOfUse` *property*, but it defines
no policy types and carries **no `@vocab`**, so an undeclared type has nothing to resolve
against:

```
// @context: ["https://www.w3.org/ns/credentials/v2"]
_:c14n0 <...#type> <PresentationRequiredPolicy> .           // relative IRI — not a valid absolute IRI

// @context: [..., {"@vocab": "https://ndadid.vn/ns#"}]
_:c14n0 <...#type> <https://ndadid.vn/ns#PresentationRequiredPolicy> .
```

This is **mandatory** for the `ecdsa-rdfc-2019` and `ecdsa-sd-2023` proof suites, which sign
over canonicalized RDF: a relative IRI is resolved differently by different JSON-LD
processors, producing a different canonical form and therefore a different hash, so a
third-party verifier can reject a credential this SDK considers valid. JWT credentials do
not canonicalize and are unaffected — but a credential issued today may be re-issued under
a Data Integrity proof later.

#### Selective disclosure and `mandatoryPointers`

Under `ecdsa-sd-2023`, pass `/termsOfUse` in the mandatory paths given to
`AddProofByProvider`. The SDK adds nothing to that list on your behalf. If the policy is
left selectively disclosable, a holder can derive a proof that omits `termsOfUse` entirely,
and the verifier sees a well-formed, correctly signed credential carrying no policy — with
no indication that anything was removed. This differs from `credentialStatus`: dropping
status leaves the verifier aware it cannot check revocation, whereas dropping `termsOfUse`
leaves it unaware there was ever a condition.

### Parsing a Verifiable Credential

1. Use `vc.ParseCredential()` to parse both JSON and JWT credentials
2. Use `vc.ParseCredentialWithValidation()` for automatic validation and verification
3. Access credential data using the `Credential` interface methods

### Extracting Fields from a Credential

Use `ExtractField(path string)` to extract any field from a credential using dot-notation path:

```go
// Parse a credential (works for JSON, JWT, or SD-JWT)
cred, err := vc.ParseCredential(credentialBytes)

// Extract nested fields using dot notation
name := cred.ExtractField("credentialSubject.name")
city := cred.ExtractField("credentialSubject.address.city")

// Returns nil if field doesn't exist
email := cred.ExtractField("credentialSubject.email")
if email != nil {
    fmt.Println("Email:", email)
}
```

**Supported paths:**
- `"credentialSubject.name"` - nested object fields
- `"credentialSubject.address.city"` - deeply nested fields
- Returns `nil` for array indices (e.g., `"credentialSubject.emails[0]"` is not supported)

### Adding Proofs/Signatures

The SDK signs via a single pluggable signer provider — anything that can sign a
digest (local key, Vault, HSM, KMS):

```go
type SignerProvider interface {
    Sign(digest []byte) ([]byte, error)
}
```

The cryptosuite is chosen from the **key type of the bound verification method**
(read from the resolved DID document at signing time), together with the
credential type:

| Credential / method | VM key type | Proof suite |
|---|---|---|
| `JSONCredential` / `JSONPresentation` | P-256 | `DataIntegrityProof` / `ecdsa-rdfc-2019` |
| `JSONCredential` / `JSONPresentation` | secp256k1 | `EcdsaSecp256k1Signature2019` (detached JWS — see below) |
| `ECDSASDCredential` | P-256 | `ecdsa-sd-2023` (selective disclosure) |
| `JWTCredential` / `JWTPresentation` | secp256k1 | `ES256K` (JWT) |
| `JWTCredential` / `JWTPresentation` | P-256 | `ES256` (JWT) |

Any other combination is rejected at signing time (`unsupported key kind ...`).
The caller never names the suite: there is no option for it, because the key
already decides which suites apply.

**secp256k1 signs under `EcdsaSecp256k1Signature2019`.**
[`vc-di-ecdsa`](https://www.w3.org/TR/vc-di-ecdsa/) defines its cryptosuites for
P-256 and P-384 only — it says of the third curve that it "is not used by this
specification" — so a secp256k1 key has no Data Integrity cryptosuite. What it
does have is the suite the CCG published for it,
[`EcdsaSecp256k1Signature2019`](https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/):
URDNA2015 canonicalization, SHA-256 digests, `ES256K`, and the signature in a
detached JWS in `jws` rather than in `proofValue`.

The suite names itself in `type`, so the proof carries no `cryptosuite`
property. Data Integrity allows this: `cryptosuite` is required only when
`type` is `DataIntegrityProof`.

The suite needs its terms defined, and `credentials/v2` defines Data Integrity
only. So the SDK appends `https://w3id.org/security/suites/secp256k1-2019/v1`,
the narrow context for this suite alone, after the base context. The document
keeps every 2.0 property it had, `BitstringStatusListEntry` included. Nothing
is appended to a document that already defines the suite, such as one built on
the VC 1.1 base context elsewhere: those terms are `@protected`, and a second
definition is a redefinition error rather than a no-op. This SDK itself issues
VC 2.0 documents only.

The suite is a CCG report, not a W3C Recommendation, and it says of itself that
it "is not fit for production deployment". Outside this deployment, expect
verifiers to reject a secp256k1 embedded proof whichever suite it names — P-256
with `ecdsa-rdfc-2019` is the interoperable path.

P-384 is **not supported yet**: the ECDSA cryptosuites spec also defines a P-384
profile (SHA-384, 96-byte signature), and the key-material helpers already parse
P-384 JWKs and Multikeys, but signing and verification are wired for P-256
(SHA-256, 64-byte signature) only — a P-384 verification method is reported as
an unrecognized key type. RSA / `JsonWebSignature2020` is **verify-only**
(see below).

Built-in providers: `NewDefaultProvider(hex)` (secp256k1);
`NewP256Provider` / `NewP256ProviderFromHex` / `NewP256Func` (P-256);
`NewRSAProvider(key, alg...)` / `NewRSAFunc(fn, alg)` (RSA, verification-side
helpers and low-level `jsonmap` use only).

> **A resolver is required when signing a JSON VC/VP**, even when the VM is
> pinned — the SDK reads the VM key type from the DID document to pick the
> cryptosuite. Pass `vc.WithResolver(...)` (a default HTTP resolver is used
> otherwise).

```go
prov, err := signer.NewP256ProviderFromHex(p256PrivateKeyHex) // P-256, local/dev
if err != nil { /* handle */ }
// Or keep the key in an HSM/KMS: signFn receives the 32-byte digest and must
// return the 64-byte r||s signature.
// prov, err = signer.NewP256Func(func(digest []byte) ([]byte, error) { return kms.SignP256(digest) })

cred, _ := vc.ParseJSONCredential(rawJSON)
err = cred.AddProofByProvider(prov, vc.WithResolver(resolver)) // → ecdsa-rdfc-2019
```

##### `ecdsa-rdfc-2019` proof format

The suite follows [Data Integrity ECDSA Cryptosuites v1.0 § 3.2](https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-rdfc-2019),
**P-256 profile only** (SHA-256, 64-byte `r||s`); the P-384 profile is not
supported yet.
The signature is computed over `proofConfigHash || transformedDocumentHash`
(§ 3.2.4), so the proof options — `created`, `proofPurpose`,
`verificationMethod`, `type` and `cryptosuite` — are covered by the signature
alongside the credential body, and the canonicalization preserves JSON number
types (`"age": 30` and `"age": "30"` no longer produce the same digest).

`proofValue` is **multibase base58btc** (§ 3.2.1 step 6), i.e. a string starting
with `z`:

```json
"proof": {
  "type": "DataIntegrityProof",
  "cryptosuite": "ecdsa-rdfc-2019",
  "created": "2026-01-01T00:00:00Z",
  "verificationMethod": "did:example:issuer#key-1",
  "proofPurpose": "assertionMethod",
  "proofValue": "z3PLC7..."
}
```

Signing also appends `https://w3id.org/security/data-integrity/v2` to `@context`
when the document does not already define the Data Integrity terms (VC 1.1
documents carrying only the 2018 credentials context). A context adds no RDF
triples, so this does not change the statements being signed.

> **Migration.** Credentials issued before this change carry a bare hex
> `proofValue`. Verification picks the format from the first character — `z`
> selects the new path, anything else the previous one, and the two cannot
> collide because the hex alphabet has no `z` — so **already-issued credentials
> keep verifying unchanged and there is no re-issuance**. There is no option to
> issue in the old format. Because an older SDK will reject the new format,
> **upgrade every verifying component before any issuing component.**

#### JsonWebSignature2020 (RSA) — verify-only

`JSONCredential` / `JSONPresentation` **verify** `JsonWebSignature2020` proofs
(detached JWS, `b64:false`, RS256/384/512 and PS256/384/512) issued by other
systems: the signer DID must expose a `JsonWebKey2020` verification method with
an RSA `publicKeyJwk`, and `Verify` checks the JWS against it like any other
proof in the set.

The public signing API does **not** issue them: `AddProofByProvider` on a JSON
credential/presentation binds to a P-256 or secp256k1 VM and returns
`unsupported key kind RSA for JSON-LD signing` for an RSA signer. If you need to
produce a JWS proof (e.g. test fixtures for interop), go through the low-level
`jsonmap` layer directly:

```go
var m jsonmap.JSONMap
_ = json.Unmarshal(rawJSON, &m)
rsaProvider, _ := signer.NewRSAProvider(rsaPrivateKey, "PS256") // alg defaults to RS256
err := m.AddJWSProof(rsaProvider, "did:example:issuer#key-2", "assertionMethod")
signed, _ := json.Marshal(m)
cred, _ := vc.ParseJSONCredential(signed) // verifies like any other proof
```

> **Pin the VM on mixed-key DIDs.** The suite comes from the bound VM's key type,
> NOT from the provider. If the issuer DID holds keys of different types (e.g. a
> secp256k1 key and a P-256 key, which select different JSON-LD suites), pin the
> right one
> with `vc.WithVerificationMethodKey("key-2")`; otherwise the latest active VM is
> used and a mismatched signer is rejected at signing time.

For a complete, runnable issuer → holder → derive → present → verify flow, see
[`examples/ecdsasd`](examples/ecdsasd).

#### Multiple proofs (proof set)

Calling `AddProofByProvider` more than once appends to a **proof set** — the
credential keeps every proof instead of replacing it. Each proof is independent
(it signs the unsecured document), so a credential can carry several
`ecdsa-rdfc-2019` proofs under different P-256 verification methods:

```go
cred, _ := vc.ParseJSONCredential(rawJSON)
cred.AddProofByProvider(p256SignerA, vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver)) // ecdsa-rdfc-2019
cred.AddProofByProvider(p256SignerB, vc.WithVerificationMethodKey("key-2"), vc.WithResolver(resolver)) // ecdsa-rdfc-2019
```

A proof set may also mix in a `JsonWebSignature2020` proof produced through
`jsonmap.AddJWSProof` (see above); `Verify` handles each proof by its own type.

On `Verify`, **every** proof must pass (AND), each checked against the DID
document resolved from its own `verificationMethod`. (Note: `ecdsa-sd-2023`
rewrites the document body and is always a single proof — it cannot be combined
into a proof set.)

### Available Options

The VC package provides several options to customize behavior:

#### **vc.WithSchemaValidation()**

Enables schema validation during credential creation and parsing.

```go
// Create credential with schema validation
credential, err := vc.NewJSONCredential(contents, vc.WithSchemaValidation())

// Parse credential with schema validation
credential, err := vc.ParseCredential(data, vc.WithSchemaValidation())
```

#### **vc.WithVerifyProof()**

Enables proof verification during credential parsing.

```go
// Parse credential with proof verification
credential, err := vc.ParseCredential(data, vc.WithVerifyProof())

// Parse credential with both validation and verification
credential, err := vc.ParseCredential(data, vc.WithSchemaValidation(), vc.WithVerifyProof())
```

On a JSON-LD `AddCustomProof` it also checks **the proof being attached**, before attaching it: the DID in `proof.verificationMethod` is resolved and the signature checked against that key, so a proof signed over the wrong digest or by the wrong key fails where it is added rather than at whoever receives the credential.

```go
// External signing: sign, then attach with the proof checked
docHash, _ := credential.GetSigningInput()
proofHash, _ := credential.CreateProofSigning(docHash, proof) // SHA-256 digest to sign
sig := sign(proofHash)                                        // raw 64-byte r||s, P-256
proof.ProofValue = verificationmethod.EncodeMultibaseKey(sig) // "z..." base58btc

err := credential.AddCustomProof(proof, vc.WithVerifyProof(), vc.WithResolver(resolver))
// refused -> the credential is unchanged, no proof attached
```

Import: `verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"`. `proofValue` must be the multibase `z…` string, not the raw signature: a raw or hex value is refused by the prefix check before the signature is ever looked at.

Costs one DID resolution and one canonicalization, and only when you pass the option — without it the proof is attached unchecked, as before. Only `ecdsa-rdfc-2019` can be checked this way (the suite the external signing flow produces); with the option set, another suite is refused rather than checked against bytes nobody signed — attach it without the option and call `Verify()`. The signing calls that make their own signature (`AddProof`, `AddProofByProvider`) already check it against the verification method, so the option changes nothing there.

#### **vc.WithBaseURL(url)**

Sets a custom DID resolver base URL for proof verification.

```go
// Use custom DID resolver
credential, err := vc.ParseCredential(data, vc.WithBaseURL("https://custom-did-resolver.com/api/v1/did"))
```

#### **vc.WithVerificationMethodKey(key)**

Sets the verification method key to sign with (e.g. `"key-2"`). When omitted, the SDK resolves the DID and uses its only verification method, or the latest active one listed for the proof purpose (`assertionMethod` for VCs, `authentication` for VPs).

For JSON credentials pass it when signing (`AddProofByProvider`); `NewJSONCredential` / `ParseJSONCredential` ignore it. For JWT credentials pass it to `NewJWTCredential`; the JWT signing calls refuse it, since the header's `kid` is already fixed.

```go
// Use custom verification method key
err := credential.AddProofByProvider(signer, vc.WithVerificationMethodKey("key-2"), vc.WithResolver(resolver))
```

#### **vc.WithReplaceProof()**

Lets a signing call replace a signature the credential already carries. Without it, signing an already-signed JWT credential (`vc+jwt` or VC 1.1 JWT) is refused.

A JWT holds one signature, so signing again always throws the old one away. Even with the same key and the same claims the new signature is different (ECDSA is randomized), so the token and its `Hash()` change too. The option makes that a choice instead of a side effect.

```go
err := cred.AddProofByProvider(signer)                         // refused: "credential is already signed"
err  = cred.AddProofByProvider(signer, vc.WithReplaceProof())  // replaces the signature
```

JSON-LD credentials add proofs to a list instead of replacing one, so their signing calls (`AddProof`, `AddProofByProvider`, `AddCustomProof`, and the `ecdsa-sd-2023` base proof) refuse the option rather than silently appending. One exception: an `ecdsa-sd-2023` base proof replaces the whole list, so it is refused on a document that already has a proof.

> A signing call that fails leaves the credential exactly as it was: no proof, no added `@context`, and any signature it already had still in place.

#### **vp.WithChallenge(nonce)** / **vp.WithDomain(domain)**

Set when **signing**: the nonce the verifier handed out, and who the presentation is
for. A JWT presentation writes them as the `nonce` and `aud` claims; a JSON-LD one
writes them into `proof.challenge` and `proof.domain`.

```go
err = pres.AddProofByProvider(holderSigner,
    vp.WithChallenge(nonceFromVerifier),
    vp.WithDomain("https://verifier.example"))
```

#### **vp.WithExpectedChallenge(nonce)** / **vp.WithExpectedDomain(domain)**

The verifying halves. `WithExpectedChallenge` refuses a presentation whose nonce is not
the one this verifier issued — that is what makes it fresh. `WithExpectedDomain` refuses
one not addressed to this verifier — that is what makes it unreplayable. Both imply
`WithVerifyProof`, since neither value means anything on an unverified proof.

```go
err = pres.Verify(
    vp.WithExpectedChallenge(nonceFromVerifier),
    vp.WithExpectedDomain("https://verifier.example"))
```

> On a JSON-LD presentation only an `ecdsa-rdfc-2019` proof signs its challenge and
> domain. A legacy hex or `JsonWebSignature2020` signature covers the document alone, so
> on those proofs the values are not bound to the signer.

#### **vp.WithRequireAudience()**

Requires the presentation to be bound to this verifier — and **must be paired with
`vp.WithExpectedDomain`**. Alone it is a configuration error: verification fails with
`WithRequireAudience needs WithExpectedDomain`, on both the JWT and the JSON-LD path.

```go
err = pres.Verify(
    vp.WithRequireAudience(),
    vp.WithExpectedDomain("https://verifier.example"))

// Callers who need to tell a misconfiguration apart from a bad presentation:
if errors.Is(err, vp.ErrAudienceUnbound) {
    // this verifier asked for binding without saying who it is
}
```

Why it cannot stand alone: checking that *some* audience exists checks nothing worth
having, because a presentation minted for a different verifier carries one too. Binding
needs both halves — the claim in the presentation, and the identity of whoever reads it.

RFC 7519 §4.1.3 states the rule it enforces, but enforcing it by default would break
every verifier that does not name itself today, so it is opt-in.

Note: Setup DID resolver baseURL for resolve DID by call vc.Init(url), vp.Init(url)

- Default: https://api.ndadid.vn/api/v1/did

Supported Proof:

- type: DataIntegrityProof
  - cryptosuite: ecdsa-rdfc-2019 (standard signing, P-256 only; `proofValue` is multibase base58btc — see above), ecdsa-sd-2023 (selective disclosure for JSON-LD, P-256 only — see below)
- type: EcdsaSecp256k1Signature2019 (secp256k1, detached JWS in `jws`; either data model — see above)
- type: JsonWebSignature2020 (RSA, detached JWS — verify-only, see above)

### <a name="sd-jwt-selective-disclosure"></a>SD-JWT (Selective Disclosure)

The SDK supports **SD-JWT** (Selective Disclosure for JWT) as per [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901). SD-JWT lets the Issuer issue a single credential where some claims can be **selectively disclosed** by the Holder when presenting to a Verifier. The Verifier only sees the disclosed claims (and any always-visible claims).

**Roles:**

- **Issuer**: Creates a JWT credential and marks which claims are selectively disclosable; the SDK builds disclosures and outputs an SD-JWT string (`<JWT>~<D1>~<D2>~...~`).
- **Holder**: Receives the SD-JWT, can present it as-is or omit some disclosures so the Verifier sees fewer claims.
- **Verifier**: Parses and verifies the SD-JWT; after verification, credential data reflects only the disclosed claims.

**Format:** An SD-JWT is a single string: the issuer-signed JWT, then `~`, then zero or more disclosure strings (base64url-encoded), optionally ending with `~`. Example: `eyJ...signed.eyJ...payload.sig~Wy...D1~Wy...D2~`

#### Issuer: Creating an SD-JWT credential

1. Build credential contents as usual with `vc.CredentialContents`.
2. Create a JWT credential with **selective disclosure paths** using `vc.WithSDSelectivePaths(paths)`.
3. Add proof and serialize; `Serialize()` returns the SD-JWT string.

**Selective paths** are dot-notation and array-index paths into the VC payload (e.g. into `credentialSubject` and nested objects). Examples:

| Path | Meaning |
|------|---------|
| `credentialSubject.firstname` | Top-level subject field `firstname` |
| `credentialSubject.person.address.city` | Nested field `person.address.city` |
| `credentialSubject.tags[0]` | First element of array `tags` |
| `credentialSubject.person.children[0].name` | Nested array element |

Only the claims at these paths are put into disclosures; all other claims remain in the JWT payload. The Issuer signs the payload that contains digests (e.g. `_sd`) for those claims; the actual values are in the disclosure strings.

```go
// Issuer: create SD-JWT with selective disclosure
paths := []string{
    "credentialSubject.firstname",
    "credentialSubject.family_name",
    "credentialSubject.email",
}
	cred, err := vc.NewJWTCredential(contents,
	    vc.WithSDSelectivePaths(paths),
	)
	if err != nil {
	    log.Fatal(err)
	}
	issuerSigner, err := signer.NewDefaultProvider(privateKeyHex) // local/dev only
	if err != nil {
	    log.Fatal(err)
	}
	err = cred.AddProof(issuerSigner)
	if err != nil {
	    log.Fatal(err)
	}
	sdJWT, err := cred.Serialize()
if err != nil {
    log.Fatal(err)
}
// sdJWT is a string: "<issuer-signed-JWT>~<D1>~<D2>~..."
```

**Advanced Options:** The SDK supports additional security features for SD-JWT:

```go
// Issue with custom hash algorithm, shuffle, and decoy digests
cred, err := vc.NewJWTCredential(contents,
    vc.WithSDSelectivePaths(paths),
    // Use sha-384 instead of default sha-256
    vc.WithSDHashAlgorithm("sha-384"),
    // Shuffle _sd array to prevent disclosure order leakage
    vc.WithSDShuffle(true),
    // Add decoy digests: 3 in credentialSubject, 1 in the emails array
    vc.WithSDDecoyDigests([]vc.Decoy{
        {Path: "credentialSubject", Count: 3},      // 3 decoys in credentialSubject object
        {Path: "credentialSubject.emails", Count: 1}, // 1 decoy in emails array (adds new elements)
    }),
)
```

> **Decoys go inside `credentialSubject`, not at the root.** A root path writes `_sd`
> beside `issuer`, `type` and `credentialStatus`, and the SDK refuses that — `the payload
> carries _sd at the root…` — because a digest there is indistinguishable from a
> top-level property a holder withheld, and nothing at that level may be withheld.


**Alternative (advanced):** If you build the disclosures yourself, put the processed claims — digests and all — into the contents and pass the matching disclosures with `vc.WithSDDisclosures(disclosures)`:

```go
res, err := sdjwt.BuildDisclosures(sdjwt.BuildDisclosuresInput{
    VC:             draft,
    SelectivePaths: []string{"credentialSubject.bloodType"},
})
// res.ProcessedVC["credentialSubject"] now holds the digests; carry it into
// Subject.CustomFields, then hand the disclosures back:
cred, err := vc.NewJWTCredential(contents,
    vc.WithSDDisclosures(res.Disclosures),
    vc.WithVerificationMethodKey("key-1"))
```

The builder validates them against the digests in the payload before signing: a disclosure that matches nothing, the same one twice, or a digest referenced twice fails with `invalid SD-JWT disclosures`. Do not combine this with `WithSDSelectivePaths` for the same claim — those paths make the builder generate its own digests with a fresh salt, which no previously built disclosure can match.

#### Holder: Presenting an SD-JWT

The Holder parses the SD-JWT into a credential, inspects what is disclosable, and presents only a chosen subset — keeping the issuer's signature intact:

```go
cred, err := vc.ParseJWTCredential(sdJWTString)
if err != nil { ... }

// Inspect available disclosures (field name, value, salt)
discs, _ := cred.DecodedDisclosures()
for _, d := range discs {
    fmt.Printf("Field: %s, Value: %v\n", d.FieldName, d.Value)
}

// Present only the chosen disclosure strings (keeps the issuer signature)
presented, _ := cred.Present(selectedDisclosures)
out, _ := presented.Serialize() // SD-JWT string to send to the Verifier
```

- **Present the full SD-JWT** — pass the original string to the Verifier (all disclosures).
- **Present a subset** — `cred.Present(selectedDisclosures)` builds a new SD-JWT with only the chosen disclosures. (`sdjwt.BuildSDJWTPresentation` is the lower-level equivalent.)

#### Verifier: Parsing and verifying an SD-JWT

Use the same parsing API as for ordinary JWT credentials. The `~` separators say where the disclosures are in the string; whether the credential is an SD-JWT at all is read from the **signed payload** (the digests the issuer put there), not from the `~`. A plain JWT with a `~` appended is still a plain JWT, and a payload carrying digests is reconstructed even if nothing was revealed. The SDK reconstructs the **processed payload** (only disclosed claims) before returning a `Credential`.

```go
// Verifier (or Holder): parse and verify SD-JWT
raw := []byte(sdJWTString) // e.g. from HTTP body or QR
cred, err := vc.ParseCredential(raw,
    vc.WithSchemaValidation(),
    vc.WithVerifyProof(),
)
if err != nil {
    log.Fatal(err)
}
// cred.GetContents() / GetType() etc. reflect only disclosed claims
contents, _ := cred.GetContents()
```

- **Detection:** `vc.ParseCredential` accepts JSON credentials, plain JWTs, or SD-JWTs. A `~` makes it split the string into the issuer-signed JWT and the disclosures that follow (format: `...~...` with a valid JWT before the first `~`); the payload then decides whether it is treated as an SD-JWT.
- **Verification:** Signature and standard claims (`exp`, `nbf`, etc.) are verified on the issuer-signed JWT. Schema validation, if enabled, runs on the **reconstructed** payload (disclosed claims only).
- **Validation:** The SDK validates:
  - Duplicate digest detection
  - Disclosure context validation (object vs array)
  - Hash algorithm support
- **No Key Binding:** SDK does not expose/verify Key Binding JWT (KB-JWT). The parser may skip the final JWT-like segment (if preceded by `~`) as holder binding, but does not verify it.

#### Summary

| Role | Action |
|------|--------|
| **Issuer** | `vc.NewJWTCredential(contents, vc.WithSDSelectivePaths(paths))` → `AddProof` → `Serialize()` → SD-JWT string |
| **Holder** | `vc.ParseJWTCredential(sdJWT)` → `DecodedDisclosures()` → `Present(selectedDisclosures)` → `Serialize()` |
| **Verifier** | `vc.ParseCredential(raw, vc.WithVerifyProof(), ...)` → use returned `Credential` (disclosed claims only) |

### <a name="vc-jose-cose"></a>vc-jose-cose (VC 2.0 secured as a JWT)

The data models in this SDK differ in **where the proof lives**, and that decides which
constructor to call:

| Constructor | Data model | Proof | Token |
|---|---|---|---|
| `NewJSONCredential` | VC 2.0 | embedded (`proof` inside the document) | JSON object |
| `NewJWTCredential` | VC 1.1 | the JWT signature, document under a `vc` claim | `header.payload.sig` |
| `NewJOSECredential` | **VC 2.0** | the JWS signature, document **is** the payload | `header.payload.sig`, `typ: vc+jwt` |

`NewJOSECredential` is [vc-jose-cose](https://www.w3.org/TR/vc-jose-cose/): a VC 2.0
document carried as the JWT payload itself, with no `vc` wrapper. Use it when the
consumer wants a compact token but the document must be 2.0.

```go
cred, err := vc.NewJOSECredential(vc.CredentialContents{
    Context:   []interface{}{"https://www.w3.org/ns/credentials/v2"},
    ID:        "urn:uuid:" + uuid.NewString(),
    Issuer:    issuerDID,
    Types:     []string{"VerifiableCredential"},
    ValidFrom: time.Now(),
    Subject:   []vc.Subject{{ID: holderDID, CustomFields: map[string]interface{}{"name": "A"}}},
}, vc.WithVerificationMethodKey("key-1"))
if err != nil {
    return err
}
if err := cred.AddProofByProvider(signerProvider); err != nil {
    return err
}
token, err := cred.Serialize() // "eyJ...vc+jwt...", a string

// Verifying: ParseCredential auto-detects the media type from the typ header.
parsed, err := vc.ParseCredential([]byte(token.(string)))
err = parsed.Verify()
```

Selective disclosure works here too, and then the media type becomes `vc+sd-jwt`:

```go
// Issuer: make a claim disclosable, sign, serialize.
cred, err := vc.NewJOSECredential(contents,
    vc.WithSDSelectivePaths([]string{"credentialSubject.bloodType"}),
    vc.WithVerificationMethodKey("key-1"))
if err != nil {
    return err
}
if err := cred.AddProofByProvider(signerProvider); err != nil {
    return err
}
// typ is now vc+sd-jwt and Serialize() appends the disclosures after a "~".
sdJWT, err := cred.Serialize()
if err != nil {
    return err
}

// Holder: parse the token that arrived, pick what to reveal, present that subset.
// The holder has the token, not the issuer's credential object — and Present
// needs a signature, so it must come after AddProofByProvider either way.
holderCred, err := vc.ParseJOSECredential(sdJWT.(string))
if err != nil {
    return err
}
discs, err := holderCred.DecodedDisclosures()
if err != nil {
    return err
}
presented, err := holderCred.Present([]string{discs[0].Disclosure})
```

What this path enforces that the 1.1 path does not:

- The payload must really be a **VC 2.0** credential — `@context` naming
  `https://www.w3.org/ns/credentials/v2` first, and a `type` that names a credential.
  A signature proves who wrote the bytes, not that the bytes are a credential.
- The `typ` header must match the format: a `vc+jwt` carrying SD-JWT disclosures is
  refused, and so is a `vc+sd-jwt` whose payload has none of the machinery.
- `vc` and `vp` claims are forbidden in the payload (vc-jose-cose §1.1.2.1).

### <a name="vp-jose-cose"></a>Presentations secured as a JWT (`vp+jwt`)

`NewJOSEPresentation` is the presentation half. Credentials inside it are carried
**enveloped**, as vc-jose-cose §3.1.2 requires — the SDK wraps them for you:

```go
pres, err := vp.NewJOSEPresentation(vp.PresentationContents{
    Context:               []interface{}{"https://www.w3.org/ns/credentials/v2"},
    Types:                 []string{"VerifiablePresentation"},
    Holder:                holderDID,
    VerifiableCredentials: []vc.Credential{joseCred}, // must be a *vc.JOSECredential
}, vp.WithVerificationMethodKey("key-1"))
if err != nil {
    return err
}
err = pres.AddProofByProvider(holderSigner,
    vp.WithChallenge(nonceFromVerifier),
    vp.WithDomain("https://verifier.example"))
```

Each credential appears as an `EnvelopedVerifiableCredential` whose `id` is a data URL —
`data:application/vc+jwt,<token>` or `data:application/vc+sd-jwt,<token>`. A bare
credential, or a Data Integrity one, is refused: it is not an enveloping scheme.

#### Binding a presentation to the verifier

A presentation made for one verifier should not verify at another. Both data models
carry that binding, in different places:

| Data model | Where | Verify with |
|---|---|---|
| `vp+jwt` / VC 1.1 JWT | the `aud` claim | `WithExpectedDomain` |
| JSON-LD | `proof.domain` | `WithExpectedDomain` |

```go
err = pres.Verify(
    vp.WithRequireAudience(),                            // refuse an unbound presentation
    vp.WithExpectedDomain("https://verifier.example"),   // ...bound to me
    vp.WithExpectedChallenge(nonceFromVerifier),         // ...and fresh
)
```

`WithRequireAudience` **must** be paired with `WithExpectedDomain`. Alone it is a
configuration error and verification fails with `WithRequireAudience needs
WithExpectedDomain` — checking that *some* audience exists checks nothing worth having,
because a presentation minted for a different verifier carries one too.

### <a name="ecdsa-sd-2023"></a>ecdsa-sd-2023 (Selective Disclosure for JSON-LD)

While **SD-JWT** (above) provides selective disclosure for **JWT** credentials, the SDK also supports **`ecdsa-sd-2023`** — selective disclosure for **JSON-LD / Data Integrity** credentials. It follows the W3C [Data Integrity ECDSA Cryptosuites](https://www.w3.org/TR/vc-di-ecdsa/) `ecdsa-sd-2023` mechanism, signing with **P-256 (secp256r1)** as mandated by the spec — both the issuer base signature and the per-statement ephemeral key are P-256. The issuer's P-256 key is published as a `JsonWebKey2020` verification method (`publicKeyJwk`, `crv: P-256`) in its DID document. The implementation is **byte-exact conformant** with the W3C worked example — the canonical N-Quads, HMAC label map, `proofValue` (CBOR + base64url multibase), and base58btc `Multikey` encoding all match the published vectors — so proofs interoperate with conformant `ecdsa-sd-2023` verifiers, not just other instances of this SDK.

**How it differs from SD-JWT:** SD-JWT uses salted-hash disclosures on a JWT; `ecdsa-sd-2023` produces a JSON-LD `DataIntegrityProof` and works by RDF-canonicalizing the credential into individual statements, signing each non-mandatory statement with an ephemeral key, and letting the Holder derive a proof that reveals only a chosen subset.

**Roles:**

- **Issuer**: Signs the credential and declares which claims are **mandatory** (always disclosed). Every other claim becomes selectively disclosable. Output is a *base proof* (cryptosuite `ecdsa-sd-2023`).
- **Holder**: Derives a new credential that reveals the mandatory claims plus a chosen subset; hidden claims are removed from the credential entirely.
- **Verifier**: Verifies the derived proof using the issuer's public key resolved from its DID document.

#### Issuer: creating a base credential

```go
// ecdsa-sd-2023 signs with P-256. Provide a P-256 key (in-memory, hex, or HSM):
issuerSigner, _ := signer.NewP256Provider(issuerP256PrivateKey)  // *ecdsa.PrivateKey
// or: signer.NewP256ProviderFromHex(hexScalar)
// or: signer.NewP256Func(func(digest []byte) ([]byte, error) { return hsm.SignP256(digest) })

cred, _ := vc.ParseECDSASDCredential(credentialJSON)

// Mandatory paths are always disclosed; everything else is selectable.
err := cred.AddProofByProvider(
    issuerSigner,
    []string{"issuer", "validFrom", "credentialSubject.id"}, // mandatory paths
    vc.WithVerificationMethodKey("key-1"),
    vc.WithResolver(resolver), // or rely on vc.Init(baseURL)
)
baseVC, _ := cred.Serialize()
```

#### Holder: deriving a selective-disclosure credential

```go
base, _ := vc.ParseECDSASDCredential(baseVCBytes)

// Reveal only name + dob (plus the issuer's mandatory claims); hide the rest.
derived, _ := base.Derive([]string{
    "credentialSubject.name",
    "credentialSubject.dob",
})
derivedVC, _ := derived.Serialize()
```

#### Verifier: verifying a derived credential

```go
cred, _ := vc.ParseJSONCredential(derivedVCBytes)
if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
    // invalid / tampered
}
// Hidden claims are absent:
cred.ExtractField("credentialSubject.email") // -> nil
```

**Notes:**

- **Paths** use dot-notation (`"credentialSubject.name"`), the same style as SD-JWT.
- **Keys:** P-256 (secp256r1). The issuer's verification method must be a `JsonWebKey2020` with a `publicKeyJwk` (`kty: EC`, `crv: P-256`). The per-statement ephemeral key embedded in the proof is also P-256.
- **Proof format:** `type: DataIntegrityProof`, `cryptosuite: ecdsa-sd-2023`. The `proofValue` is a multibase-base64url CBOR structure with a base (`0xd95d00`) or derived (`0xd95d01`) header.
- **Blank nodes:** handled via the spec's HMAC blank-node label map. Internal `urn:bnid:` skolemization is only a canonicalization aid and does **not** appear in the issued or derived credential body.
- A runnable end-to-end example (issue → derive → verify → VP, fully offline) is in [`examples/ecdsasd`](examples/ecdsasd/main.go). See also [`docs/ecdsa-sd-2023.md`](docs/ecdsa-sd-2023.md) for design details.

#### Summary

| Role | Action |
|------|--------|
| **Issuer** | `vc.ParseECDSASDCredential(json)` → `AddProofByProvider(signer, mandatoryPaths, ...)` → `Serialize()` → base VC |
| **Holder** | `vc.ParseECDSASDCredential(baseVC)` → `Derive(selectivePaths)` → `Serialize()` → derived VC |
| **Verifier** | `vc.ParseCredential(derivedVC)` → `Verify(vc.WithResolver(...))` → revealed claims only |

## <a name="vc-example"></a>Example

```go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

func main() {
	// Generate a secure ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Convert private key to hex format for the SDK
	privateKeyHex := fmt.Sprintf("%x", privateKey.D.Bytes())
	method := "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce#key-1"

	// Initialize VC package with DID resolver endpoint
	vc.Init("https://api.ndadid.vn/api/v1/did")

	// Define credential contents
	vcc := vc.CredentialContents{
		Context: []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2",
			map[string]interface{}{
				// Define a namespace for your custom terms
				"@vocab": "https://schema.org/version/latest/schemaorg-all-https.jsonld",
				// Map your custom terms to that namespace
				"VerifiableAttestation":      "ex:VerifiableAttestation",
				"VerifiableEducationalID":    "ex:VerifiableEducationalID",
				"eduPersonScopedAffiliation": "ex:eduPersonScopedAffiliation",
				"identifier":                 "ex:identifier",
			},
		},
		ID: "urn:uuid:db2a23dc-80e2-4ef8-b708-5d2ea7b5deb6",
		Types: []string{
			"VerifiableCredentialDTA",
			"VerifiableAttestation",
			"VerifiableEducationalID",
		},
		Issuer: "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce",
		ValidFrom: func() time.Time {
			t, _ := time.Parse(time.RFC3339, "2023-11-11T00:00:00Z")
			return t
		}(),
		ValidUntil: func() time.Time {
			t, _ := time.Parse(time.RFC3339, "2024-11-11T00:00:00Z")
			return t
		}(),
		Subject: []vc.Subject{
			{
				ID: "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbsEYvdrjxMjQ4tpnje9BDBTzuNDP3knn6qLZErzd4bJ5go2CChoPjd5GAH3zpFJP5fuwSk66U5Pq6EhF4nKnHzDnznEP8fX99nZGgwbAh1o7Gj1X52Tdhf7U4KTk66xsA5r",
				CustomFields: map[string]interface{}{
					"identifier":                 "c305487c-52ae-459e-b3d9-2a8d0a1b96e3",
					"eduPersonScopedAffiliation": []interface{}{"student"},
					"scoreabcdididid":            []int{100, 100, 100, 100, 100},
					"isActive":                   true,
				},
			},
		},
		CredentialStatus: []vc.Status{
			{
				ID:              "https://university.example/credentials/status/3#94567",
				Type:            "BitstringStatusListEntry",
				StatusPurpose:   "revocation",
				StatusListIndex: "94567",
			},
		},
		Schemas: []vc.Schema{
			{
				ID:   "http://localhost:8080/verifiable-educational-id.schema.json",
				Type: "JsonSchema",
			},
		},
	}

	// Create the credential (JSON format) with schema validation
		credential, err := vc.NewJSONCredential(vcc, vc.WithSchemaValidation())
		if err != nil {
			log.Fatalf("Failed to create credential: %v", err)
		}

		// Add a cryptographic proof using private key hex
		issuerSigner, err := signer.NewDefaultProvider(privateKeyHex) // local/dev only
		if err != nil {
			log.Fatalf("Failed to create signer: %v", err)
		}
		err = credential.AddProof(issuerSigner)
		if err != nil {
			log.Fatalf("Failed to add proof: %v", err)
		}

	// Serialize the credential to JSON
	vcSerialized, err := credential.Serialize()
	if err != nil {
		log.Fatalf("Failed to serialize VC: %v", err)
	}
	fmt.Printf("VC with Embedded Proof:\n%+v\n\n", vcSerialized)

	// Parse and verify the credential with validation and proof verification
	verifyVC, err := vc.ParseCredential([]byte(fmt.Sprintf("%v", vcSerialized)),
		vc.WithSchemaValidation(),
		vc.WithVerifyProof())
	if err != nil {
		log.Fatalf("Failed to parse VC: %v", err)
	}
	fmt.Println("Parsed VC type:", verifyVC.GetType())
	fmt.Println("Proof verified successfully")

	// Example: Create JWT credential with custom verification method key
		jwtCredential, err := vc.NewJWTCredential(vcc, vc.WithVerificationMethodKey("key-2"))
		if err != nil {
			log.Fatalf("Failed to create JWT credential: %v", err)
		}

		// Add proof to JWT credential
		err = jwtCredential.AddProof(issuerSigner)
		if err != nil {
			log.Fatalf("Failed to add proof to JWT credential: %v", err)
		}

	// Serialize JWT credential
	jwtSerialized, err := jwtCredential.Serialize()
	if err != nil {
		log.Fatalf("Failed to serialize JWT credential: %v", err)
	}
	fmt.Printf("JWT Credential:\n%s\n", jwtSerialized)
}
```

**Notes:**

- Replace `privateKeyHex` with your actual private key in hex format.
- The package assumes you are familiar with W3C Verifiable Credentials standards.
- Ensure your DID resolver endpoint is accessible and supports the DID methods you're using.
- Use `vc.WithSchemaValidation()` to enable schema validation during creation/parsing.
- Use `vc.WithVerifyProof()` to enable proof verification during parsing.
- The `Credential` interface works with both JSON and JWT formats seamlessly.

---

# Verifiable Presentation (VP) Package

## <a name="vp-features"></a>Features

- Create W3C Verifiable Presentations in both JSON and JWT formats
- Add ECDSA cryptographic proofs using holder's private key
- Parse and verify presentation structure and proofs
- Support for custom contexts and presentation types
- DID resolution for proof verification
- Flexible options for validation and verification

## <a name="vp-usage"></a>Usage

### Prerequisites for Creating a VP

To create a Verifiable Presentation, you need:

1. **Holder Private Key**: Generate securely using `crypto/ecdsa` package, then convert to hex format
2. **Verification Method**: DID identifier with key fragment for the holder
3. **Verifiable Credentials**: Array of VCs to include in the presentation
4. **DID Resolution Endpoint**: Initialize the VP package with a DID resolver URL

### Creating a Verifiable Presentation

1. Initialize the VP package with a DID resolver endpoint
2. Create or obtain Verifiable Credentials to include
3. Define presentation contents using `vp.PresentationContents`
4. Create the presentation using `vp.NewJSONPresentation()` or `vp.NewJWTPresentation()`
5. Add a cryptographic proof using `AddProof()` with a signer provider
6. Serialize and verify the presentation

### Parsing a Verifiable Presentation

1. Use `vp.ParsePresentation()` to parse both JSON and JWT presentations
2. Use `vp.ParsePresentationWithValidation()` for automatic validation and verification
3. Access presentation data using the `Presentation` interface methods

### Adding Proofs/Signatures

The SDK signs via a pluggable signer provider (Vault/HSM/local).

```go
holderSigner, err := signer.NewDefaultProvider(privateKeyHex) // local/dev only
if err != nil { /* handle */ }

// Add cryptographic proof (works for both JSON and JWT)
err = presentation.AddProof(holderSigner)
```

### Available Options

The VP package provides several options to customize behavior:

#### **vp.WithVCValidation(opts ...vc.CredentialOpt)**

Verifies every credential embedded in the presentation. With no arguments only
each credential's proof is verified. Any `vc.CredentialOpt` passed in is
forwarded to each credential's `Verify`, so the same checks available on a
standalone credential apply here — schema, revocation, expiration, and so on.
The presentation's resolver is forwarded automatically.

```go
// Proof only
presentation, err := vp.ParsePresentation(data, vp.WithVCValidation())

// Proof + credentialSchema + revocation status
presentation, err := vp.ParsePresentation(data,
    vp.WithVCValidation(vc.WithSchemaValidation(), vc.WithCheckRevocation()))
```

> Before this change `WithVCValidation()` always validated `credentialSchema`
> and rejected credentials without one. `credentialSchema` is optional in the
> VC Data Model, so schema validation is now opt-in via
> `vc.WithSchemaValidation()`.

#### **vp.WithVerifyProof()**

Enables proof verification during presentation parsing.

```go
// Parse presentation with proof verification
presentation, err := vp.ParsePresentation(data, vp.WithVerifyProof())

// Parse presentation with both VC validation and proof verification
presentation, err := vp.ParsePresentation(data, vp.WithVCValidation(), vp.WithVerifyProof())
```

On a JSON-LD `AddCustomProof` it also checks **the proof being attached**, before attaching it — same rule as `vc.WithVerifyProof()`. Here the check covers `proof.challenge` and `proof.domain` as well, since both are part of the proof configuration the signature commits to: a proof whose challenge or domain was edited after signing is refused where it is attached. This is not replay protection: an old proof with its original nonce still verifies, and the verifier rejects it with `vp.WithExpectedChallenge` / `vp.WithExpectedDomain`.

```go
err := presentation.AddCustomProof(proof, vp.WithVerifyProof(), vp.WithResolver(resolver))
// refused -> the presentation is unchanged, no proof attached
```

#### **vp.WithBaseURL(url)**

Sets a custom DID resolver base URL for proof verification.

```go
// Verify presentation using custom resolver
err = presentation.Verify(vp.WithBaseURL("https://did-resolver.prod.company.com/api/v1/did"))
```

#### **vp.WithVerificationMethodKey(key)**

Sets the verification method key to sign with (e.g. `"key-2"`). When omitted, the SDK resolves the DID and uses its only verification method, or the latest active one listed for the proof purpose (`assertionMethod` for VCs, `authentication` for VPs).

For JSON presentations pass it when signing (`AddProofByProvider`); `NewJSONPresentation` / `ParseJSONPresentation` ignore it. For JWT presentations pass it to `NewJWTPresentation`; the JWT signing calls refuse it, since the header's `kid` is already fixed.

```go
// Use custom verification method key
err := presentation.AddProofByProvider(signer, vp.WithVerificationMethodKey("key-2"), vp.WithResolver(resolver))
```

#### **vp.WithReplaceProof()**

Lets a signing call replace a signature the presentation already carries. Without it, signing an already-signed JWT presentation (`vp+jwt` or VC 1.1 JWT) is refused.

The usual reason to need it: the verifier hands out a new challenge and the holder signs again.

```go
err := pres.AddProofByProvider(signer, vp.WithChallenge(newNonce), vp.WithReplaceProof())
```

> If that re-sign fails, the presentation keeps its old signature and its old
> nonce — the new challenge is only written once a signature covering it exists.

JSON-LD presentations add proofs to a list instead of replacing one, so their signing calls (`AddProof`, `AddProofByProvider`, `AddCustomProof`) refuse the option rather than silently appending.

Note: Setup DID resolver baseURL for resolve DID by call vc.Init(url), vp.Init(url)

- Default: https://api.ndadid.vn/api/v1/did

Supported Proof:

- type: DataIntegrityProof
- cryptosuite: ecdsa-rdfc-2019 (`proofValue` is multibase base58btc)

## <a name="vp-example"></a>Example

```go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
		"log"

		"github.com/pilacorp/go-credential-sdk/credential/vc"
		"github.com/pilacorp/go-credential-sdk/credential/vp"
		"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	)

func main() {
	// Generate a secure ECDSA private key for the holder
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Convert private key to hex format for the SDK
	privateKeyHex := fmt.Sprintf("%x", privateKey.D.Bytes())
	vmID := "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce#key-1"

	// Initialize VP package with DID resolver endpoint
	vp.Init("https://api.ndadid.vn/api/v1/did")

	// Assume vcList contains previously created VCs
	// vcList := []*vc.Credential{credential1, credential2}
	var vcList []*vc.Credential // Replace with your actual VC list

	// Define presentation contents
	vpc := vp.PresentationContents{
		Context: []interface{}{
			"https://www.w3.org/ns/credentials/v2",
		},
		ID:                    "urn:uuid:abcd1234-5678-90ab-cdef-1234567890ab",
		Types:                 []string{"VerifiablePresentation"},
		Holder:                "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce",
		VerifiableCredentials: vcList,
	}

	// Create the presentation (JSON format) with VC validation
	presentation, err := vp.NewJSONPresentation(vpc, vp.WithVCValidation())
	if err != nil {
		log.Fatalf("Failed to create presentation: %v", err)
	}

		// Add a cryptographic proof using holder's private key
		holderSigner, err := signer.NewDefaultProvider(privateKeyHex) // local/dev only
		if err != nil {
			log.Fatalf("Failed to create signer: %v", err)
		}
		err = presentation.AddProof(holderSigner)
		if err != nil {
			log.Fatalf("Failed to add proof: %v", err)
		}

	// Serialize the presentation to JSON
	presentationJSON, err := presentation.Serialize()
	if err != nil {
		log.Fatalf("Failed to serialize presentation: %v", err)
	}
	fmt.Printf("VP with Embedded Proof:\n%+v\n\n", presentationJSON)

	// Parse the presentation with VC validation and proof verification
	parsedPresentation, err := vp.ParsePresentation([]byte(fmt.Sprintf("%v", presentationJSON)),
		vp.WithVCValidation(),
		vp.WithVerifyProof())
	if err != nil {
		log.Fatalf("Failed to parse presentation: %v", err)
	}

	// Get presentation contents for inspection
	contents, err := parsedPresentation.GetContents()
	if err != nil {
		log.Fatalf("Failed to get presentation contents: %v", err)
	}
	log.Printf("Parsed Presentation Contents:\n%s\n", string(contents))
	log.Println("Proof verified successfully in the presentation")

	// Example: Create JWT presentation with custom verification method key
		jwtPresentation, err := vp.NewJWTPresentation(vpc, vp.WithVerificationMethodKey("key-2"))
		if err != nil {
			log.Fatalf("Failed to create JWT presentation: %v", err)
		}

		// Add proof to JWT presentation
		err = jwtPresentation.AddProof(holderSigner)
		if err != nil {
			log.Fatalf("Failed to add proof to JWT presentation: %v", err)
		}

	// Serialize JWT presentation
	jwtSerialized, err := jwtPresentation.Serialize()
	if err != nil {
		log.Fatalf("Failed to serialize JWT presentation: %v", err)
	}
	fmt.Printf("JWT Presentation:\n%s\n", jwtSerialized)
}
```

**Notes:**

- Replace `privateKeyHex` with your actual private key in hex format.
- The package assumes you are familiar with W3C Verifiable Presentations standards.
- Ensure your DID resolver endpoint is accessible and supports the DID methods you're using.
- VCs included in the presentation should be valid and properly signed.
- Use `vp.WithVCValidation()` to enable VC validation during presentation parsing.
- Use `vp.WithVerifyProof()` to enable proof verification during parsing.
- The `Presentation` interface works with both JSON and JWT formats seamlessly.

---

# DIDComm Package

## <a name="didcomm-features"></a>Features

- Key derivation from sender public and recipient private keys
- Encryption of messages using a shared secret
- Decryption of JWE messages

## <a name="didcomm-usage"></a>Usage Example

```go
package main

import (
    "crypto/sha256"
    "fmt"
    "github.com/yourorg/go-credential-sdk/didcomm"
)

func main() {
    message := `{
        "@context": [...],
        "id": "urn:uuid:...",
        "type": ["VerifiableCredential"],
        "issuer": "did:example:123456",
        "issuanceDate": "...",
        "credentialSubject": { ... },
        "proof": {
            "type": "Ed25519Signature2020",
            "created": "...",
            "verificationMethod": "did:example:123456#key-1",
            "proofPurpose": "assertionMethod",
            "jws": "..."
        }
    }`

    sharedSecret := didcomm.GetFromKeys(SenderPublicKey, SenderPrivateKey)
    fmt.Printf("Recipient derived: %x\n", sha256.Sum256(sharedSecret))

    jweOutput := didcomm.Encrypt(sharedSecret, message)
    fmt.Printf("JWE Output: %s\n", jweOutput)

    plaintext := didcomm.DecryptJWE(jweOutput, sharedSecret)
    fmt.Printf("Plaintext: %s\n", plaintext)
}
```

## <a name="didcomm-api"></a>API

- `GetFromKeys(senderPub, senderPriv []byte) []byte`: Derives a shared secret from the sender's public and recipient's private keys.
- `Encrypt(sharedSecret []byte, message string) string`: Encrypts a message using the shared secret and returns a JWE string.
- `DecryptJWE(jwe string, sharedSecret []byte) string`: Decrypts a JWE string using the shared secret and returns the plaintext message.

**Notes:**

- Replace `SenderPublicKey` and `SenderPrivateKey` with your actual key variables.
- The package assumes you are familiar with DIDComm and JWE standards.

---

# <a name="vccontract-package"></a>On-Chain VC Verification (vccontract) Package

`credential/vccontract` is a lightweight, **read-only** client for the Credential
Registry smart contract. It lets a holder or any third party verify that a
Verifiable Credential (VC) hash is anchored on-chain — without a private key and
without spending gas.

The issuer service groups VC hashes per issuer into Merkle trees and anchors each
tree's **root** on-chain. A VC hash is a **leaf**; membership is proven with a
Merkle **proof** (the ordered sibling hashes). This package folds the proof into a
root locally and asks the chain whether that issuer anchored it — it does not
build trees or submit transactions.

**The contract keeps no roots in storage.** An anchoring is the log its
transaction emitted, and logs are never overwritten — so a proof, once issued,
stays checkable however the issuer's trees grow afterwards. It also means
verification needs the transaction hash the proof was issued against.

## <a name="vccontract-features"></a>Features

- Verify a VC hash against the transaction that anchored it, by reading that
  transaction's logs
- Reads five event shapes: the three the current contract emits and the two its
  predecessor did, so credentials anchored before the upgrade keep verifying
- Checks which contract emitted a log — anyone can deploy one emitting the same
  event signatures
- Read-only: no private key, no gas, no transactions
- Self-contained (only depends on `go-ethereum`); the contract ABI is embedded

## <a name="vccontract-usage"></a>Usage

You supply the proof components directly (this package does not call the
authen-service API). They typically come from the authen-service proof endpoint
`GetVCProofByHash` / `GetVCProofByID`, whose response carries the `TxHash`.

```go
import "github.com/pilacorp/go-credential-sdk/credential/vccontract"

registry, err := vccontract.NewCredentialRegistry(
    "https://rpc-testnet-new.pila.vn",
    "0x...CurrentDeployment",
    // Every earlier deployment whose anchorings must keep verifying. Leave one
    // out and every credential anchored by it reads as never anchored.
    "0x...PreviousDeployment",
)
if err != nil {
    log.Fatal(err)
}
defer registry.Close() // reuse one registry across calls; Close on shutdown

ok, err := registry.VerifyVCHashByTx(context.Background(), &vccontract.VerifyByTxRequest{
    IssuerAddress:   "0x...Issuer",
    Leaf:            "0x...vcHash",              // 32-byte hex
    Proof:           []string{"0x...", "0x..."}, // sibling hashes (empty for a single-leaf tree)
    TxHash:          "0x...",                    // from the proof API — store it with the VC
    ContractAddress: "0x...",                    // optional; pins the lookup to one deployment
})
if errors.Is(err, vccontract.ErrTxNotFound) {
    // unknown or not yet mined — worth retrying
}
```

> **`TxHash` is part of the proof, not metadata.** Store it alongside the VC: a
> proof without it cannot be checked. If it is lost, the proof API can reissue it.

A runnable example lives in [`credential/examples/vccontract/verifybytx`](credential/examples/vccontract/verifybytx).

### What a `true` proves — and what the verifier must supply itself

A `true` means exactly one thing:

> **an anchoring of this root was recorded under this issuer address — by the issuer itself or by a WRITER of a trusted deployment — and this leaf is in it.**

Two of the inputs decide what that sentence is *about*, and neither can be taken
from whoever is presenting the credential.

- **`Leaf` — hash the VC yourself.** The tree hashes sibling pairs but does not
  hash leaves, so a leaf and an inner node are both just 32 bytes and the fold
  cannot tell them apart. An inner node, presented with the rest of its path,
  reproduces the anchored root one step shorter — and verification says true,
  correctly: that value really is in the tree. It says nothing about any
  credential. Only hashing the document in front of you ties the answer to that
  document.
- **`IssuerAddress` — derive it from the VC's own `issuer`, and check it against
  the issuers you trust.** The contract lets any address anchor roots under itself
  (`anchorTreeRoot` and `batchAnchorIssuerTreeRoots` accept the caller as its own
  issuer). So anyone can build a tree containing anything, anchor it under an
  address they control, and hand over a valid proof. `true` then means "that
  address anchored this" — true, and worthless.

`TxHash`, `Proof` and `ContractAddress` are safe to take from the bundle: they
cannot make a false claim verify. A bad one yields `false`, or an error —
`ErrTxNotFound` for an unknown hash, `ErrUntrustedContract` for an untrusted
pin — so cap retries on `ErrTxNotFound` when the hash came from the holder.

### Reading the result

`(true, nil)` means the chain attests the leaf. `(false, nil)` means **the chain
was asked and it does not** — the proof folds to no root this transaction anchored
for this issuer, or the transaction reverted and so anchored nothing. Both are
verdicts, not failures.

An error means **the chain could not be asked**, and nothing was established
either way. Errors worth branching on: `ErrTxNotFound` (unknown or not yet mined),
`ErrUntrustedContract` (a pinned `ContractAddress` this client was not configured
to trust).

A caller that needs to tell a reverted transaction apart from a proof that simply
does not match calls `IsRootAnchored` directly — the layer below, which returns
`ErrTxReverted` unchanged. It is keyed on the root rather than the leaf, so fold
first with the exported `FoldProof`; reimplementing that rule risks a fold that
differs in some detail and produces a different root with nothing to signal it.

### Why the transaction hash is required

There is no tree index any more. The contract records an anchoring as
`(issuer, root)` and nothing else, so "what root did tree 7 get?" has no single
answer: one transaction anchors many of an issuer's trees and nothing in the log
tells them apart.

Folding the proof first removes the need for a tiebreaker. Every root in the log
is one the issuer really anchored, so finding your folded root among them proves
exactly what verification is for.

### Trusting the right contract

Reading a root from a log means trusting whoever emitted it, and anyone can deploy
a contract emitting these exact event signatures. The client therefore only
believes logs from the addresses passed to `NewCredentialRegistry`. Setting
`ContractAddress` narrows that further to the one deployment that anchored the
proof; it must already be trusted, or the call returns `ErrUntrustedContract` —
pinning can only narrow what is believed, never widen it.

## <a name="vccontract-api"></a>API

- `NewCredentialRegistry(rpcURL, contractAddress string, alsoTrust ...string) (*CredentialRegistry, error)` — connect to the chain (RPC connection required). `alsoTrust` names earlier deployments whose anchoring logs are still to be believed.
- `(*CredentialRegistry) VerifyVCHashByTx(ctx, *VerifyByTxRequest) (bool, error)` — verify a VC hash against the transaction that anchored it. **This is the one to use.**
- `(*CredentialRegistry) IsRootAnchored(ctx, txHash common.Hash, issuer common.Address, root [32]byte) (bool, error)` — whether a transaction records this issuer anchoring this root. Reports the chain's state rather than a verdict: returns `ErrTxNotFound` and `ErrTxReverted` instead of folding them into `false`.
- `(*CredentialRegistry) IsRootAnchoredAtContract(ctx, txHash, issuer, root, contractAddress common.Address) (bool, error)` — the same, restricted to one deployment.
- `(*CredentialRegistry) Close()` — release the RPC connection.

**Deprecated.** These call contract functions the current deployment does not
have, so against it they can only fail; they work solely against an older one that
still keeps roots in storage.

- `(*CredentialRegistry) VerifyVCHashOnChain(ctx, *VerifyRequest) (bool, error)`
- `(*CredentialRegistry) GetTreeRoot(ctx, issuer string, treeIndex uint64) ([32]byte, error)`
- `(*CredentialRegistry) HasTree(ctx, issuer string, treeIndex uint64) (bool, error)`
- `(*CredentialRegistry) GetAnchoredRoot(ctx, txHash, issuer, treeIndex uint64) ([32]byte, error)` — kept for source compatibility with v1.9.x. Reads the legacy `BatchTreesUpdated` event only, so a root anchored by the current contract is never found through it (`ErrRootNotAnchored`). Use `IsRootAnchored`.

> Reuse a single `CredentialRegistry` across calls (it holds a live,
> concurrency-safe RPC client) and `Close()` it on shutdown rather than creating
> one per request.

---


## Key Differences from Previous Version

### Verifiable Credentials (VC)

- **Unified Interface**: Single `Credential` interface for both JSON and JWT formats
- **Constructor Pattern**: Use `vc.NewJSONCredential()` or `vc.NewJWTCredential()` to create credentials
- **Simplified API**: `AddProof()`, `Serialize()`, `Verify()` methods work consistently across formats
- **Flexible Parsing**: `vc.ParseCredential()` automatically detects and parses JSON, JWT, and SD-JWT (selective disclosure) formats
- **Options Pattern**: Use `vc.WithSchemaValidation()`, `vc.WithVerifyProof()` for configuration
- **Uses hex-encoded private keys** instead of `*ecdsa.PrivateKey` objects
- **Requires initialization** with DID resolver endpoint via `vc.Init()`
- **Supports flexible JSON-LD contexts** with custom vocabulary mappings
- **Includes credential status support** for revocation/suspension
- **Enhanced schema support** with `vc.Schema` type
- **Verification uses DID resolution** instead of requiring public key parameter

### Verifiable Presentations (VP)

- **Unified Interface**: Single `Presentation` interface for both JSON and JWT formats
- **Constructor Pattern**: Use `vp.NewJSONPresentation()` or `vp.NewJWTPresentation()` to create presentations
- **Simplified API**: `AddProof()`, `Serialize()`, `Verify()` methods work consistently across formats
- **Flexible Parsing**: `vp.ParsePresentation()` automatically detects and parses both JSON and JWT formats
- **Options Pattern**: Use `vp.WithVCValidation()`, `vp.WithVerifyProof()` for configuration
- **Similar initialization pattern** with `vp.Init()` for DID resolution
- **Support for multiple VCs** within a single presentation
- **Holder-based proof model** (holder signs the presentation)
- **Comprehensive parsing and verification capabilities**

### General Improvements

- **Consistent API Design**: Both VC and VP packages follow the same patterns
- **Better error handling** and logging patterns throughout
- **Support for custom fields** in credential subjects
- **Enhanced JSON serialization and parsing**
- **Integration with DID resolution services** for cryptographic proof verification
- **Type Safety**: Strong typing with `CredentialData` and `PresentationData` types

## Quick Reference

### VC API

```go
// Create credentials
jsonCred, err := vc.NewJSONCredential(contents)
jwtCred, err := vc.NewJWTCredential(contents)
sdJwtCred, err := vc.NewJWTCredential(contents, vc.WithSDSelectivePaths([]string{"credentialSubject.email"}))

// Parse credentials (works for JSON, JWT, or SD-JWT)
cred, err := vc.ParseCredential(data)
cred, err := vc.ParseCredentialWithValidation(data)

	// Add proof and verify
	issuerSigner, err := signer.NewDefaultProvider(privateKeyHex) // local/dev only
	err = cred.AddProof(issuerSigner)
	err = cred.Verify()
	result, err := cred.Serialize()
```

### VP API

```go
// Create presentations
jsonPres, err := vp.NewJSONPresentation(contents)
jwtPres, err := vp.NewJWTPresentation(contents)

// Parse presentations
pres, err := vp.ParsePresentation(data)
pres, err := vp.ParsePresentationWithValidation(data)

// Create a VC 2.0 presentation secured as a JWT (vc-jose-cose)
josePres, err := vp.NewJOSEPresentation(contents)

	// Add proof and verify
	holderSigner, err := signer.NewDefaultProvider(privateKeyHex) // local/dev only
	err = pres.AddProof(holderSigner)
	err = pres.Verify()
	result, err := pres.Serialize()

// Bind the presentation to this verifier
err = pres.Verify(
	vp.WithRequireAudience(),                          // needs WithExpectedDomain
	vp.WithExpectedDomain("https://verifier.example"),
	vp.WithExpectedChallenge(nonceFromVerifier))
```

### Options Usage Examples

#### **Combining Multiple Options**

```go
// Create credential with multiple options
credential, err := vc.NewJSONCredential(contents, vc.WithSchemaValidation())
// WithVerificationMethodKey applies where the proof is made: AddProofByProvider
// for JSON credentials, NewJWTCredential for JWT credentials.
err = credential.AddProofByProvider(signer, vc.WithVerificationMethodKey("key-2"))

// Parse credential with all validation options
credential, err := vc.ParseCredential(data,
    vc.WithSchemaValidation(),
    vc.WithVerifyProof(),
    vc.WithBaseURL("https://custom-resolver.com/api/v1/did"))

// Create presentation with VC validation
presentation, err := vp.NewJSONPresentation(contents, vp.WithVCValidation())
err = presentation.AddProofByProvider(signer, vp.WithVerificationMethodKey("key-3"))

// Verify a presentation that is bound and fresh
err = presentation.Verify(
    vp.WithVCValidation(),
    vp.WithRequireAudience(),
    vp.WithExpectedDomain("https://verifier.example"),
    vp.WithExpectedChallenge(nonceFromVerifier))
```

#### **Using ParseCredentialWithValidation and ParsePresentationWithValidation**

```go
// These are convenience functions that enable all validation options
credential, err := vc.ParseCredentialWithValidation(data)
// Equivalent to: vc.ParseCredential(data, vc.WithSchemaValidation(), vc.WithVerifyProof())

presentation, err := vp.ParsePresentationWithValidation(data)
// Equivalent to: vp.ParsePresentation(data, vp.WithVCValidation(), vp.WithVerifyProof())
```

#### **vc.WithSDSelectivePaths(paths)** / **vc.WithSDDisclosures(disclosures)**

Used when **issuing** JWT credentials to produce an SD-JWT (selective disclosure).

- **WithSDSelectivePaths(paths)**: SDK builds disclosures for the given claim paths (e.g. `"credentialSubject.email"`, `"credentialSubject.tags[0]"`). When you call `Serialize()`, the result is an SD-JWT string.
- **WithSDDisclosures(disclosures)**: Attach disclosure strings you built yourself, against digests you put in the contents (advanced; normally use `WithSDSelectivePaths`). Validated against the payload before signing — see above.

```go
// Issue SD-JWT with selective disclosure
cred, err := vc.NewJWTCredential(contents,
    vc.WithSDSelectivePaths([]string{"credentialSubject.firstname", "credentialSubject.email"}),
)
// ... AddProof(...); then Serialize() returns SD-JWT string
```

Parsing SD-JWT uses the same API as JWT: `vc.ParseCredential(sdJWTBytes, vc.WithVerifyProof(), ...)`.

#### **Options Summary**

```go
// VC options
vc.WithSchemaValidation()                    // Enable schema validation
vc.WithVerifyProof()                        // Enable proof verification
vc.WithBaseURL(url)                         // Set custom DID resolver URL
vc.WithVerificationMethodKey(key)           // Set custom verification method key
vc.WithSDSelectivePaths(paths)              // Issue SD-JWT: claims at these paths are selectively disclosable
vc.WithSDDisclosures(disclosures)           // Issue SD-JWT: disclosures you built, matching digests already in the contents
vc.WithReplaceProof()                       // Allow signing to replace a signature already present

// VP options
vp.WithVCValidation()                       // Enable VC validation within presentation
vp.WithVerifyProof()                        // Enable proof verification
vp.WithBaseURL(url)                         // Set custom DID resolver URL
vp.WithVerificationMethodKey(key)           // Set custom verification method key
vp.WithReplaceProof()                       // Allow signing to replace a signature already present
```

---

## License

This package is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
