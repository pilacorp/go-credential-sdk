# Go Credential SDK

This repository provides a Go SDK for working with W3C Verifiable Credentials (VCs), Verifiable Presentations (VPs), and DIDComm cryptographic utilities. It enables you to create, manage, and verify Verifiable Credentials and Presentations, as well as encrypt and decrypt messages using DIDComm standards.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Verifiable Credential (VC) Package](#verifiable-credential-vc-package)
  - [Features](#vc-features)
  - [Usage](#vc-usage)
  - [Example](#vc-example)
- [Verifiable Presentation (VP) Package](#verifiable-presentation-vp-package)
  - [Features](#vp-features)
  - [Usage](#vp-usage)
  - [Example](#vp-example)
- [DIDComm Package](#didcomm-package)
  - [Features](#didcomm-features)
  - [Usage](#didcomm-usage)
  - [API](#didcomm-api)
- [License](#license)

## Overview

- **Verifiable Credential (VC) Package**: Create, sign, serialize, and verify W3C Verifiable Credentials in Go.
- **Verifiable Presentation (VP) Package**: Create, sign, serialize, and verify W3C Verifiable Presentations containing one or more VCs.
- **DIDComm Package**: Cryptographic utilities for key derivation, message encryption, and decryption using DIDComm and JWE standards.

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
- Add ECDSA cryptographic proofs using private key hex strings
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
4. Add a cryptographic proof using one of two methods:
   - **Direct signing**: Provide private key to `AddProof()`
   - **External signing**: Get signing string, sign externally, then add signature
5. Serialize and verify the credential

### Parsing a Verifiable Credential

1. Use `vc.ParseCredential()` to parse both JSON and JWT credentials
2. Use `vc.ParseCredentialWithValidation()` for automatic validation and verification
3. Access credential data using the `Credential` interface methods

### Adding Proofs/Signatures

The SDK supports two approaches for adding cryptographic proofs:

#### **Method 1: Direct Signing**

The SDK handles the entire signing process internally.

```go
// Add cryptographic proof (works for both JSON and JWT)
err = credential.AddProof(privateKeyHex)
```

#### **Method 2: External Signing**

Get the signing string, sign externally, then add the signature back.

```go
// Step 1: Get the signing string
signingInput, err := credential.GetSigningInput()
if err != nil {
    log.Fatalf("Failed to get signing input: %v", err)
}

// Step 2: Sign externally (using your preferred signing method)
signature := signExternally(signingInput, privateKey)

// Step 3: Add the signature back
// For JSON credentials - adds DataIntegrityProof
err = credential.AddCustomProof(&dto.Proof{
    Type:               "DataIntegrityProof",
    Created:            time.Now().UTC().Format(time.RFC3339),
    VerificationMethod: "did:example:issuer#key-1",
    ProofPurpose:       "assertionMethod",
    Cryptosuite:        "ecdsa-rdfc-2019",
    ProofValue:         signature,
})

// For JWT credentials - sets signature directly
err = jwtCredential.AddCustomProof(&dto.Proof{
    Signature: signature,
})
```

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

#### **vc.WithBaseURL(url)**

Sets a custom DID resolver base URL for proof verification.

```go
// Use custom DID resolver
credential, err := vc.ParseCredential(data, vc.WithBaseURL("https://custom-did-resolver.com/api/v1/did"))
```

#### **vc.WithVerificationMethodKey(key)**

Sets a custom verification method key (default: "key-1").

```go
// Use custom verification method key
credential, err := vc.NewJSONCredential(contents, vc.WithVerificationMethodKey("key-2"))
```

Note: Setup DID resolver baseURL for resolve DID by call vc.Init(url), vp.Init(url)

- Default: https://api.ndadid.vn/api/v1/did

Supported Proof:

- type: DataIntegrityProof
- cryptosuite: ecdsa-rdfc-2019,

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
	err = credential.AddProof(privateKeyHex)
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
	err = jwtCredential.AddProof(privateKeyHex)
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
5. Add a cryptographic proof using one of two methods:
   - **Direct signing**: Provide private key to `AddProof()`
   - **External signing**: Get signing string, sign externally, then add signature
6. Serialize and verify the presentation

### Parsing a Verifiable Presentation

1. Use `vp.ParsePresentation()` to parse both JSON and JWT presentations
2. Use `vp.ParsePresentationWithValidation()` for automatic validation and verification
3. Access presentation data using the `Presentation` interface methods

### Adding Proofs/Signatures

The SDK supports two approaches for adding cryptographic proofs:

#### **Method 1: Direct Signing**

The SDK handles the entire signing process internally.

```go
// Add cryptographic proof (works for both JSON and JWT)
err = presentation.AddProof(privateKeyHex)
```

#### **Method 2: External Signing**

Get the signing string, sign externally, then add the signature back.

```go
// Step 1: Get the signing string
signingInput, err := presentation.GetSigningInput()
if err != nil {
    log.Fatalf("Failed to get signing input: %v", err)
}

// Step 2: Sign externally (using your preferred signing method)
signature := signExternally(signingInput, privateKey)

// Step 3: Add the signature back
// For JSON presentations - adds DataIntegrityProof
err = presentation.AddCustomProof(&dto.Proof{
    Type:               "DataIntegrityProof",
    Created:            time.Now().UTC().Format(time.RFC3339),
    VerificationMethod: "did:example:holder#key-1",
    ProofPurpose:       "authentication",
    Cryptosuite:        "ecdsa-rdfc-2019",
    ProofValue:         signature,
})

// For JWT presentations - sets signature directly
err = jwtPresentation.AddCustomProof(&dto.Proof{
    Signature: signature,
})
```

### Available Options

The VP package provides several options to customize behavior:

#### **vp.WithVCValidation()**

Enables validation for credentials within the presentation.

```go
// Create presentation with VC validation
presentation, err := vp.NewJSONPresentation(contents, vp.WithVCValidation())

// Parse presentation with VC validation
presentation, err := vp.ParsePresentation(data, vp.WithVCValidation())
```

#### **vp.WithVerifyProof()**

Enables proof verification during presentation parsing.

```go
// Parse presentation with proof verification
presentation, err := vp.ParsePresentation(data, vp.WithVerifyProof())

// Parse presentation with both VC validation and proof verification
presentation, err := vp.ParsePresentation(data, vp.WithVCValidation(), vp.WithVerifyProof())
```

#### **vp.WithBaseURL(url)**

Sets a custom DID resolver base URL for proof verification.

```go
// Verify presentation using custom resolver
err = presentation.Verify(vp.WithBaseURL("https://did-resolver.prod.company.com/api/v1/did"))
```

#### **vp.WithVerificationMethodKey(key)**

Sets a custom verification method key (default: "key-1").

```go
// Use custom verification method key
presentation, err := vp.NewJSONPresentation(contents, vp.WithVerificationMethodKey("key-2"))
```

Note: Setup DID resolver baseURL for resolve DID by call vc.Init(url), vp.Init(url)

- Default: https://api.ndadid.vn/api/v1/did

Supported Proof:

- type: DataIntegrityProof
- cryptosuite: ecdsa-rdfc-2019,

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
	err = presentation.AddProof(privateKeyHex)
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
	err = jwtPresentation.AddProof(privateKeyHex)
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

## Key Differences from Previous Version

### Verifiable Credentials (VC)

- **Unified Interface**: Single `Credential` interface for both JSON and JWT formats
- **Constructor Pattern**: Use `vc.NewJSONCredential()` or `vc.NewJWTCredential()` to create credentials
- **Simplified API**: `AddProof()`, `Serialize()`, `Verify()` methods work consistently across formats
- **Flexible Parsing**: `vc.ParseCredential()` automatically detects and parses both JSON and JWT formats
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

// Parse credentials
cred, err := vc.ParseCredential(data)
cred, err := vc.ParseCredentialWithValidation(data)

// Add proof and verify
err = cred.AddProof(privateKeyHex)
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

// Add proof and verify
err = pres.AddProof(privateKeyHex)
err = pres.Verify()
result, err := pres.Serialize()
```

### Options Usage Examples

#### **Combining Multiple Options**

```go
// Create credential with multiple options
credential, err := vc.NewJSONCredential(contents,
    vc.WithSchemaValidation(),
    vc.WithVerificationMethodKey("key-2"))

// Parse credential with all validation options
credential, err := vc.ParseCredential(data,
    vc.WithSchemaValidation(),
    vc.WithVerifyProof(),
    vc.WithBaseURL("https://custom-resolver.com/api/v1/did"))

// Create presentation with VC validation
presentation, err := vp.NewJSONPresentation(contents,
    vp.WithVCValidation(),
    vp.WithVerificationMethodKey("key-3"))
```

#### **Using ParseCredentialWithValidation and ParsePresentationWithValidation**

```go
// These are convenience functions that enable all validation options
credential, err := vc.ParseCredentialWithValidation(data)
// Equivalent to: vc.ParseCredential(data, vc.WithSchemaValidation(), vc.WithVerifyProof())

presentation, err := vp.ParsePresentationWithValidation(data)
// Equivalent to: vp.ParsePresentation(data, vp.WithVCValidation(), vp.WithVerifyProof())
```

#### **Options Summary**

```go
// VC options
vc.WithSchemaValidation()                    // Enable schema validation
vc.WithVerifyProof()                        // Enable proof verification
vc.WithBaseURL(url)                         // Set custom DID resolver URL
vc.WithVerificationMethodKey(key)           // Set custom verification method key

// VP options
vp.WithVCValidation()                       // Enable VC validation within presentation
vp.WithVerifyProof()                        // Enable proof verification
vp.WithBaseURL(url)                         // Set custom DID resolver URL
vp.WithVerificationMethodKey(key)           // Set custom verification method key
```

---

## License

This package is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
