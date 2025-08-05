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
go get github.com/your-repo/go-credential-sdk
```

Ensure dependencies are installed:

```bash
go get github.com/xeipuuv/gojsonschema
go get github.com/piprate/json-gold/ld
```

---

# Verifiable Credential (VC) Package

## <a name="vc-features"></a>Features

- Create W3C Verifiable Credentials with flexible context and schema support
- Add ECDSA cryptographic proofs using private key hex strings
- Support for credential status (revocation/suspension)
- Serialize credentials to JSON
- Parse and verify ECDSA proofs with DID resolution
- Custom field support in credential subjects

## <a name="vc-usage"></a>Usage

### Prerequisites for Creating a VC

To create a Verifiable Credential, you need:

1. **Issuer Private Key**: Generate securely using `crypto/ecdsa` package, then convert to hex format
2. **Verification Method**: DID identifier with key fragment (e.g., `"did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce#key-1"`)
3. **DID Resolution Endpoint**: Initialize the VC package with a DID resolver URL

### Creating a Verifiable Credential

1. Initialize the VC package with a DID resolver endpoint
2. Define credential contents using `vc.CredentialContents`
3. Create the credential using `vc.CreateCredentialWithContent`
4. Add an ECDSA proof using the issuer's private key
5. Serialize and verify the credential

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

	"github.com/pilacorp/go-credential-sdk/vc"
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
	vc.Init("https://auth-dev.pila.vn/api/v1/did")

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

	// Create the credential
	credential, err := vc.CreateCredentialWithContent(vcc)
	if err != nil {
		log.Fatalf("Failed to create credential: %v", err)
	}

	// Add an ECDSA proof using private key hex and verification method
	err = credential.AddECDSAProof(privateKeyHex, method)
	if err != nil {
		log.Fatalf("Failed to add ECDSA proof: %v", err)
	}

	// Serialize the credential to JSON
	vcSerialized, err := credential.ToJSON()
	if err != nil {
		log.Fatalf("Failed to serialize VC: %v", err)
	}
	fmt.Printf("VC with Embedded Proof:\n%s\n\n", string(vcSerialized))

	// Parse and verify the credential
	verifyVC, err := vc.ParseCredential(vcSerialized)
	if err != nil {
		log.Fatalf("Failed to parse VC: %v", err)
	}
	fmt.Println("Parsed VC:", verifyVC)

	// Verify the ECDSA proof (uses DID resolution for public key)
	isValid, err := vc.VerifyECDSACredential(verifyVC)
	if err != nil {
		log.Fatalf("Failed to verify ECDSA proof: %v", err)
	}
	fmt.Println("ECDSA proof verified successfully - result:", isValid)
}
```
**Notes:**

- Replace `PrivateKey` and `VerificationMethod` with your actual key variables.
- The package assumes you are familiar with W3C Verifiable Presentations standards.
- Ensure your DID resolver endpoint is accessible and supports the DID methods you're using.
- VCs included in the presentation should be valid and properly signed.

---

# Verifiable Presentation (VP) Package

## <a name="vp-features"></a>Features

- Create W3C Verifiable Presentations containing one or more VCs
- Add ECDSA cryptographic proofs using holder's private key
- Parse and verify presentation structure and proofs
- Support for custom contexts and presentation types
- DID resolution for proof verification

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
4. Create the presentation using `vp.CreatePresentationWithContent`
5. Add an ECDSA proof using the holder's private key
6. Serialize and verify the presentation

## <a name="vp-example"></a>Example

```go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"

	"github.com/pilacorp/go-credential-sdk/vc"
	"github.com/pilacorp/go-credential-sdk/vp"
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
	vp.Init("https://auth-dev.pila.vn/api/v1/did")

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

	// Create the presentation
	presentation, err := vp.CreatePresentationWithContent(vpc)
	if err != nil {
		log.Fatalf("Failed to create presentation: %v", err)
	}

	// Add an ECDSA proof using holder's private key
	err = presentation.AddECDSAProof(privateKeyHex, vmID)
	if err != nil {
		log.Fatalf("Failed to add ECDSA proof: %v", err)
	}

	// Serialize the presentation to JSON
	presentationJSON, err := presentation.ToJSON()
	if err != nil {
		log.Fatalf("Failed to serialize presentation: %v", err)
	}
	fmt.Printf("VP with Embedded Proof:\n%s\n\n", string(presentationJSON))

	// Parse the presentation to verify its structure
	parsedPresentation, err := vp.ParsePresentation(presentationJSON)
	if err != nil {
		log.Fatalf("Failed to parse presentation: %v", err)
	}

	// Parse presentation contents for inspection
	parsedPresentationContent, err := parsedPresentation.ParsePresentationContents()
	if err != nil {
		log.Fatalf("Failed to parse presentation contents: %v", err)
	}
	log.Printf("Parsed Presentation Contents:\n%+v\n", parsedPresentationContent)

	// Verify the ECDSA proof in the presentation (uses DID resolution)
	isValid, err := vp.VerifyECDSAPresentation(parsedPresentation)
	if err != nil {
		log.Fatalf("Error verifying ECDSA proof: %v", err)
	}

	if !isValid {
		log.Fatal("ECDSA proof verification failed in the presentation")
	}
	log.Println("ECDSA proof verified successfully in the presentation")
}
```
**Notes:**

- Replace `PrivateKey` and `VerificationMethod` with your actual key variables.
- The package assumes you are familiar with W3C Verifiable Presentations standards.
- Ensure your DID resolver endpoint is accessible and supports the DID methods you're using.
- VCs included in the presentation should be valid and properly signed.

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
- Uses hex-encoded private keys instead of `*ecdsa.PrivateKey` objects
- Requires initialization with DID resolver endpoint via `vc.Init()`
- Supports flexible JSON-LD contexts with custom vocabulary mappings
- Includes credential status support for revocation/suspension
- Enhanced schema support with `vc.Schema` type
- Verification uses DID resolution instead of requiring public key parameter

### Verifiable Presentations (VP)
- New VP package for creating and managing Verifiable Presentations
- Similar initialization pattern with `vp.Init()` for DID resolution
- Support for multiple VCs within a single presentation
- Holder-based proof model (holder signs the presentation)
- Comprehensive parsing and verification capabilities

### General Improvements
- Better error handling and logging patterns throughout
- Support for custom fields in credential subjects
- Enhanced JSON serialization and parsing
- Integration with DID resolution services for cryptographic proof verification

---

## License

This package is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
