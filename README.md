# Go Credential SDK

This repository provides a Go SDK for working with W3C Verifiable Credentials (VCs) and DIDComm cryptographic utilities. It enables you to create, manage, and verify Verifiable Credentials, as well as encrypt and decrypt messages using DIDComm standards.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Verifiable Credential (VC) Package](#verifiable-credential-vc-package)
  - [Features](#vc-features)
  - [Usage](#vc-usage)
  - [Example](#vc-example)
- [DIDComm Package](#didcomm-package)
  - [Features](#didcomm-features)
  - [Usage](#didcomm-usage)
  - [API](#didcomm-api)
- [License](#license)

## Overview

- **Verifiable Credential (VC) Package**: Create, sign, serialize, and verify W3C Verifiable Credentials in Go.
- **DIDComm Package**: Cryptographic utilities for key derivation, message encryption, and decryption using DIDComm and JWE standards.

## Prerequisites

- Go 1.18 or higher
- For VC: ECDSA key pair for signing/verifying
- For DIDComm: Key pairs for sender/recipient
- Internet access for fetching JSON-LD schemas (VC)
- Dependencies:
  - `github.com/xeipuuv/gojsonschema`
  - `github.com/piprate/json-gold/ld`
  - `crypto/ecdsa` (standard library)

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

- Create W3C Verifiable Credentials
- Add ECDSA cryptographic proofs
- Serialize credentials to JSON
- Verify ECDSA proofs

## <a name="vc-usage"></a>Usage

### Creating a Verifiable Credential

Use the `vc.CredentialContents` struct to define the credential's properties and pass it to `vc.CreateCredentialWithContent`.

### Adding an ECDSA Proof

Add an ECDSA proof to the credential using the `AddECDSAProofs` method, which requires a private key and a key identifier.

### Serializing the Credential

Serialize the credential to JSON using the `ToJSON` method for sharing or storage.

### Verifying the ECDSA Proof

Verify the credential's ECDSA proof using the `VerifyECDSACredential` function with the corresponding public key.

## <a name="vc-example"></a>Example

```go
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/pilacorp/go-credential-sdk/vc"
)

func main() {
	// Generate ECDSA key pair
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		fmt.Printf("Failed to generate key: %v\n", err)
		return
	}

	publicKey, ok := privateKey.Public().(*ecdsa.PublicKey)
	if !ok {
		fmt.Printf("Failed to get public key\n")
		return
	}

	// Define credential contents
	vcc := vc.CredentialContents{
		Context: []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:      "urn:uuid:db2a23dc-80e2-4ef8-b708-5d2ea7b5deb6",
		Types: []string{
			"VerifiableCredential",
			"VerifiableAttestation",
			"VerifiableEducationalID",
		},
		Issuer: "did:nda:zvHWX359A3CvfJnCYaAiAde",
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
					"eduPersonScopedAffiliation": []string{"student"},
				},
			},
		},
		Schemas: []vc.TypedID{
			{
				ID:   "https://api-test.nda.vn/trusted-schemas-registry/v3/schemas/0xff4f1fa4f0efd4306a218f669c7482d8cfcc7a13ba44f34af69f41889704002a",
				Type: "JsonSchema",
			},
		},
	}

	// Create the credential
	credential, err := vc.CreateCredentialWithContent(vcc)
	if err != nil {
		fmt.Printf("Failed to create credential: %v\n", err)
		return
	}

	// Add an embedded ECDSA proof
	err = credential.AddECDSAProofs(
		privateKey,
		"did:nda:zvHWX359A3CvfJnCYaAiAde#ExHkBMW9fmbkvV266mRpuP2sUY_N_EWIN1lapUzO8ro",
	)
	if err != nil {
		fmt.Printf("Failed to add embedded ECDSA proof: %v\n", err)
		return
	}

	// Serialize the credential to JSON
	vcSerialized, err := credential.ToJSON()
	if err != nil {
		fmt.Printf("Failed to serialize VC: %v\n", err)
		return
	}
	fmt.Printf("VC with Embedded Proof:\n%s\n\n", string(vcSerialized))

	// Verify the proof
	err = vc.VerifyECDSACredential(credential, publicKey)
	if err != nil {
		fmt.Printf("Failed to verify embedded ECDSA proof: %v\n", err)
		return
	}
	fmt.Println("ECDSA proof verified successfully")
}
```

---

# DIDComm Package

## <a name="didcomm-features"></a>Features

- Key derivation from recipient public and sender private keys
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

    sharedSecret := didcomm.GetFromKeys(ReceiverPublicKey, SenderPrivateKey)
    fmt.Printf("Recipient derived: %x\n", sha256.Sum256(sharedSecret))

    jweOutput := didcomm.Encrypt(sharedSecret, message)
    fmt.Printf("JWE Output: %s\n", jweOutput)

    plaintext := didcomm.DecryptJWE(jweOutput, sharedSecret)
    fmt.Printf("Plaintext: %s\n", plaintext)
}
```

## <a name="didcomm-api"></a>API

- `GetFromKeys(receiverPub, senderPriv []byte) []byte`: Derives a shared secret from the recipient's public and sender's private keys.
- `Encrypt(sharedSecret []byte, message string) string`: Encrypts a message using the shared secret and returns a JWE string.
- `DecryptJWE(jwe string, sharedSecret []byte) string`: Decrypts a JWE string using the shared secret and returns the plaintext message.

**Notes:**

- Replace `ReceiverPublicKey` and `SenderPrivateKey` with your actual key variables.
- The package assumes you are familiar with DIDComm and JWE standards.

---

## License

This package is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
