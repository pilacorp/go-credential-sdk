# Verifiable Credential (VC) Package

This package provides functionality to create, manage, and verify W3C Verifiable Credentials (VCs) in Go, following the [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/). It supports creating credentials, adding cryptographic proofs, serializing to JSON, and verifying proofs.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
  - [Creating a Verifiable Credential](#creating-a-verifiable-credential)
  - [Adding an ECDSA Proof](#adding-an-ecdsa-proof)
  - [Serializing the Credential](#serializing-the-credential)
  - [Verifying the ECDSA Proof](#verifying-the-ecdsa-proof)
- [Example](#example)
- [License](#license)

## Prerequisites
- Go 1.18 or higher
- A cryptographic key pair (e.g., ECDSA P-256) for signing and verifying proofs
- Internet access for fetching JSON-LD schemas
- Dependencies:
  - `github.com/xeipuuv/gojsonschema`
  - `github.com/piprate/json-gold/ld`
  - `crypto/ecdsa` (standard library)

## Installation
Install the package using:

```bash
go get github.com/your-repo/vc
```

Ensure dependencies are installed:

```bash
go get github.com/xeipuuv/gojsonschema
go get github.com/piprate/json-gold/ld
```

## Usage

### Creating a Verifiable Credential
To create a new Verifiable Credential, use the `vc.CredentialContents` struct to define the credential's properties and pass it to `vc.CreateCredentialWithContent`.

### Adding an ECDSA Proof
Add an ECDSA proof to the credential using the `AddECDSAProofs` method, which requires a private key and a key identifier.

### Serializing the Credential
Serialize the credential to JSON using the `ToJSON` method for sharing or storage.

### Verifying the ECDSA Proof
Verify the credential's ECDSA proof using the `VerifyECDSACredential` function with the corresponding public key.

## Example
Below is a complete example of creating a Verifiable Credential, generating an ECDSA key pair, adding an ECDSA proof, serializing it, and verifying the proof.

```go
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"

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
		Context: []string{"https://www.w3.org/ns/credentials/v2"},
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

### Steps Explained
1. **Generate Key Pair**: Use `crypto.GenerateKey` to create an ECDSA key pair.
2. **Define Credential Contents**: Create a `vc.CredentialContents` struct with required fields like context, ID, types, issuer, validity dates, subject, and schema.
3. **Create Credential**: Use `vc.CreateCredentialWithContent` to convert the contents into a `vc.Credential`.
4. **Add ECDSA Proof**: Use `credential.AddECDSAProofs` to add an ECDSA proof with the private key and key identifier.
5. **Serialize to JSON**: Use `credential.ToJSON` to serialize the credential for sharing or storage.
6. **Verify Proof**: Use `vc.VerifyECDSACredential` to validate the proof with the corresponding public key.

## License
This package is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.