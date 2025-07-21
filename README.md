# Verifiable Credential (VC) Package

This package provides functionality to create, manage, and verify W3C Verifiable Credentials (VCs) in Go, following the [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/). It supports creating credentials, adding cryptographic proofs, serializing to JSON, and verifying proofs.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
    - [Creating a Verifiable Credential](#creating-a-verifiable-credential)
    - [Adding a Proof](#adding-a-proof)
    - [Serializing the Credential](#serializing-the-credential)
    - [Verifying the Proof](#verifying-the-proof)
- [Example](#example)
- [License](#license)

## Prerequisites
- Go 1.18 or higher
- A cryptographic key pair (e.g., ECDSA P-256) for signing and verifying proofs
- Internet access for fetching JSON-LD schemas
- Dependencies:
    - `github.com/xeipuuv/gojsonschema`
    - A JSON-LD document loader (e.g., `github.com/piprate/json-gold/ld`)

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

### Adding a Proof
Add a cryptographic proof (e.g., ECDSA) to the credential using a `ProofCreator`. The proof ensures the credential's integrity and authenticity.

### Serializing the Credential
Serialize the credential to JSON using the `ToJSON` method for sharing or storage.

### Verifying the Proof
Verify the credential's proof using a `ProofVerifier` to ensure its authenticity.

## Example
Below is a complete example of creating a Verifiable Credential, adding an ECDSA proof, serializing it, and verifying the proof.

```go
package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/piprate/json-gold/ld"
	"github.com/your-repo/vc"
)

func main() {
	// Define credential contents
	vcc := vc.CredentialContents{
		Context: []string{"https://www.w3.org/ns/credentials/v2"},
		ID:      "urn:uuid:db2a23dc-80e2-4ef8-b708-5d2ea7b5deb6",
		Types: []string{
			"VerifiableCredential",
			"VerifiableAttestation",
			"VerifiableEducationalID",
		},
		Issuer: "did:ebsi:zvHWX359A3CvfJnCYaAiAde",
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
				ID:   "https://api-test.ebsi.eu/trusted-schemas-registry/v3/schemas/0xff4f1fa4f0efd4306a218f669c7482d8cfcc7a13ba44f34af69f41889704002a",
				Type: "JsonSchema",
			},
		},
		Proofs: []vc.Proof{},
	}

	// Create the credential
	credential, err := vc.CreateCredentialWithContent(vcc)
	if err != nil {
		fmt.Printf("Failed to create credential: %v\n", err)
		return
	}

	// Initialize proof creator with ECDSA key
	privateKey := []byte{/* Your ECDSA private key bytes */}
	proofCreator := vc.NewProofCreator()
	proofCreator.AddProofType(&vc.ECDSADescriptor{}, &vc.ECDSASigner{PrivateKey: privateKey})

	// Add an embedded ECDSA proof
	err = credential.AddProof(
		proofCreator,
		"DataIntegrityProof",
		"did:ebsi:zvHWX359A3CvfJnCYaAiAde#ExHkBMW9fmbkvV266mRpuP2sUY_N_EWIN1lapUzO8ro",
		vc.KeyTypeECDSAP256,
		false,
		vc.WithDocumentLoader(ld.NewDefaultDocumentLoader(&http.Client{})),
		vc.WithRemoveAllInvalidRDF(),
		vc.WithAlgorithm("URDNA2015"),
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
	publicKey := []byte{/* Your ECDSA public key bytes */}
	verifier := vc.NewProofVerifier()
	verifier.AddVerifier(&vc.ECDSAVerifier{PublicKey: publicKey})
	err = verifier.Verify(
		credential,
		publicKey,
		vc.KeyTypeECDSAP256,
		vc.WithDocumentLoader(ld.NewDefaultDocumentLoader(&http.Client{})),
		vc.WithRemoveAllInvalidRDF(),
		vc.WithAlgorithm("URDNA2015"),
	)
	if err != nil {
		fmt.Printf("Failed to verify embedded ECDSA proof: %v\n", err)
		return
	}
	fmt.Println("Embedded ECDSA proof verified successfully")
}
```

### Steps Explained
1. **Define Credential Contents**: Create a `vc.CredentialContents` struct with required fields like context, ID, types, issuer, validity dates, subject, and schema.
2. **Create Credential**: Use `vc.CreateCredentialWithContent` to convert the contents into a `vc.Credential`.
3. **Add Proof**: Configure a `ProofCreator` with an ECDSA signer and add a proof using `credential.AddProof`.
4. **Serialize to JSON**: Use `credential.ToJSON` to serialize the credential for sharing or storage.
5. **Verify Proof**: Use a `ProofVerifier` with an ECDSA verifier to validate the proof.

## License
This package is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.