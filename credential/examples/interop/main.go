// Command interop issues a Verifiable Credential with this SDK and writes it to
// vc.json, so verify.mjs can check it with an independent implementation.
//
//	go run ./credential/examples/interop
//
// It signs with ecdsa-rdfc-2019 over P-256. That curve matters: Data Integrity
// ECDSA Cryptosuites v1.0 allows only P-256 and P-384, so the secp256k1 keys the
// SDK uses elsewhere cannot be verified by a conformant implementation.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// A fixed test key, so repeated runs stay comparable. Never reuse a published
// private key for anything real.
const privateKeyHex = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"

const outputFile = "vc.json"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	credential := jsonmap.JSONMap{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			// Terms for the claims below, inline so nothing has to be fetched.
			map[string]interface{}{
				"age":  "https://schema.org/age",
				"name": "https://schema.org/name",
			},
		},
		"id":        "urn:uuid:0f7c2d1e-3b4a-4c5d-8e9f-0a1b2c3d4e5f",
		"type":      []interface{}{"VerifiableCredential"},
		"issuer":    "did:example:issuer",
		"validFrom": "2024-01-01T00:00:00Z",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
			"age":  30,
		},
	}

	signerProvider, err := signer.NewP256ProviderFromHex(privateKeyHex)
	if err != nil {
		return fmt.Errorf("build signer: %w", err)
	}

	if err := credential.AddECDSAProof(
		signerProvider, "did:example:issuer#key-1", "assertionMethod"); err != nil {
		return fmt.Errorf("sign credential: %w", err)
	}

	// verify.mjs needs the public key to check the proof.
	publicKeyMultibase, err := verificationmethod.EncodePubMultibase(signerProvider.Public())
	if err != nil {
		return fmt.Errorf("encode public key: %w", err)
	}
	output, err := json.MarshalIndent(map[string]interface{}{
		"credential":         credential,
		"publicKeyMultibase": publicKeyMultibase,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode output: %w", err)
	}
	if err := os.WriteFile(outputFile, append(output, '\n'), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", outputFile, err)
	}

	fmt.Printf("wrote %s\n", outputFile)
	fmt.Println("verify it with: node credential/examples/interop/verify.mjs")
	return nil
}
