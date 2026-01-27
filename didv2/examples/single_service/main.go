// Package main demonstrates Model 1: Single-Service Issuance Flow.
//
// This example shows how to use the DID V2 SDK when a single backend service
// acts as both the Issuer and the DID owner. The backend holds both the Issuer's
// private key and the DID's private key, allowing it to control the entire DID
// lifecycle in one place.
//
// This model is suitable when:
//   - The system needs full control over DID lifecycle
//   - There is no need to separate DID ownership for end-users
//   - All DID operations are managed centrally
//
// The example demonstrates:
//  1. Initializing an Issuer Signer
//  2. Creating a DID Generator with the Issuer Signer
//  3. Generating a DID (automatically creates key pair and transaction)
//  4. Displaying the results
//  5. Instructions for submitting the transaction to the blockchain
//
// For complete documentation, see:
// https://github.com/pilacorp/go-credential-sdk/tree/main/didv2
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/pilacorp/go-credential-sdk/didv2"
	"github.com/pilacorp/go-credential-sdk/didv2/did"
	"github.com/pilacorp/go-credential-sdk/didv2/signer"
)

// main demonstrates the complete workflow for Model 1: Single-Service Issuance Flow.
//
// This example shows a backend service that:
//   - Holds the Issuer's private key
//   - Automatically generates DID key pairs
//   - Creates issuer signatures
//   - Builds and signs transactions
//   - Returns the complete DID issuance result including the private key
//
// In production, ensure private keys are stored securely (vault, HSM, etc.)
// and never exposed in logs or error messages.
func main() {
	ctx := context.Background()

	// ========================================
	// STEP 1: Initialize Issuer Signer
	// ========================================
	fmt.Println("=== Model 1: Single-Service Issuance Flow ===")
	fmt.Println("Step 1: Initialize Issuer Signer...")

	issuerPrivateKey := "0xdd6eef5f9579724bf2f66f42ffabfa4246f3313c04beb575dfe00b51cb13ff47"
	issuerSigner, err := signer.NewDefaultProvider(issuerPrivateKey)
	if err != nil {
		log.Fatalf("Failed to create issuer signer: %v", err)
	}

	issuerAddr := issuerSigner.GetAddress()
	fmt.Printf("Issuer Address: %s\n", issuerAddr)
	fmt.Println("✓ Issuer Signer initialized")

	// ========================================
	// STEP 2: Initialize DID Generator with Issuer Signer
	// ========================================
	fmt.Println("Step 2: Initialize DID Generator...")

	didGenerator, err := didv2.NewDIDGenerator(
		didv2.WithRPC("https://rpc-testnet-new.pila.vn"),
		didv2.WithDIDChainID(704),
		didv2.WithDIDAddressSMC("0x75e7b09a24bce5a921babe27b62ec7bfe2230d6a"),
		didv2.WithMethod("did:nda:testnet"),
		didv2.WithIssuerSignerProvider(issuerSigner), // Inject Issuer Signer
	)
	if err != nil {
		log.Fatalf("Failed to initialize DID generator: %v", err)
	}

	fmt.Println("✓ DID Generator initialized")

	// ========================================
	// STEP 3: Generate DID (automatically creates key pair and transaction)
	// ========================================
	fmt.Println("Step 3: Generate DID...")

	// Metadata for DID
	metadata := map[string]any{
		"name":        "User 1",
		"email":       "user1@example.com",
		"description": "Example user for Model 1",
	}

	// Generate DID with DIDType People
	didResult, err := didGenerator.GenerateDID(
		ctx,
		did.DIDTypePeople,
		"", // hash (optional)
		metadata,
	)
	if err != nil {
		log.Fatalf("Failed to generate DID: %v", err)
	}

	fmt.Printf("✓ DID Generated Successfully!\n\n")

	// ========================================
	// STEP 4: Display Results
	// ========================================
	fmt.Println("=== Results ===")
	fmt.Printf("DID: %s\n", didResult.DID)
	fmt.Printf("DID Address: %s\n", didResult.Document.Id)
	fmt.Printf("Issuer DID: %s\n", didResult.Document.Controller)
	fmt.Printf("Private Key (DID): %s\n", didResult.Secret.PrivateKeyHex)
	fmt.Printf("Transaction Hash: %s\n", didResult.Transaction.TxHash)
	fmt.Printf("Transaction Hex: %s\n", didResult.Transaction.TxHex)

	// Display DID Document
	fmt.Println("=== DID Document ===")
	docJSON, _ := json.MarshalIndent(didResult.Document, "", "  ")
	fmt.Println(string(docJSON))

	// ========================================
	// STEP 5: Submit Transaction to Blockchain
	// ========================================
	fmt.Println("=== Note ===")
	fmt.Println("SDK only creates raw transaction, does not submit to blockchain.")
	fmt.Println("You need to submit transaction.TxHex to blockchain using:")
	fmt.Println("  - Web3 client (eth_sendRawTransaction)")
	fmt.Println("  - Custom API BE")
}
