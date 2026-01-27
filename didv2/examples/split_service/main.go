package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/pilacorp/go-credential-sdk/didv2"
	"github.com/pilacorp/go-credential-sdk/didv2/did"
	"github.com/pilacorp/go-credential-sdk/didv2/didcontract"
	"github.com/pilacorp/go-credential-sdk/didv2/issuer"
	"github.com/pilacorp/go-credential-sdk/didv2/signer"
)

// Model 2: Split Issuer / DID Owner Flow
//
// In this model:
// - Issuer and DID owner are in separate environments
// - Responsibilities are clearly separated:
//   + Backend Issuer: Holds Issuer Signer, only creates Issuer Signature
//   + App/FE/Wallet: Holds DID Signer, signs transaction to create raw transaction
// - This model is suitable when:
//   + DID belongs to end-user control
//   + Need to separate trust boundary between Issuer and DID owner

func main() {
	ctx := context.Background()

	fmt.Println("=== Model 2: Split Issuer / DID Owner Flow ===")

	// ========================================
	// PART 1: WALLET/APP (DID OWNER) - Generate Key Pair
	// ========================================
	fmt.Println("\n=== PART 1: Wallet/App (DID Owner) ===")

	// STEP 1: Generate Key Pair (Wallet/App)
	fmt.Println("Step 1: Generate Key Pair (Wallet/App)...")

	// Wallet/App generates key pair locally
	keyPair, err := did.GenerateECDSAKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	didPublicKeyHex := keyPair.GetPublicKeyHex()
	didPrivateKeyHex := keyPair.GetPrivateKeyHex()
	didAddr := keyPair.GetAddress()

	fmt.Printf("DID Public Key: %s\n", didPublicKeyHex)
	fmt.Printf("DID Address: %s\n", didAddr)
	fmt.Printf("DID Private Key: %s (stored securely in wallet)\n", didPrivateKeyHex)
	fmt.Println("✓ Key pair generated")

	// STEP 2: Send Public Key to Backend (Wallet/App)
	fmt.Println("\nStep 2: Send Public Key to Backend (Wallet/App)...")
	fmt.Println("Calling Backend API: POST /api/v1/did/issue")
	fmt.Printf("Request: { publicKey: %s, didType: %d }\n", didPublicKeyHex, did.DIDTypePeople)
	fmt.Println("✓ Request sent to Backend")

	// ========================================
	// PART 2: BACKEND ISSUER SERVICE
	// ========================================
	fmt.Println("\n=== PART 2: Backend Issuer Service ===")

	// STEP 3: Initialize Issuer Signer (Backend)
	fmt.Println("Step 3: Initialize Issuer Signer (Backend)...")

	// Issuer private key (in production, retrieve from vault/HSM/secure storage)
	issuerPrivateKey := "0xdd6eef5f9579724bf2f66f42ffabfa4246f3313c04beb575dfe00b51cb13ff47"
	issuerSigner, err := signer.NewDefaultProvider(issuerPrivateKey)
	if err != nil {
		log.Fatalf("Failed to create issuer signer: %v", err)
	}

	issuerAddr := issuerSigner.GetAddress()
	fmt.Printf("Issuer Address: %s\n", issuerAddr)
	fmt.Println("✓ Issuer Signer initialized")

	// STEP 4: Initialize DID Generator (Backend)
	fmt.Println("Step 4: Initialize DID Generator (Backend)...")

	didGenerator, err := didv2.NewDIDGenerator(
		didv2.WithRPC("https://rpc-new.pila.vn"),
		didv2.WithDIDChainID(704),
		didv2.WithDIDAddressSMC("0x75e7b09a24bce5a921babe27b62ec7bfe2230d6a"),
		didv2.WithMethod("did:nda"),
		didv2.WithIssuerSignerProvider(issuerSigner),
	)
	if err != nil {
		log.Fatalf("Failed to initialize DID generator: %v", err)
	}

	fmt.Println("✓ DID Generator initialized")

	// STEP 5: Receive DID Public Key from Wallet/App (Backend)
	fmt.Println("Step 5: Receive DID Public Key from Wallet/App (Backend)...")
	fmt.Printf("Received DID Public Key: %s\n", didPublicKeyHex)
	fmt.Printf("Received DID Address: %s\n", didAddr)
	fmt.Println("✓ DID information received")

	// STEP 6: Create Issuer Signature (Backend)
	fmt.Println("Step 6: Create Issuer Signature (Backend)...")

	// Generate CapID (or can be set manually)
	capID, err := issuer.GenerateCapID()
	if err != nil {
		log.Fatalf("Failed to generate CapID: %v", err)
	}

	issuerSig, err := didGenerator.GenerateIssuerSignature(
		ctx,
		did.DIDTypePeople,
		didAddr,
		issuerAddr,
		didv2.WithCapID(capID), // Set CapID
	)
	if err != nil {
		log.Fatalf("Failed to generate issuer signature: %v", err)
	}

	fmt.Printf("Issuer Signature R: %s\n", issuerSig.R.String())
	fmt.Printf("Issuer Signature S: %s\n", issuerSig.S.String())
	fmt.Printf("Issuer Signature V: %s\n", issuerSig.V.String())
	fmt.Printf("CapID: %s\n", capID)
	fmt.Println("✓ Issuer Signature created")

	// STEP 7: Create DID Document (Backend)
	fmt.Println("Step 7: Create DID Document (Backend)...")

	metadata := map[string]any{
		"name":        "User 2",
		"email":       "user2@example.com",
		"description": "Example user for Model 2",
	}

	issuerDID := did.ToDID("did:nda", issuerAddr)
	didIdentifier := did.ToDID("did:nda", didAddr)

	didDoc := did.GenerateDIDDocument(didPublicKeyHex, didIdentifier, "", issuerDID, did.DIDTypePeople, metadata)
	docHash, err := didDoc.Hash()
	if err != nil {
		log.Fatalf("Failed to hash DID document: %v", err)
	}

	fmt.Printf("DID: %s\n", didIdentifier)
	fmt.Printf("Document Hash: %s\n", docHash)
	fmt.Println("✓ DID Document created")

	// STEP 8: Return Issuer Signature and DID Document to Wallet/App (Backend)
	fmt.Println("Step 8: Return Issuer Signature and DID Document to Wallet/App (Backend)...")

	issuerResponse := struct {
		IssuerSignature *issuer.Signature `json:"issuerSignature"`
		DIDDocument     *did.DIDDocument  `json:"didDocument"`
		DocHash         string            `json:"docHash"`
		IssuerAddress   string            `json:"issuerAddress"`
		CapID           string            `json:"capID"`
	}{
		IssuerSignature: issuerSig,
		DIDDocument:     didDoc,
		DocHash:         docHash,
		IssuerAddress:   issuerAddr,
		CapID:           capID,
	}

	responseJSON, _ := json.MarshalIndent(issuerResponse, "", "  ")
	fmt.Println("Response to Wallet/App:")
	fmt.Println(string(responseJSON))
	fmt.Println("=== End of Backend Service ===")

	// ========================================
	// PART 3: WALLET/APP (DID OWNER) - Create Transaction
	// ========================================
	fmt.Println("\n=== PART 3: Wallet/App (DID Owner) - Create Transaction ===")

	// STEP 9: Receive Response from Backend (Wallet/App)
	fmt.Println("Step 9: Receive Response from Backend (Wallet/App)...")
	fmt.Println("Received Issuer Signature, DID Document, DocHash, CapID")
	fmt.Println("✓ Response received from Backend")

	// STEP 10: Initialize DID Signer (Wallet/App)
	fmt.Println("Step 10: Initialize DID Signer (Wallet/App)...")

	// DID private key (already generated in Step 1, stored securely in wallet)
	didSigner, err := signer.NewDefaultProvider(didPrivateKeyHex)
	if err != nil {
		log.Fatalf("Failed to create DID signer: %v", err)
	}

	didSignerAddr := didSigner.GetAddress()
	fmt.Printf("DID Signer Address: %s\n", didSignerAddr)
	fmt.Println("✓ DID Signer initialized (using key pair from Step 1)")

	// STEP 11: Initialize DID Contract Client (Wallet/App)
	fmt.Println("Step 11: Initialize DID Contract Client (Wallet/App)...")

	contractClient, err := didcontract.NewContract(
		&didcontract.Config{
			RPCURL:          "https://rpc-new.pila.vn",
			ContractAddress: "0x75e7b09a24bce5a921babe27b62ec7bfe2230d6a",
			ChainID:         704,
		},
	)
	if err != nil {
		log.Fatalf("Failed to initialize contract client: %v", err)
	}

	fmt.Println("✓ Contract Client initialized")

	// STEP 12: Create Transaction (Wallet/App)
	fmt.Println("Step 13: Create Transaction (Wallet/App)...")

	// Create CreateDIDRequest from Issuer Signature and DID Document
	createDIDReq := &didcontract.CreateDIDRequest{
		IssuerAddress: issuerAddr,
		IssuerSig:     issuerSig,
		DocHash:       docHash,
		DIDType:       did.DIDTypePeople,
		CapID:         capID, // CapID from issuer response
		Nonce:         0,
	}

	// Create transaction with DID Signer
	txResult, err := contractClient.CreateDIDTx(ctx, createDIDReq, didSigner)
	if err != nil {
		log.Fatalf("Failed to create DID transaction: %v", err)
	}

	fmt.Printf("Transaction Hash: %s\n", txResult.TxHash)
	fmt.Printf("Transaction Hex: %s\n", txResult.TxHex)
	fmt.Println("✓ Transaction created")

	// ========================================
	// STEP 14: Display Final Results
	// ========================================
	fmt.Println("\n=== Final Results ===")
	fmt.Printf("DID: %s\n", didIdentifier)
	fmt.Printf("DID Address: %s\n", didAddr)
	fmt.Printf("Issuer Address: %s\n", issuerAddr)
	fmt.Printf("Transaction Hash: %s\n", txResult.TxHash)

	// Display DID Document
	fmt.Println("\n=== DID Document ===")
	docJSON, _ := json.MarshalIndent(didDoc, "", "  ")
	fmt.Println(string(docJSON))

	// ========================================
	// STEP 15: Submit Transaction to Blockchain
	// ========================================
	fmt.Println("\n=== Note ===")
	fmt.Println("SDK only creates raw transaction, does not submit to blockchain.")
	fmt.Println("Wallet/App needs to submit transaction.TxHex to blockchain using:")
	fmt.Println("  - Web3 client (eth_sendRawTransaction)")
	fmt.Println("  - Custom API BE")
}
