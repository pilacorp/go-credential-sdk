## How to Get the Package
To add the go-credential-sdk to your project, you can use the following go get command in your terminal:

```bash
go get github.com/pilacorp/go-credential-sdk/did
```
This will download the SDK, including the did package, and make it available for import in your project.

## ✨ Key Features
Based on the code, the did package provides the following core functionality:

- DID Generation: A did.NewDIDGenerator() function to initialize a generator.

- DID Customization: Ability to specify properties for the new DID using the did.CreateDID struct, including:

  + Type (e.g., did.TypePeople)

  + Hash

  + Metadata (using a map[string]interface{})

DID Document Creation: The GenerateDID method produces a full did.DIDDocument.

Blockchain Integration: The generation result also includes blockchain.SubmitTxResult, indicating it likely handles the necessary blockchain transaction for anchoring the DID.

Register DID: After generate DID, DID will be registered to a registry API. It Sends the DID Document to a registry API for public registration.
## 🚀 Example: Creating and Registering a DID

Here is the complete, runnable example flow for generating a new DID and registering it with an API.

This code performs two main actions:

Locally: Generates a new DID, key pair, and DID Document.

Remotely: Sends this new DID Document to a registry API to make it public.

```go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/pilacorp/go-credential-sdk/did"
	"github.com/pilacorp/go-credential-sdk/did/blockchain"
)

// NewDID defines the JSON payload structure for the registration API
type NewDID struct {
	IssuerDID   string                    `json:"issuer_did"`
	Document    did.DIDDocument           `json:"document"`
	Transaction blockchain.SubmitTxResult `json:"transaction"`
}

func main() {
	ctx := context.Background()

	// 1. Initialize the DID Generator
	didGenerator := did.NewDIDGenerator()

	// 2. Define the properties for the new DID
	createDID := did.CreateDID{
		Type: did.TypePeople,
		Hash: "", // Can be left empty
		Metadata: map[string]interface{}{
			"name": "User 1",
		},
	}

	// 3. Generate the DID
	// This step creates the private key, public key, and DID Document locally
	fmt.Println("Generating DID...")
	generatedDID, err := didGenerator.GenerateDID(ctx, createDID)
	if err != nil {
		log.Fatalf("Failed to generate DID: %v", err)
	}

	// Print the generated DID Document
	fmt.Println("\n=== Generated DID Document ===")
	didJSON, err := json.MarshalIndent(generatedDID.Document, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal DID: %v", err)
	}
	fmt.Println(string(didJSON))

	// IMPORTANT: 'generatedDID' contains the new DID's private key.
	// You will need this key to sign Verifiable Credentials as this new issuer.
	// Do NOT send the private key to the API.

	// 4. Send the new DID Document to the registry API
	fmt.Println("\n=== Sending DID to API Registry ===")
	apiURL := "https://api.ndadid.vn/api/v1/did/register"

	// This is the payload for the registration request.
	// Note: This API requires a pre-existing "IssuerDID" to authorize the registration.
	reqDID := NewDID{
		IssuerDID:   "did:nda:0x3fa4902238e3416886a68bc006c1f352d723e37a", // The DID authorized to register new DIDs
		Document:    generatedDID.Document,                                // The new DID Document
		Transaction: generatedDID.Transaction,                             // The associated blockchain transaction
	}

	// Marshal the payload to JSON
	requestBody, err := json.Marshal(reqDID)
	if err != nil {
		log.Fatalf("Failed to marshal DID for API request: %v", err)
	}

	// 5. Create and send the HTTP POST request
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(requestBody))
	if err != nil {
		log.Fatalf("Failed to create HTTP request: %v", err)
	}

	apiKey := "xxxxxxxxx" // <-- Replace with your actual API key

	// Set required headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("accept", "application/json")
	req.Header.Set("x-api-key", apiKey)

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to send API request: %v", err)
	}
	defer resp.Body.Close()

	// 6. Read and print the API response
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read API response: %v", err)
	}

	fmt.Printf("API Response Status: %s\n", resp.Status)
	fmt.Printf("API Response Body:\n%s\n", string(responseBody))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Println("\n✓ DID successfully submitted to API")
	} else {
		log.Fatalf("API request failed with status %d", resp.StatusCode)
	}
}

```