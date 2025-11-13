# NDA DID SDK (`nda-did`)

**Official Go SDK for generating Decentralized Identifiers (DIDs) locally.**

This SDK allows you to:
- Generate **NDA-compliant DIDs** locally with full control over keys.
  - Create **DID Documents** with customizable metadata.
  - Anchor DIDs on the **NDA Chain** via pre-signed transactions.
- **Re-generate failed registration transactions** without losing the DID or keys.

---

## ✨ Key Features

- Local DID Generation - Create DIDs with private/public key pairs and full DID Document
  - Customizable DID Document: Attach structured data (name, type, etc.) to your DID.
  - Pre-signed Transactions: Generate blockchain-ready transactions for NDA Chain anchoring.
- Transaction Regeneration: Re-create failed `SubmitDIDTX` without regenerating keys or DID.
---

## 🚀 Installation

Add the SDK to your Go project:

```bash
go get github.com/pilacorp/go-credential-sdk/did
```
##  Example: Creating and Registering a DID

Here is the complete, runnable example flow for generating a new DID and registering it with an API.

This code performs two main actions:

Locally: Generates a new DID, key pair, and DID Document.

Remotely: Sends this new DID Document to a registry API to make it public.
### Core model

```go
type DIDType string

const (
    TypeItem     DIDType = "item"
    TypePeople   DIDType = "people"
    TypeLocation DIDType = "location"
    TypeDefault  DIDType = "default"
)

type CreateDID struct {
    Type     DIDType                `json:"type"`
    Metadata map[string]interface{} `json:"metadata"`
    Hash     string                 `json:"hash,omitempty"`
}

type DIDDocument struct {
    Context            []string               `json:"@context"`
    Id                 string                 `json:"id"`
    Controller         string                 `json:"controller"`
    VerificationMethod []VerificationMethod   `json:"verificationMethod"`
    Authentication     []string               `json:"authentication"`
    AssertionMethod    []string               `json:"assertionMethod"`
    DocumentMetadata   map[string]interface{} `json:"didDocumentMetadata"`
}
```
Example

For creating a DID, you can follow these steps:
- Step 1: Init package → Using NewDIDGenerator with optional config
- Step 2: Generate DID → Using GenerateDID(...)
- Step 3: Register DID → Call API via sendDIDToAPI

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

  // --- Assumed Imports ---
  "github.com/pilacorp/go-credential-sdk/did"
  "github.com/pilacorp/go-credential-sdk/did/blockchain"
  "github.com/pilacorp/go-credential-sdk/did/config"
)

// NewDID represents the payload sent to the DID registration API
type NewDID struct {
  IssuerDID   string                 `json:"issuer_did"`
  Document    did.DIDDocument        `json:"document"`
  Transaction blockchain.SubmitDIDTX `json:"transaction"`
}

func main() {
  ctx := context.Background()

  // ========================================
  // STEP 1: Init Package with Configuration
  // ========================================
  fmt.Println("Step 1: Initializing DID Generator with config...")
  didGenerator := did.NewDIDGenerator(
    did.WithConfig(config.Config{
      RPC:        "https://rpc-testnet.pila.vn",
      ChainID:    6789,
      DIDAddress: "0x0000000000000000000000000000000000018888",
      Method:     "did:pila",
    }),
  )
  fmt.Println("DID Generator initialized successfully.\n")

  // ========================================
  // STEP 2: Generate DID
  // ========================================
  fmt.Println("Step 2: Generating new DID...")
  createDID := did.CreateDID{
    Type: did.TypePeople,
    Hash: "",
    Metadata: map[string]interface{}{
      "name": "User 1",
    },
  }

  generatedDID, err := didGenerator.GenerateDID(ctx, createDID)
  if err != nil {
    log.Fatalf("Failed to generate DID: %v", err)
  }

  fmt.Println("DID generated successfully!")
  didJSON, _ := json.MarshalIndent(generatedDID, "", "  ")
  fmt.Println(string(didJSON))

  // ========================================
  // STEP 3: Register DID via API
  // ========================================
  fmt.Println("\nStep 3: Preparing and submitting DID to registry API...")

  // Re-generate transaction using private key and metadata
  newTx, err := didGenerator.ReGenerateDIDTX(ctx, generatedDID.Secret.PrivateKeyHex, generatedDID.Document.DocumentMetadata)
  if err != nil {
    log.Fatalf("Failed to re-generate DID transaction: %v", err)
  }

  reqDID := NewDID{
    IssuerDID:   "did:nda:testnet:0x3fa4902238e3416886a68bc006c1f352d723e37a", // Replace your Issuer DID
    Document:    generatedDID.Document,
    Transaction: *newTx,
  }

  apiURL := "https://auth-dev.pila.vn/api/v1/did/register"
  apiKey := "YOUR_API_KEY"

  responseBody, err := sendDIDToAPI(ctx, apiURL, apiKey, reqDID)
  if err != nil {
    log.Fatalf("API request failed: %v", err)
  }

  fmt.Printf("API Response:\n%s\n", responseBody)
  fmt.Println("\nDID successfully registered on the blockchain!")
}

// sendDIDToAPI sends the DID registration request to the remote API
func sendDIDToAPI(
        ctx context.Context,
        apiURL string,
        apiKey string,
        reqDID NewDID,
) (string, error) {

  client := &http.Client{}

  requestBody, err := json.Marshal(reqDID)
  if err != nil {
    return "", fmt.Errorf("failed to marshal request body: %w", err)
  }

  req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(requestBody))
  if err != nil {
    return "", fmt.Errorf("failed to create HTTP request: %w", err)
  }

  req.Header.Set("Content-Type", "application/json")
  req.Header.Set("accept", "application/json")
  req.Header.Set("x-api-key", apiKey)

  resp, err := client.Do(req)
  if err != nil {
    return "", fmt.Errorf("failed to send request: %w", err)
  }
  defer resp.Body.Close()

  responseBodyBytes, err := io.ReadAll(resp.Body)
  if err != nil {
    return "", fmt.Errorf("failed to read response body: %w", err)
  }

  responseBodyString := string(responseBodyBytes)
  fmt.Printf("API Status: %s\n", resp.Status)

  if resp.StatusCode < 200 || resp.StatusCode >= 300 {
    return "", fmt.Errorf("API error %d: %s", resp.StatusCode, responseBodyString)
  }

  return responseBodyString, nil
}
```
## Regenerating TX when First Transaction was Failed
Use Case: If the original blockchain transaction fails (e.g., due to network issues, low gas, or timeout), you can recreate the transaction using the original private key and metadata — without changing the DID or keys.

Note: when use ReGenerateDIDTX, make sure correct RPC Config in package
```go
func (d *DIDGenerator) ReGenerateDIDTX(
    ctx context.Context,
    privKey string,
    didMetadata map[string]interface{},
) (*blockchain.SubmitDIDTX, error)
```

## 📡 API Reference

Endpoint - Method - Purpose

`POST /api/v1/did/registerRegister new DIDRequires x-api-key and authorized issuer_did`

## 🔐 Security Best Practices

- Store PrivateKeyHex securely (e.g., encrypted vault, HSM).
- Use environment variables for API keys.
- Never commit keys to version control.
- Validate all metadata before submission.