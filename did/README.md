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

type NewDID struct {
  IssuerDID   string                    `json:"issuer_did"`
  Document    did.DIDDocument           `json:"document"`
  Transaction blockchain.SubmitTxResult `json:"transaction"`
}

func main() {
  ctx := context.Background()
  didGenerator := did.NewDIDGenerator()

  // Step 1: Define DID properties
  createDID := did.CreateDID{
    Type: did.TypePeople,
    Metadata: map[string]interface{}{
      "name": "Alice Johnson",
    },
  }

  // Step 2: Generate DID + Transaction
  fmt.Println("Generating DID and pre-signed transaction...")
  generated, err := didGenerator.GenerateDID(ctx, createDID)
  if err != nil {
    log.Fatalf("DID generation failed: %v", err)
  }

  fmt.Printf("DID: %s\n", generated.Document.Id)
  fmt.Printf("Private Key (save securely!): %s\n", generated.Secret.PrivateKeyHex)

  // Step 3: Submit to NDA DID Registry
  apiURL := "https://api.ndadid.vn/api/v1/did/register"
  payload := NewDID{
    IssuerDID:   "did:nda:0x3fa4902238e3416886a68bc006c1f352d723e37a", // Authorized issuer
    Document:    generated.Document,
    Transaction: generated.Transaction,
  }

  body, _ := json.Marshal(payload)
  req, _ := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(body))
  req.Header.Set("Content-Type", "application/json")
  req.Header.Set("x-api-key", "YOUR_API_KEY_HERE")

  client := &http.Client{}
  resp, err := client.Do(req)
  if err != nil {
    log.Fatalf("API request failed: %v", err)
  }
  defer resp.Body.Close()

  respBody, _ := io.ReadAll(resp.Body)
  fmt.Printf("Status: %s\nResponse: %s\n", resp.Status, string(respBody))

  if resp.StatusCode >= 200 && resp.StatusCode < 300 {
    fmt.Println("DID registered successfully!")
  }
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