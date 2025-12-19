# NDA DID SDK v2 (`didv2`)

**Official Go SDK for generating Decentralized Identifiers (DIDs) locally.**

This SDK allows you to:

- Generate **NDA-compliant DIDs** locally with full control over keys.
  - Create **DID Documents** with customizable metadata.
  - Anchor DIDs on the **NDA Chain** via pre-signed transactions.
- **Re-generate failed registration transactions** without losing the DID or keys.

---

## ✨ Key Features

- **Local DID Generation** - Create DIDs with private/public key pairs and full DID Document
  - Customizable DID Document: Attach structured data (name, type, etc.) to your DID.
  - Pre-signed Transactions: Generate blockchain-ready transactions for NDA Chain anchoring.
- **Transaction Regeneration**: Re-create failed transactions without regenerating keys or DID.

---

## 🚀 Installation

Add the SDK to your Go project:

```bash
go get github.com/pilacorp/go-credential-sdk/didv2
```

---

## 📖 Example: Creating and Registering a DID

Here is the complete, runnable example flow for generating a new DID and registering it with an API.

This code performs two main actions:

1. **Locally**: Generates a new DID, key pair, and DID Document.
2. **Remotely**: Sends this new DID Document to a registry API to make it public.

### Core Models

```go
type CreateDID struct {
    IssuerAddress string                 `json:"issuerAddress"`
    IssuerPkHex   string                 `json:"issuerPrivateKeyHex"`
    Type          blockchain.DIDType     `json:"type"`
    Metadata      map[string]interface{} `json:"metadata"`
    Hash          string                 `json:"hash"`
    Deadline      uint                   `json:"deadline"`
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

type DID struct {
    DID         string                     `json:"did"`
    Secret      Secret                     `json:"secret"`
    Document    *DIDDocument               `json:"document"`
    Transaction *blockchain.SubmitTxResult `json:"transaction"`
}
```

### Complete Example

For creating a DID, you can follow these steps:
- **Step 1**: Init package → Using `NewDIDGenerator` with optional config
- **Step 2**: Generate DID → Using `GenerateDID(...)`
- **Step 3**: Register DID → Call API with the generated DID and transaction

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
  "time"

  "github.com/pilacorp/go-credential-sdk/didv2"
  "github.com/pilacorp/go-credential-sdk/didv2/blockchain"
  "github.com/pilacorp/go-credential-sdk/didv2/config"
)

// NewDID represents the payload sent to the DID registration API
type NewDID struct {
  IssuerDID   string                      `json:"issuer_did"`
  Document    *didv2.DIDDocument          `json:"document"`
  Transaction *blockchain.SubmitTxResult  `json:"transaction"`
}

func main() {
  ctx := context.Background()

  // ========================================
  // STEP 1: Init Package with Configuration
  // ========================================
  fmt.Println("Step 1: Initializing DID Generator with config...")
  didGenerator := didv2.NewDIDGenerator(
    didv2.WithConfig(config.Config{
      ChainID:    6789,
      DIDAddress: "0x0000000000000000000000000000000000018888",
      Method:     "did:nda",
    }),
  )
  fmt.Println("DID Generator initialized successfully.\n")

  // ========================================
  // STEP 2: Generate DID
  // ========================================
  fmt.Println("Step 2: Generating new DID...")
  
  // Calculate deadline (e.g., 1 hour from now)
  deadline := uint(time.Now().Add(1 * time.Hour).Unix())
  
  createDID := didv2.CreateDID{
    IssuerAddress: "0x3fa4902238e3416886a68bc006c1f352d723e37a", // Your Issuer Address
    IssuerPkHex:   "0xYOUR_ISSUER_PRIVATE_KEY_HEX",              // Your Issuer Private Key
    Type:          blockchain.DIDTypePeople,
    Hash:          "0x1111111111111111111111111111111111111111111111111111111111111111",
    Deadline:      deadline,
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

  reqDID := NewDID{
    IssuerDID:   "did:nda:testnet:0x3fa4902238e3416886a68bc006c1f352d723e37a", // Your Issuer DID
    Document:    generatedDID.Document,
    Transaction: generatedDID.Transaction,
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

---

## 🔄 Regenerating Transactions

**Use Case**: If the original blockchain transaction fails (e.g., due to network issues, low gas, or timeout), you can recreate the transaction using the original private key and metadata — without changing the DID or keys.

**Note**: When using `ReGenerateDIDTx`, make sure the correct config is set in the package.

```go
// Calculate new deadline
deadline := uint(time.Now().Add(1 * time.Hour).Unix())

regenerateReq := didv2.ReGenerateDIDRxRequest{
    IssuerAddress: "0x3fa4902238e3416886a68bc006c1f352d723e37a",
    IssuerPkHex:   "0xYOUR_ISSUER_PRIVATE_KEY_HEX",
    DIDPkHex:      generatedDID.Secret.PrivateKeyHex, // Use the DID's private key
    Type:          blockchain.DIDTypePeople,
    Hash:          "0x1111111111111111111111111111111111111111111111111111111111111111",
    Deadline:      deadline,
    Metadata: map[string]interface{}{
        "name": "User 1",
    },
}

txResult, err := didGenerator.ReGenerateDIDTx(ctx, regenerateReq)
if err != nil {
    log.Fatalf("Failed to re-generate DID transaction: %v", err)
}

// Use txResult.TxHex to submit the transaction
fmt.Printf("Transaction Hex: %s\n", txResult.TxHex)
fmt.Printf("Transaction Hash: %s\n", txResult.TxHash)
```

### Function Signature

```go
func (d *DIDGenerator) ReGenerateDIDTx(
    ctx context.Context,
    req ReGenerateDIDRxRequest,
) (*blockchain.SubmitTxResult, error)
```

---

## 📡 API Reference

### Configuration

```go
type Config struct {
    ChainID    int64  // Chain ID (default: 6789)
    DIDAddress string // Contract address (default: "0x0000000000000000000000000000000000018888")
    Method     string // DID method (default: "did:nda")
}
```

### DID Types

```go
const (
    DIDTypePeople   DIDType = 0
    DIDTypeItem     DIDType = 1
    DIDTypeActivity DIDType = 3
    DIDTypeLocation DIDType = 4
)
```

### Main Functions

- `NewDIDGenerator(options ...Option) *DIDGenerator` - Creates a new DID generator instance
- `GenerateDID(ctx context.Context, req CreateDID) (*DID, error)` - Generates a new DID with a new key pair
- `ReGenerateDIDTx(ctx context.Context, req ReGenerateDIDRxRequest) (*blockchain.SubmitTxResult, error)` - Regenerates a transaction for an existing DID

### Registration API Endpoint

- **Endpoint**: `POST /api/v1/did/register`
- **Purpose**: Register new DID
- **Requirements**: Requires `x-api-key` header and authorized `issuer_did`

---

## 🔐 Security Best Practices

- **Store PrivateKeyHex securely** (e.g., encrypted vault, HSM).
- **Use environment variables** for API keys and sensitive configuration.
- **Never commit keys** to version control.
- **Validate all metadata** before submission.
- **Set appropriate deadlines** for signatures to prevent replay attacks.
- **Keep issuer private keys** separate from DID private keys.

---

## 📝 Notes

- The SDK generates transactions but **does not send them** to the blockchain. You must submit the `TxHex` via your own infrastructure or API.
- All private keys should be hex-encoded strings (with or without `0x` prefix).
- The `Deadline` field is a Unix timestamp representing when the signature expires.
- The `Hash` field represents the DID document hash that will be anchored on-chain.
