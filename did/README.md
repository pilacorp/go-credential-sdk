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

---

## 🆕 DID Contract V2

**New version of DID contract with enhanced capabilities and signing requirements.**

The V2 contract introduces a capability-based signing model where a signer (issuer) must sign a capability payload to authorize DID creation. This provides better security and control over DID issuance.

### Key Differences from V1

- **Capability-based Authorization**: Requires a signer (issuer) to sign a capability payload before creating a DID
- **Dual Signing**: Both the issuer (capability signer) and the DID keypair (transaction signer) are involved
- **Epoch Support**: Optional capability epoch for managing authorization lifecycle
- **Enhanced Security**: More granular control over who can issue DIDs

### Core Model V2

```go
type ConfigV2 struct {
    RPC        string
    ChainID    int64
    DIDAddress string
    Method     string
    Epoch      uint64  // Optional: capability epoch (default: 0)
    CapID      string  // Auto-generated random hex if not provided
}

type Signer interface {
    Sign(payload []byte) ([]byte, error)
}
```

### Initialization V2

```go
import (
    "github.com/pilacorp/go-credential-sdk/did"
    "github.com/pilacorp/go-credential-sdk/did/signer"
)

// Initialize V2 DID Generator
didGeneratorV2, err := did.NewDIDGeneratorV2(
    did.WithConfigV2(&did.ConfigV2{
        ChainID:    704,
        DIDAddress: "0x75e7b09a24bCE5a921bABE27b62ec7bfE2230d6A",
        Method:     "did:nda",
        RPC:        "https://rpc-testnet-new.pila.vn",
        Epoch:      0, // Optional: set capability epoch
    }),
)
if err != nil {
    log.Fatalf("Failed to initialize DID generator V2: %v", err)
}
```

### GenerateDID V2 Function

```go
func (d *DIDGeneratorV2) GenerateDID(
    ctx context.Context,
    sigSigner signer.Signer,    // Signs the capability payload (issuer's signer)
    signerDID string,            // Issuer DID (e.g., "did:nda:0x...")
    didType blockchain.DIDType,  // DID type (People, Item, Location, Activity)
    hash string,                 // Optional hash
    metadata map[string]interface{}, // DID metadata
    options ...OptionV2,         // Optional: override config per call
) (*DID, error)
```

**Parameters:**
- `sigSigner`: Implements `signer.Signer` interface - signs the capability payload (typically the issuer's private key)
- `signerDID`: Full DID string of the issuer/authorizer (e.g., `"did:nda:0x3fa4902238e3416886a68bc006c1f352d723e37a"`)
- `didType`: Type of DID being created (`blockchain.DIDTypePeople`, `DIDTypeItem`, `DIDTypeLocation`, `DIDTypeActivity`)
- `hash`: Optional hash string
- `metadata`: Map of metadata to attach to the DID document
- `options`: Optional V2 config overrides (e.g., `did.WithEpochV2(epoch)`)

**Returns:**
- `*DID`: Contains the generated DID, private key, document, and transaction

### Example 1: Using Vault Signer (Recommended for Production)

This example shows how to use a vault-based signer for secure key management:

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/pilacorp/go-credential-sdk/did"
    "github.com/pilacorp/go-credential-sdk/did/blockchain"
    "github.com/pilacorp/go-credential-sdk/did/signer"
)

// vaultSigner implements signer.Signer interface using vault
type vaultSigner struct {
    vault   *Vault // Your vault implementation
    ctx     context.Context
    address string // Issuer address
}

func (vs *vaultSigner) Sign(hashPayload []byte) ([]byte, error) {
    // Sign using vault - returns ECDSA signature (65 bytes: v, r, s)
    return vs.vault.SignMessage(vs.ctx, hashPayload, vs.address)
}

func main() {
    ctx := context.Background()

    // Step 1: Initialize V2 DID Generator
    didGeneratorV2, err := did.NewDIDGeneratorV2(
        did.WithConfigV2(&did.ConfigV2{
            ChainID:    704,
            DIDAddress: "0x75e7b09a24bCE5a921bABE27b62ec7bfE2230d6A",
            Method:     "did:nda",
            RPC:        "https://rpc-testnet-new.pila.vn",
        }),
    )
    if err != nil {
        log.Fatalf("Failed to initialize DID generator: %v", err)
    }

    // Step 2: Create vault signer for issuer
    issuerDID := "did:nda:0x3fa4902238e3416886a68bc006c1f352d723e37a"
    issuerAddress := "0x3fa4902238e3416886a68bc006c1f352d723e37a" // Extract from issuerDID
    
    vaultSigner := &vaultSigner{
        vault:   yourVaultInstance,
        ctx:     ctx,
        address: issuerAddress,
    }

    // Step 3: Generate DID with V2
    generatedDID, err := didGeneratorV2.GenerateDID(
        ctx,
        vaultSigner,                    // Issuer's signer (signs capability)
        issuerDID,                      // Issuer DID
        blockchain.DIDTypePeople,       // DID type
        "",                             // Hash (optional)
        map[string]interface{}{        // Metadata
            "name": "User 1",
            "type": "people",
        },
    )
    if err != nil {
        log.Fatalf("Failed to generate DID: %v", err)
    }

    fmt.Printf("Generated DID: %s\n", generatedDID.DID)
    fmt.Printf("Private Key: %s\n", generatedDID.Secret.PrivateKeyHex)
    fmt.Printf("Transaction Hash: %s\n", generatedDID.Transaction.TxHash)
}
```

### Example 2: Using Default Signer (For Testing/Development)

This example shows how to use a default signer with a private key directly:

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/pilacorp/go-credential-sdk/did"
    "github.com/pilacorp/go-credential-sdk/did/blockchain"
    "github.com/pilacorp/go-credential-sdk/did/signer"
)

func main() {
    ctx := context.Background()

    // Step 1: Initialize V2 DID Generator
    didGeneratorV2, err := did.NewDIDGeneratorV2(
        did.WithConfigV2(&did.ConfigV2{
            ChainID:    704,
            DIDAddress: "0x75e7b09a24bCE5a921bABE27b62ec7bfE2230d6A",
            Method:     "did:nda",
            RPC:        "https://rpc-testnet-new.pila.vn",
        }),
    )
    if err != nil {
        log.Fatalf("Failed to initialize DID generator: %v", err)
    }

    // Step 2: Create default signer from issuer's private key
    issuerPrivateKey := "0x..." // Issuer's private key
    adminSigner, err := signer.NewDefaultSigner(issuerPrivateKey)
    if err != nil {
        log.Fatalf("Failed to create signer: %v", err)
    }

    // Step 3: Generate DID
    issuerDID := "did:nda:0x3fa4902238e3416886a68bc006c1f352d723e37a"
    generatedDID, err := didGeneratorV2.GenerateDID(
        ctx,
        adminSigner,                   // Issuer's signer
        issuerDID,                     // Issuer DID
        blockchain.DIDTypePeople,      // DID type
        "",                            // Hash
        map[string]interface{}{       // Metadata
            "type": "issuer",
        },
    )
    if err != nil {
        log.Fatalf("Failed to generate DID: %v", err)
    }

    fmt.Printf("Generated DID: %s\n", generatedDID.DID)
}
```

### Example 3: Using Capability Epoch

If you need to manage capability epochs, you can retrieve and set them:

```go
// Get current capability epoch for a signer
capabilityEpoch, err := didGeneratorV2.GetCapabilityEpoch(ctx, issuerAddress)
if err != nil {
    log.Fatalf("Failed to get capability epoch: %v", err)
}

// Generate DID with specific epoch
generatedDID, err := didGeneratorV2.GenerateDID(
    ctx,
    vaultSigner,
    issuerDID,
    blockchain.DIDTypePeople,
    "",
    metadata,
    did.WithEpochV2(capabilityEpoch), // Override epoch
)
```

### GetCapabilityEpoch

Retrieve the current capability epoch for a signer address:

```go
func (d *DIDGeneratorV2) GetCapabilityEpoch(
    ctx context.Context,
    signerAddress string, // Issuer's address (without 0x prefix or with)
) (uint64, error)
```

**Usage:**
```go
issuerAddress := "0x3fa4902238e3416886a68bc006c1f352d723e37a"
epoch, err := didGeneratorV2.GetCapabilityEpoch(ctx, issuerAddress)
if err != nil {
    return fmt.Errorf("failed to get capability epoch: %w", err)
}
```

### Implementing Custom Signer

To use a custom signing mechanism (e.g., HSM, hardware wallet), implement the `signer.Signer` interface:

```go
type Signer interface {
    Sign(payload []byte) ([]byte, error)
}
```

The `Sign` method must:
- Accept a byte slice (the hash of the capability payload)
- Return a 65-byte ECDSA signature: `[v (1 byte)][r (32 bytes)][s (32 bytes)]`
- Handle errors appropriately

**Example Custom Signer:**
```go
type customSigner struct {
    // Your signing mechanism
}

func (cs *customSigner) Sign(hashPayload []byte) ([]byte, error) {
    // Implement your signing logic
    // Must return 65-byte signature: [v][r][s]
    signature := yourSigningFunction(hashPayload)
    return signature, nil
}
```

### Configuration Options V2

```go
// Individual options
did.WithRPCV2("https://rpc-testnet-new.pila.vn")
did.WithChainIDV2(704)
did.WithDIDAddressV2("0x75e7b09a24bCE5a921bABE27b62ec7bfE2230d6A")
did.WithMethodV2("did:nda")
did.WithEpochV2(0)

// Or use WithConfigV2 for all at once
did.WithConfigV2(&did.ConfigV2{
    RPC:        "https://rpc-testnet-new.pila.vn",
    ChainID:    704,
    DIDAddress: "0x75e7b09a24bCE5a921bABE27b62ec7bfE2230d6A",
    Method:     "did:nda",
    Epoch:      0,
})
```

### Default Values V2

- `RPC`: `"https://rpc-testnet-new.pila.vn"`
- `ChainID`: `704`
- `DIDAddress`: `"0x75e7b09a24bCE5a921bABE27b62ec7bfE2230d6A"`
- `Method`: `"did:nda"`
- `Epoch`: `0`
- `CapID`: Auto-generated random 32-byte hex string

---

## 📡 API Reference

Endpoint - Method - Purpose

`POST /api/v1/did/register` Register new DIDRequires x-api-key and authorized issuer_did

## 🔐 Security Best Practices

- Store PrivateKeyHex securely (e.g., encrypted vault, HSM).
- Use environment variables for API keys.
- Never commit keys to version control.
- Validate all metadata before submission.