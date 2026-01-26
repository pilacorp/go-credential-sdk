# NDA DID SDK V2 (`didv2`)

**Official Go SDK for generating Decentralized Identifiers (DIDs) with capability-based authorization.**

This SDK allows you to:

- Generate **NDA-compliant DIDs** locally with capability-based authorization
- Create **DID Documents** with customizable metadata
- Use signer providers for flexible authentication
- Anchor DIDs on the **NDA Chain** via pre-signed transactions

- **Generate transactions** for existing key pairs or create new DIDs with auto-generated keys

---

## ✨ Key Features

- **Capability-based DID Generation**: Create DIDs with capability-based authorization for enhanced security
- **Signer Provider Support**: Flexible signer interface for different authentication mechanisms
- **Flexible Key Management**: Create new DIDs with auto-generated keys or use existing key pairs
- **Customizable DID Documents**: Attach structured metadata (name, type, etc.) to your DID
- **Pre-signed Transactions**: Generate blockchain-ready transactions for NDA Chain anchoring
- **Transaction Regeneration**: Re-create failed transactions without regenerating keys or DID
- **Epoch & Nonce Synchronization**: Automatic synchronization of capability epochs and transaction nonces

---

## 🚀 Installation

Add the SDK to your Go project:

```bash
go get github.com/pilacorp/go-credential-sdk/didv2

```

---

## Getting Started

The DID SDK V2 uses a capability-based signing model where a signer provider must sign a capability payload to authorize DID creation. This provides better security and control over DID issuance.

### Initialization

```go
import (
    "context"
    "log"

    "github.com/pilacorp/go-credential-sdk/didv2"
)

ctx := context.Background()

// Initialize DID Generator with default values
didGenerator, err := didv2.NewDIDGenerator()
if err != nil {
    log.Fatalf("Failed to initialize DID generator: %v", err)
}

// Or with custom configuration
didGenerator, err := didv2.NewDIDGenerator(
    didv2.WithRPC("https://rpc-testnet-new.pila.vn"),
    didv2.WithDIDChainID(704),
    didv2.WithDIDAddressSMC("0x75e7b09a24bCE5a921bABE27b62ec7bfE2230d6A"),
    didv2.WithMethod("did:nda"),
    // didv2.WithIssuerSignerProvider(issuerSigner), // Optional: Set a global issuer signer here
)
if err != nil {
    log.Fatalf("Failed to initialize DID generator: %v", err)
}

```

### Default Configuration

The SDK provides sensible defaults:

- **RPC**: `https://rpc-new.pila.vn`
- **ChainID**: `704`
- **DID Contract Address**: `0x75e7b09a24bce5a921babe27b62ec7bfe2230d6a`
- **Method**: `did:nda`

---

## 🆔 Creating DID Transactions

The SDK uses a **Generator** pattern. You can configure a **Global Issuer** (Signer Provider) when initializing the generator, or provide a **Custom Issuer** for specific transactions.

### Pattern 1: Global Issuer (Recommended)

_Use this when one account (e.g., an Admin or Organization) issues all DIDs. You inject the signer once during initialization._

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/pilacorp/go-credential-sdk/didv2"
    "github.com/pilacorp/go-credential-sdk/didv2/did"
    "github.com/pilacorp/go-credential-sdk/didv2/signer"
)

func main() {
    ctx := context.Background()

    // 1. Create the Global Issuer (Signer Provider)
    issuerPrivateKey := "0x..."
    signerProvider, err := signer.NewDefaultProvider(issuerPrivateKey)
    if err != nil {
        log.Fatalf("Failed to create signer provider: %v", err)
    }

    // 2. Initialize Generator with the Global Signer
    didGenerator, err := didv2.NewDIDGenerator(
        didv2.WithRPC("https://rpc-testnet-new.pila.vn"),
        didv2.WithDIDChainID(704),
        didv2.WithDIDAddressSMC("0x75e7b09a24bCE5a921bABE27b62ec7bfE2230d6A"),
        didv2.WithMethod("did:nda"),
        didv2.WithIssuerSignerProvider(signerProvider), // <--- Injected Globally
    )
    if err != nil {
        log.Fatalf("Failed to initialize DID generator: %v", err)
    }

    // 3. Generate DID (Issuer Signer is automatically used)
    generatedDID, err := didGenerator.GenerateDID(
        ctx,
        did.DIDTypePeople,
        "",
        map[string]interface{}{
            "name": "User 1",
            "type": "people",
        },
        // No need to pass issuer signer here (already set globally)
    )
    if err != nil {
        log.Fatalf("Failed to generate DID: %v", err)
    }

    fmt.Printf("Generated DID: %s\n", generatedDID.DID)
}

```

### Pattern 2: Custom / Override Issuer

_Use this when you need to switch issuers dynamically or didn't set a global one._

```go
func main() {
    ctx := context.Background()

    // 1. Initialize Generator (Without a global signer)
    didGenerator, _ := didv2.NewDIDGenerator()

    // 2. Create a Specific Issuer for this transaction
    specificIssuerKey := "0x..."
    customSigner, _ := signer.NewDefaultProvider(specificIssuerKey)

    // 3. Generate DID with Custom Issuer Signer Option
    generatedDID, err := didGenerator.GenerateDID(
        ctx,
        did.DIDTypeItem,
        "",
        map[string]interface{}{ "name": "Item A" },
        didv2.WithIssuerSignerProvider(customSigner), // <--- Injected Locally
    )
    if err != nil {
        log.Fatalf("Failed to generate DID: %v", err)
    }
}

```

---

## 📚 Usage Examples

The SDK supports two deployment models based on your architecture requirements:

### Model 1: Single-Service Issuance Flow

**Use Case**: One backend service holds both Issuer and DID keys.

**Characteristics**:
- Backend service acts as both Issuer and DID owner
- Backend holds Issuer private key and DID private key
- Suitable when system needs full control over DID lifecycle
- No need to separate DID ownership for end-users

**Example**: See `examples/single_service/main.go`

```go
package main

import (
    "context"
    "github.com/pilacorp/go-credential-sdk/didv2"
    "github.com/pilacorp/go-credential-sdk/didv2/did"
    "github.com/pilacorp/go-credential-sdk/didv2/signer"
)

func main() {
    ctx := context.Background()
    
    // 1. Initialize Issuer Signer
    issuerSigner, _ := signer.NewDefaultProvider("0x...") // Issuer private key
    
    // 2. Initialize DID Generator with Issuer Signer
    didGenerator, _ := didv2.NewDIDGenerator(
        didv2.WithIssuerSignerProvider(issuerSigner),
    )
    
    // 3. Generate DID (automatically creates key pair and transaction)
    result, _ := didGenerator.GenerateDID(
        ctx,
        did.DIDTypePeople,
        "",
        map[string]any{"name": "User 1"},
    )
    
    // 4. Use result.Transaction.TxHex to submit to blockchain
    fmt.Printf("DID: %s\n", result.DID)
    fmt.Printf("Transaction: %s\n", result.Transaction.TxHex)
}
```

### Model 2: Split Issuer / DID Owner Flow

**Use Case**: Issuer and DID owner are in separate environments.

**Characteristics**:
- Backend Issuer Service: Holds Issuer private key, creates Issuer Signature
- App/FE/Wallet: Holds DID private key, signs transaction
- Suitable when DID belongs to end-user control
- Separates trust boundary between Issuer and DID owner

**Example**: See `examples/single_service/main.go`

**Flow**:
1. Initialize Issuer Signer
2. Initialize DID Generator with Issuer Signer
3. Generate DID (automatically creates key pair and transaction)
4. Submit transaction to blockchain

### Model 2: Split Issuer / DID Owner Flow

**Use Case**: Issuer and DID owner are in separate environments.

**Characteristics**:
- Backend Issuer Service: Holds Issuer private key, creates Issuer Signature
- Wallet/App: Holds DID private key, generates key pair first, then signs transaction
- Suitable when DID belongs to end-user control
- Separates trust boundary between Issuer and DID owner

**Example**: See `examples/split_service/main.go`

**Flow**:

**Step 1-2: Wallet/App generates key pair and sends public key to Backend**
```go
// Wallet/App: Generate Key Pair
keyPair, _ := did.GenerateECDSAKeyPair()
didPublicKeyHex := keyPair.GetPublicKeyHex()
didPrivateKeyHex := keyPair.GetPrivateKeyHex() // Store securely

// Send public key to Backend API
// POST /api/v1/did/issue
// { "publicKey": didPublicKeyHex, "didType": did.DIDTypePeople }
```

**Step 3-8: Backend creates Issuer Signature and DID Document**
```go
// Backend: Receive DID public key from Wallet/App
didPublicKeyHex := "0x..." // From Wallet/App request

// Initialize DID Generator
didGenerator, _ := didv2.NewDIDGenerator(
    didv2.WithIssuerSignerProvider(issuerSigner),
)

// Generate Issuer Signature
issuerSig, _ := didGenerator.GenerateIssuerSignature(
    ctx,
    did.DIDTypePeople,
    didAddr,
    issuerAddr,
)

// Generate DID Document
didDoc := did.GenerateDIDDocument(didPublicKeyHex, didIdentifier, "", issuerDID, did.DIDTypePeople, metadata)
docHash, _ := didDoc.Hash()

// Return to Wallet/App: issuerSig, didDoc, docHash, capID
```

**Step 9-13: Wallet/App creates and signs transaction**
```go
// Wallet/App: Receive response from Backend
// issuerSig, didDoc, docHash, capID from Backend API

// Initialize DID Signer (using key pair from Step 1)
didSigner, _ := signer.NewDefaultProvider(didPrivateKeyHex)

// Initialize Contract Client
contractClient, _ := didcontract.NewContract(...)

// Create Transaction
createDIDReq := &didcontract.CreateDIDRequest{
    IssuerAddress: issuerAddr,
    IssuerSig:     issuerSig,
    DocHash:       docHash,
    DIDType:       did.DIDTypePeople,
    CapID:         capID,
    Nonce:         0, // Set manually or sync from blockchain
}

txResult, _ := contractClient.CreateDIDTx(ctx, createDIDReq, didSigner)

// Submit txResult.TxHex to blockchain
```

For complete working examples, see:
- `examples/single_service/main.go` - Single-service flow
- `examples/split_service/main.go` - Split issuer/DID owner flow

---

## Configuration Options

### Option Functions

```go
// Network configuration
didv2.WithRPC("https://rpc-testnet-new.pila.vn")
didv2.WithDIDChainID(704)
didv2.WithDIDAddressSMC("0x75e7b09a24bCE5a921bABE27b62ec7bfE2230d6A")
didv2.WithMethod("did:nda")

// Signer configuration
didv2.WithIssuerSignerProvider(issuerSigner)  // Issuer signer (for creating issuer signature)
didv2.WithDIDSignerProvider(didSigner)        // DID signer (for signing transaction)

// Capability configuration
didv2.WithEpoch(0)                    // Set capability epoch manually
didv2.WithSyncEpoch(true)             // Automatically sync epoch from blockchain (requires valid RPC URL)
didv2.WithCapID("0x...")              // Set capability ID manually

// Transaction configuration
didv2.WithSyncNonce(true)             // Automatically sync nonce from blockchain (requires valid RPC URL)

// Complete configuration object
didv2.WithDIDConfig(&didv2.DIDConfig{
    RPC:           "https://rpc-testnet-new.pila.vn",
    ChainID:       704,
    DIDSMCAddress: "0x75e7b09a24bCE5a921bABE27b62ec7bfE2230d6A",
    Method:        "did:nda",
    IssuerSigner: issuerSigner,
    DIDSigner:    didSigner,
    SyncEpoch:     true,  #require a valid, accessible RPC URL
    SyncNonce:     true,  #require a valid, accessible RPC URL
})

```

### Using Configuration Object

```go
config := &didv2.DIDConfig{
    RPC:           "https://rpc-testnet-new.pila.vn",
    ChainID:       704,
    DIDSMCAddress: "0x75e7b09a24bCE5a921bABE27b62ec7bfE2230d6A",
    Method:        "did:nda",
}

didGenerator, err := didv2.NewDIDGenerator(
    didv2.WithDIDConfig(config),
)

```

### ⚠️ Important Notes on SyncEpoch and SyncNonce

**When using `WithSyncEpoch(true)` or `WithSyncNonce(true)`:**

- **RPC URL must be valid and accessible**: These options require a working RPC connection to query the blockchain
- **If RPC is invalid or unavailable**: The SDK will fail when trying to sync epoch/nonce
- **Recommendation**: 
  - If you have a valid RPC URL: Use `WithSyncEpoch(true)` and `WithSyncNonce(true)` for automatic synchronization
  - If RPC is not available: Set `SyncEpoch: false` and `SyncNonce: false`, then manually set `Epoch` and `Nonce` values (default is 0)

**Example with manual epoch/nonce:**
```go
didGenerator, err := didv2.NewDIDGenerator(
    didv2.WithRPC("https://rpc-new.pila.vn"), // Valid RPC
    didv2.WithSyncEpoch(true),                 // Auto-sync epoch
    didv2.WithSyncNonce(true),                 // Auto-sync nonce
)
```

**Example without RPC (manual values):**
```go
didGenerator, err := didv2.NewDIDGenerator(
    // No RPC or invalid RPC
    didv2.WithEpoch(0),    // Set epoch manually (default: 0)
    didv2.WithSyncEpoch(false), // Disable auto-sync
    didv2.WithSyncNonce(false), // Disable auto-sync
    // Nonce will default to 0 if not set
)
```

---

## Signer Providers

The SDK uses a `SignerProvider` interface for signing capability payloads. You can implement your own signer or use the provided default implementation.

### SignerProvider Interface

```go
type SignerProvider interface {
    Sign(payload []byte) ([]byte, error)
    GetAddress() string
}

```

### Default Provider

```go
import "github.com/pilacorp/go-credential-sdk/didv2/signer"

// Create a default provider from a private key
signerProvider, err := signer.NewDefaultProvider("0x...") // private key hex
if err != nil {
    log.Fatalf("Failed to create signer: %v", err)
}

```

### Custom Signer Implementation

You can implement your own signer provider for different authentication mechanisms (e.g., HSM, hardware wallet, remote signing service):

```go
type CustomSigner struct {
    // Your signing mechanism
}

func (cs *CustomSigner) Sign(payload []byte) ([]byte, error) {
    // Implement your signing logic
    // Must return 65-byte signature: [v (1 byte)][r (32 bytes)][s (32 bytes)]
    signature := yourSigningFunction(payload)
    return signature, nil
}

func (cs *CustomSigner) GetAddress() string {
    // Return the Ethereum address of the signer
    return "0x..."
}

```

---

## DID Types

The SDK supports the following DID types:

- `did.DIDTypePeople` - For people/individuals
- `did.DIDTypeItem` - For items/products
- `did.DIDTypeLocation` - For locations
- `did.DIDTypeActivity` - For activities

---

## 📡 API Reference

### Core Functions

#### `NewDIDGenerator(options ...DIDOption) (*DIDGenerator, error)`

Creates a new DID generator instance with the provided configuration options.

#### `GenerateDID(ctx, didType, hash, metadata, options ...) (*DIDTxResult, error)`

Generates a new DID with an automatically generated key pair. Returns DID identifier, document, transaction, and secret (private key).

#### `GenerateDIDTX(ctx, didType, didPublicKeyHex, hash, metadata, options ...) (*DIDTxResult, error)`

Creates a transaction to register a DID from an existing public key. Use this when you already have a key pair.

#### `GenerateIssuerSignature(ctx, didType, didAddr, issuerAddr, options ...) (*issuer.Signature, error)`

Generates an issuer signature for a DID. Used in split issuer/DID owner flow.

#### `GenerateDIDCreateTransaction(ctx, didType, docHash, didAddr, issuerAddr, issuerSig, options ...) (*didcontract.Transaction, error)`

Generates a DID create transaction from issuer signature and document hash.

---

## 🔐 Security Best Practices

- **Store Private Keys Securely**: Use encrypted vaults, HSMs, or secure key management systems
- **Use Environment Variables**: Store sensitive configuration (RPC URLs, API keys) in environment variables
- **Never Commit Keys**: Never commit private keys or sensitive credentials to version control
- **Validate Metadata**: Always validate and sanitize metadata before submission
- **Use SyncEpoch and SyncNonce carefully**: Enable automatic synchronization only when you have a valid and accessible RPC URL. If RPC is invalid or unavailable, set these to `false` and use manual epoch/nonce values (default is 0)
- **Implement Custom Signers**: For production, implement custom signer providers that use secure key storage
- **Separate Issuer and DID Keys**: In split flow, ensure issuer keys and DID keys are stored in separate secure environments

---

## Error Handling

The SDK returns descriptive errors for common failure scenarios:

- Missing required configuration (RPC, contract address, issuer signer)
- Invalid key pair or signature format
- Blockchain transaction failures
- Network errors when syncing epoch/nonce
- Invalid public key format (compressed/uncompressed)

Always check and handle errors appropriately:

```go
generatedDID, err := didGenerator.GenerateDID(ctx, ...)
if err != nil {
    // Handle error appropriately
    log.Printf("Error: %v", err)
    return err
}
```

## 📝 Notes

- **SDK does not submit transactions**: The SDK only creates raw transactions (`TxHex`). You must submit them to the blockchain using:
  - Web3 client (`eth_sendRawTransaction`)
  - Custom API Backend
  - Blockchain explorer API

- **Transaction lifecycle**: The SDK does not manage transaction status (success/failure) on the blockchain. You need to track this separately.

- **Key pair generation**: In Model 2 (split flow), Wallet/App must generate the key pair first before calling Backend to get issuer signature.

- **SyncEpoch and SyncNonce require valid RPC**: 
  - `WithSyncEpoch(true)` and `WithSyncNonce(true)` require a valid, accessible RPC URL
  - If RPC is invalid or unavailable, these operations will fail
  - **Solution**: Set `SyncEpoch: false` and `SyncNonce: false`, then manually set `Epoch` and `Nonce` values (default is 0)
