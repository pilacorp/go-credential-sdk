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
)
if err != nil {
    log.Fatalf("Failed to initialize DID generator: %v", err)
}
```

### Default Configuration

The SDK provides sensible defaults:
- **RPC**: `https://rpc-testnet-new.pila.vn`
- **ChainID**: `704`
- **DID Contract Address**: `0x75e7b09a24bCE5a921bABE27b62ec7bfE2230d6A`
- **Method**: `did:nda`

---

## Creating DID Transactions

There are 2 main functions to create DID transactions:

1. **`GenerateDID`**: Creates a new DID with automatically generated key pair
2. **`GenerateDIDTX`**: Creates a transaction for a DID that already has a key pair

### Example 1: GenerateDID - Create New DID with New Key Pair

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/pilacorp/go-credential-sdk/didv2"
    "github.com/pilacorp/go-credential-sdk/didv2/blockchain"
    "github.com/pilacorp/go-credential-sdk/didv2/signer"
)

func main() {
    ctx := context.Background()

    // 1. Initialize DID Generator
    didGenerator, err := didv2.NewDIDGenerator(
        didv2.WithRPC("https://rpc-testnet-new.pila.vn"),
        didv2.WithDIDChainID(704),
        didv2.WithDIDAddressSMC("0x75e7b09a24bCE5a921bABE27b62ec7bfE2230d6A"),
        didv2.WithMethod("did:nda"),
    )
    if err != nil {
        log.Fatalf("Failed to initialize DID generator: %v", err)
    }

    // 2. Create signer provider (issuer who authorizes DID creation)
    issuerPrivateKey := "0x..." // Private key of the issuer
    signerProvider, err := signer.NewDefaultProvider(issuerPrivateKey)
    if err != nil {
        log.Fatalf("Failed to create signer provider: %v", err)
    }

    // 3. Generate DID with auto-generated key pair
    generatedDID, err := didGenerator.GenerateDID(
        ctx,
        blockchain.DIDTypePeople, // DID type (People, Item, Location, Activity)
        "",                       // Hash (optional)
        map[string]interface{}{  // Metadata
            "name": "User 1",
            "type": "people",
        },
        didv2.WithSignerProvider(signerProvider),
        didv2.WithSyncEpoch(true),  // Automatically sync capability epoch
        didv2.WithSyncNonce(true),  // Automatically sync transaction nonce
    )
    if err != nil {
        log.Fatalf("Failed to generate DID: %v", err)
    }

    fmt.Printf("Generated DID: %s\n", generatedDID.DID)
    fmt.Printf("Private Key: %s\n", generatedDID.Secret.PrivateKeyHex)
    fmt.Printf("Transaction Hash: %s\n", generatedDID.Transaction.TxHash)
    fmt.Printf("Transaction Hex: %s\n", generatedDID.Transaction.TxHex)

    // 4. Submit transaction to blockchain to register DID
}
```

### Example 2: GenerateDIDTX - Create Transaction for Existing Key Pair

```go
package main

import (
    "context"
    "crypto/ecdsa"
    "fmt"
    "log"
    "strings"

    "github.com/ethereum/go-ethereum/crypto"
    "github.com/pilacorp/go-credential-sdk/didv2"
    "github.com/pilacorp/go-credential-sdk/didv2/blockchain"
    "github.com/pilacorp/go-credential-sdk/didv2/signer"
)

func main() {
    ctx := context.Background()

    // 1. Initialize DID Generator
    didGenerator, err := didv2.NewDIDGenerator(
        didv2.WithRPC("https://rpc-testnet-new.pila.vn"),
        didv2.WithDIDChainID(704),
        didv2.WithDIDAddressSMC("0x75e7b09a24bCE5a921bABE27b62ec7bfE2230d6A"),
        didv2.WithMethod("did:nda"),
    )
    if err != nil {
        log.Fatalf("Failed to initialize DID generator: %v", err)
    }

    // 2. Create signer provider (issuer)
    issuerPrivateKey := "0x..." // Private key of the issuer
    signerProvider, err := signer.NewDefaultProvider(issuerPrivateKey)
    if err != nil {
        log.Fatalf("Failed to create signer provider: %v", err)
    }

    // 3. Create KeyPair from existing private key
    existingPrivateKeyHex := "0x..." // Private key of the DID to create transaction for
    
    privKey, err := crypto.HexToECDSA(strings.TrimPrefix(existingPrivateKeyHex, "0x"))
    if err != nil {
        log.Fatalf("Failed to parse private key: %v", err)
    }

    publicKeyECDSA := privKey.Public().(*ecdsa.PublicKey)
    address := strings.ToLower(crypto.PubkeyToAddress(*publicKeyECDSA).Hex())
    privateKeyHex := strings.ToLower("0x" + fmt.Sprintf("%x", crypto.FromECDSA(privKey)))
    publicKeyHex := strings.ToLower("0x" + fmt.Sprintf("%x", crypto.CompressPubkey(publicKeyECDSA)))
    identifier := strings.ToLower(fmt.Sprintf("did:nda:%s", address))

    keyPair := &didv2.KeyPair{
        Address:    address,
        PublicKey:  publicKeyHex,
        PrivateKey: privateKeyHex,
        Identifier: identifier,
    }

    // 4. Generate transaction for existing key pair
    generatedDID, err := didGenerator.GenerateDIDTX(
        ctx,
        blockchain.DIDTypePeople, // DID type
        keyPair,                  // Existing key pair
        "",                       // Hash (optional)
        map[string]interface{}{  // Metadata
            "name": "User 1",
            "type": "people",
        },
        didv2.WithSignerProvider(signerProvider),
        didv2.WithSyncEpoch(true),
        didv2.WithSyncNonce(true),
    )
    if err != nil {
        log.Fatalf("Failed to generate DID transaction: %v", err)
    }

    fmt.Printf("DID: %s\n", generatedDID.DID)
    fmt.Printf("Transaction Hash: %s\n", generatedDID.Transaction.TxHash)
    fmt.Printf("Transaction Hex: %s\n", generatedDID.Transaction.TxHex)

    // 5. Submit transaction to blockchain to register DID
}
```

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
didv2.WithSignerProvider(signerProvider)

// Capability configuration
didv2.WithEpoch(0)                    // Set capability epoch manually
didv2.WithSyncEpoch(true)             // Automatically sync epoch from blockchain
didv2.WithCapID("0x...")              // Set capability ID manually

// Transaction configuration
didv2.WithSyncNonce(true)             // Automatically sync nonce from blockchain

// Complete configuration object
didv2.WithDIDConfig(&didv2.DIDConfig{
    RPC:           "https://rpc-testnet-new.pila.vn",
    ChainID:       704,
    DIDSMCAddress: "0x75e7b09a24bCE5a921bABE27b62ec7bfE2230d6A",
    Method:        "did:nda",
    SignerProvider: signerProvider,
    SyncEpoch:     true,
    SyncNonce:     true,
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

- `blockchain.DIDTypePeople` - For people/individuals
- `blockchain.DIDTypeItem` - For items/products
- `blockchain.DIDTypeLocation` - For locations
- `blockchain.DIDTypeActivity` - For activities

---

## 📡 API Reference

### Core Functions

#### `NewDIDGenerator(options ...DIDOption) (*DIDGenerator, error)`
Creates a new DID generator instance with the provided configuration options.

#### `GenerateDID(ctx, didType, hash, metadata, options ...) (*DID, error)`
Generates a new DID with an automatically generated key pair.

#### `GenerateDIDTX(ctx, didType, keyPair, hash, metadata, options ...) (*DID, error)`
Generates a transaction for an existing key pair.

---

## 🔐 Security Best Practices

- **Store Private Keys Securely**: Use encrypted vaults, HSMs, or secure key management systems
- **Use Environment Variables**: Store sensitive configuration (RPC URLs, API keys) in environment variables
- **Never Commit Keys**: Never commit private keys or sensitive credentials to version control
- **Validate Metadata**: Always validate and sanitize metadata before submission
- **Use SyncEpoch and SyncNonce**: Enable automatic synchronization to prevent transaction failures
- **Implement Custom Signers**: For production, implement custom signer providers that use secure key storage

---

## Error Handling

The SDK returns descriptive errors for common failure scenarios:

- Missing required configuration (RPC, contract address)
- Invalid key pair or signature format
- Blockchain transaction failures
- Network errors when syncing epoch/nonce

Always check and handle errors appropriately:

```go
generatedDID, err := didGenerator.GenerateDID(ctx, ...)
if err != nil {
    // Handle error appropriately
    log.Printf("Error: %v", err)
    return err
}
```
