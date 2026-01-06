# NDA DID SDK (`nda-did`)

**Official Go SDK for generating Decentralized Identifiers (DIDs) locally.**

This SDK allows you to:
- Generate **NDA-compliant DIDs** locally with capability-based authorization
  - Create **DID Documents** with customizable metadata
  - Use multiple signer types (Admin, Issuer, Local) for flexible authentication
  - Anchor DIDs on the **NDA Chain** via pre-signed transactions
- **Re-generate failed registration transactions** without losing the DID or keys

---

## ✨ Key Features

- **Capability-based DID Generation**: Create DIDs with capability-based authorization for enhanced security
- **Multiple Signer Support**: Support for Admin Signer, Issuer Signer, and Local Signer
- **Flexible Key Management**: Create new DIDs with auto-generated keys or use existing key pairs
- **Customizable DID Documents**: Attach structured metadata (name, type, etc.) to your DID
- **Pre-signed Transactions**: Generate blockchain-ready transactions for NDA Chain anchoring
- **Transaction Regeneration**: Re-create failed transactions without regenerating keys or DID
---

## 🚀 Installation

Add the SDK to your Go project:

```bash
go get github.com/pilacorp/go-credential-sdk/didv2
```

---

## Getting Started

The DID SDK uses a capability-based signing model where a signer (issuer) must sign a capability payload to authorize DID creation. This provides better security and control over DID issuance.

### Initialization

```go
import (
    "context"
    "log"

    "github.com/pilacorp/go-credential-sdk/didv2"
)

ctx := context.Background()

// Initialize DID Generator
didGenerator, err := didv2.NewDIDGenerator(
    didv2.WithConfig(&didv2.Config{
        ChainID:    704,
        DIDAddress: "0x75e7b09a24bCE5a921bABE27b62ec7bfE2230d6A",
        Method:     "did:nda",
        RPC:        "https://rpc-testnet-new.pila.vn",
    }),
)
if err != nil {
    log.Fatalf("Failed to initialize DID generator: %v", err)
}
```

### Creating DID Transactions

There are 2 functions to create DID transactions:
- `GenerateDID`: Creates a new DID with automatically generated key pair
- `ReGenerateDID`: Creates a transaction for a DID that already has a key pair

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

    // 1. Init did generator
    didGenerator, err := didv2.NewDIDGenerator(
        didv2.WithConfig(&didv2.Config{
            ChainID:    704,
            DIDAddress: "0x75e7b09a24bCE5a921bABE27b62ec7bfE2230d6A",
            Method:     "did:nda",
            RPC:        "https://rpc-testnet-new.pila.vn",
        }),
    )
    if err != nil {
        log.Fatalf("Failed to initialize DID generator: %v", err)
    }

    // 2. Config signer (có 3 loại: Local Signer, L2 Admin Signer, L2 Issuer Signer)

    // Option 1: L2 Remote Signer (sử dụng remote API để ký)
    sigSigner, err := signer.NewRemoteSigner(
        "https://api.example.com/sign", // Endpoint của remote signer
        "your-api-key",                 // API key nếu cần
    )
    if err != nil {
        log.Fatalf("Failed to create remote signer: %v", err)
    }

    // Option 2: Local Signer (sử dụng private key trực tiếp)
    // issuerPrivateKey := "0x..." // Private key của issuer (signer)
    // sigSigner, err := signer.NewDefaultSigner(issuerPrivateKey)
    // if err != nil {
    //     log.Fatalf("Failed to create signer: %v", err)
    // }

    // DID của issuer (người có quyền tạo DID mới)
    issuerDID := "did:nda:0x3fa4902238e3416886a68bc006c1f352d723e37a"

    // 3. Dùng generator để gọi hàm GenerateDID (tự động tạo key pair mới)
    generatedDID, err := didGenerator.GenerateDID(
        ctx,
        sigSigner,                      // Signer để ký capability payload
        issuerDID,                      // DID của issuer
        blockchain.DIDTypePeople,       // Loại DID (People, Item, Location, Activity)
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
    fmt.Printf("Transaction Hex: %s\n", generatedDID.Transaction.TxHex)

    // 4. Call register DID trên L2 để đăng ký did
}
```

### Example 2: ReGenerateDID - Create Transaction for DID with Existing Key Pair

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

    // 1. Init did generator
    didGenerator, err := didv2.NewDIDGenerator(
        didv2.WithConfig(&didv2.Config{
            ChainID:    704,
            DIDAddress: "0x75e7b09a24bCE5a921bABE27b62ec7bfE2230d6A",
            Method:     "did:nda",
            RPC:        "https://rpc-testnet-new.pila.vn",
        }),
    )
    if err != nil {
        log.Fatalf("Failed to initialize DID generator: %v", err)
    }

    // 2. Config signer
    issuerPrivateKey := "0x..." // Private key của issuer (signer)
    sigSigner, err := signer.NewDefaultSigner(issuerPrivateKey)
    if err != nil {
        log.Fatalf("Failed to create signer: %v", err)
    }

    issuerDID := "did:nda:0x3fa4902238e3416886a68bc006c1f352d723e37a"

    // 3. Tạo KeyPair từ private key đã có sẵn
    existingPrivateKeyHex := "0x..." // Private key của DID cần tạo transaction
    
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

    // 4. Dùng generator để gọi hàm ReGenerateDID với KeyPair đã có
    generatedDID, err := didGenerator.ReGenerateDID(
        ctx,
        sigSigner,                      // Signer để ký capability payload
        issuerDID,                      // DID của issuer
        blockchain.DIDTypePeople,       // Loại DID
        keyPair,                        // KeyPair đã có sẵn
        "",                             // Hash (optional)
        map[string]interface{}{        // Metadata
            "name": "User 1",
            "type": "people",
        },
    )
    if err != nil {
        log.Fatalf("Failed to regenerate DID: %v", err)
    }

    fmt.Printf("DID: %s\n", generatedDID.DID)
    fmt.Printf("Transaction Hash: %s\n", generatedDID.Transaction.TxHash)
    fmt.Printf("Transaction Hex: %s\n", generatedDID.Transaction.TxHex)

    // 5. Call register DID trên L2 để đăng ký did
}
```

## Using Signers

There are 3 types of signers available:

| Loại Signer | Cách tạo | Header được set | Khi nào sử dụng |
|-------------|----------|-----------------|-----------------|
| **L2 Admin Signer** | `signer.NewAdminSigner(endpoint, adminToken)` | `Authorization: Bearer {adminToken}` | Khi có admin token và cần quyền admin để tạo DID |
| **L2 Issuer Signer** | `signer.NewIssuerSigner(endpoint, apiKey)` | `x-api-key: {apiKey}` | Khi có issuer API key để tạo DID |
| **Local Signer** | `signer.NewDefaultSigner(privateKeyHex)` | Không có (ký local) | Khi có private key trực tiếp, dùng cho development hoặc local signing |

### Example: Creating Signers

```go
import "github.com/pilacorp/go-credential-sdk/didv2/signer"

// L2 Admin Signer
adminSigner, err := signer.NewAdminSigner(
    "https://admin-api.example.com/sign",
    "your-admin-token",
)

// L2 Issuer Signer
issuerSigner, err := signer.NewIssuerSigner(
    "https://issuer-api.example.com/sign",
    "your-api-key",
)

// Local Signer
localSigner, err := signer.NewDefaultSigner("0x...") // private key hex

// Remote Signer (generic remote API signer)
remoteSigner, err := signer.NewRemoteSigner(
    "https://api.example.com/sign",
    "your-api-key",
)
```

---

## 📡 API Reference

Endpoint - Method - Purpose

`POST /api/v1/did/register` Register new DIDRequires x-api-key and authorized issuer_did

## 🔐 Security Best Practices

- Store PrivateKeyHex securely (e.g., encrypted vault, HSM).
- Use environment variables for API keys.
- Never commit keys to version control.
- Validate all metadata before submission.