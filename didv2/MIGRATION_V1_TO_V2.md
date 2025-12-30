## Thay đổi thư viện go-credential-sdk trong cách tạo DID transaction

- Vẫn giữ did version 1.
- Bổ sung did generator version 2 để tạo transaction để tạo did tx mới
- Input khi tạo DID sẽ truyền thêm signer
- Output: không thay đổi

## Cách tạo DID Generator V2

```go
ctx := context.Background()

// Khởi tạo DIDGeneratorV2
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
```

## Cách tạo Tạo DID Tx Version 2

Có 2 hàm để tạo DID transaction:
- `GenerateDID`: Tạo DID mới với key pair được tự động tạo
- `ReGenerateDID`: Tạo transaction cho DID đã có sẵn key pair

### Example 1: GenerateDID - Tạo DID mới với key pair mới

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

    // 1. Init did generator
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
    generatedDID, err := didGeneratorV2.GenerateDID(
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

### Example 2: ReGenerateDID - Tạo transaction cho DID đã có key pair

```go
package main

import (
    "context"
    "crypto/ecdsa"
    "fmt"
    "log"
    "strings"

    "github.com/ethereum/go-ethereum/crypto"
    "github.com/pilacorp/go-credential-sdk/did"
    "github.com/pilacorp/go-credential-sdk/did/blockchain"
    "github.com/pilacorp/go-credential-sdk/did/signer"
)

func main() {
    ctx := context.Background()

    // 1. Init did generator
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

    keyPair := &did.KeyPair{
        Address:    address,
        PublicKey:  publicKeyHex,
        PrivateKey: privateKeyHex,
        Identifier: identifier,
    }

    // 4. Dùng generator để gọi hàm ReGenerateDID với KeyPair đã có
    generatedDID, err := didGeneratorV2.ReGenerateDID(
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

## Cách tạo Issuer Tx

Dùng để tạo transaction để thêm issuer mới với các quyền (permissions) tạo DID cụ thể.

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

    // 1. Khởi tạo IssuerGenerator
    issuerGenerator, err := did.NewIssuerGenerator(
        did.WithIssuerConfig(&did.IssuerConfig{
            ChainID:    704,
            DIDAddress: "0x75e7b09a24bCE5a921bABE27b62ec7bfE2230d6A",
            RPCURL:     "https://rpc-testnet-new.pila.vn",
        }),
    )
    if err != nil {
        log.Fatalf("Failed to initialize issuer generator: %v", err)
    }

    // 2. Tạo signer (thường là admin signer để có quyền thêm issuer)
    adminSigner, err := signer.NewAdminSigner(
        "https://admin-api.example.com/sign",
        "your-admin-token",
    )
    if err != nil {
        log.Fatalf("Failed to create admin signer: %v", err)
    }

    // 3. Tạo transaction để thêm issuer
    // signerAddress: địa chỉ của người có quyền admin (để ký transaction)
    // issuerAddress: địa chỉ của issuer mới cần thêm
    // permissions: danh sách các loại DID mà issuer được phép tạo
    signerAddress := "0x..." // Address của admin
    issuerAddress := "0x..." // Address của issuer mới
    permissions := []blockchain.DIDType{
        blockchain.DIDTypePeople,
        blockchain.DIDTypeItem,
        // blockchain.DIDTypeLocation,
        // blockchain.DIDTypeActivity,
    }

    txResult, err := issuerGenerator.AddIssuerTx(
        ctx,
        adminSigner,      // Signer để ký transaction
        signerAddress,    // Address của admin
        issuerAddress,    // Address của issuer mới
        permissions,      // Quyền được phép tạo loại DID nào
    )
    if err != nil {
        log.Fatalf("Failed to create add issuer transaction: %v", err)
    }

    fmt.Printf("Transaction Hash: %s\n", txResult.TxHash)
    fmt.Printf("Transaction Hex: %s\n", txResult.TxHex)

    // 4. Submit transaction lên L2 để thêm issuer
}
```

## Cách sử dụng Signer

| Loại Signer | Cách tạo | Header được set | Khi nào sử dụng |
|-------------|----------|-----------------|-----------------|
| **L2 Admin Signer** | `signer.NewAdminSigner(endpoint, adminToken)` | `Authorization: Bearer {adminToken}` | Khi có admin token và cần quyền admin để tạo DID |
| **L2 Issuer Signer** | `signer.NewIssuerSigner(endpoint, apiKey)` | `x-api-key: {apiKey}` | Khi có issuer API key để tạo DID |
| **Local Signer** | `signer.NewDefaultSigner(privateKeyHex)` | Không có (ký local) | Khi có private key trực tiếp, dùng cho development hoặc local signing |

### Ví dụ tạo signer

```go
import "github.com/pilacorp/go-credential-sdk/did/signer"

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
```