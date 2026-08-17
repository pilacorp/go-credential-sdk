# VC Anchor

`vcanchor` helps applications build their own Merkle tree for VC hashes, submit
the root to Authen Service for on-chain anchoring, and issue receipts that prove
one VC hash belongs to an anchored root.

The package intentionally hides the Merkle details from integrators. The hash
scheme is fixed:

```text
keccak256-sorted-pairs-no-leaf-hash-v1
```

Rules:

- each leaf is the raw 32-byte `vc_hash`
- leaf hashing is disabled
- parent nodes are `keccak256(sort(left, right))`
- odd rightmost nodes are paired with themselves
- receipts contain sibling hashes as `0x`-prefixed 32-byte hex strings

## Flow

```text
application creates VC
-> application computes vc_hash
-> SDK builds Merkle batch
-> application submits root to Authen Service
-> Authen Service anchors root on-chain and returns tx_hash
-> SDK generates receipt for each VC hash
-> holder keeps VC + receipt
-> verifier checks receipt locally or through Authen Service
```

## Recommended usage

Production integrations should use `Manager` with a persistent `Store`. This
prevents the common failure where the application builds a root in memory,
submits it, then loses the ordered leaf list before it can issue receipts.

```go
// Implement vcanchor.Store in your application using your database or object
// storage. The SDK intentionally does not ship a storage backend.
store := yourapp.NewVCAnchorStore(db)
client := vcanchor.NewServiceClient(
	"https://authen.example.com",
	"did:pila:testnet:0xissuer",
	vcanchor.WithAuthorization("Bearer <accessible-credential>"),
)
manager := vcanchor.NewManager(store, client)

batch, err := manager.CreateBatch(ctx, vcanchor.BatchInput{
	IssuerDID:      "did:pila:testnet:0xissuer",
	ExternalTreeID: "app-tree-001",
	VCHashes:       hashes,
})
if err != nil {
	panic(err)
}

// Submits the persisted root and marks the stored batch anchored when tx_hash
// is returned by Authen Service.
_, err = manager.SubmitRoot(ctx, batch.IssuerDID, batch.ExternalTreeID)
if err != nil {
	panic(err)
}

receipt, err := manager.GenerateReceipt(ctx, batch.IssuerDID, batch.ExternalTreeID, hashes[0])
if err != nil {
	panic(err)
}
```

The manager can also validate local storage at startup or on a schedule:

```go
err := manager.ValidateStoredBatch(ctx, "did:pila:testnet:0xissuer", "app-tree-001")
```

## Authen Service client

`ServiceClient` implements `RootSubmitter`, so it can be passed directly to
`Manager`. It also submits receipts to the single Authen Service verify
endpoint:

```go
client := vcanchor.NewServiceClient(
	"https://authen.example.com",
	"did:pila:testnet:0xissuer",
	vcanchor.WithAuthorization("Bearer <accessible-credential>"),
)

receipt, err := manager.GenerateReceipt(ctx, issuerDID, externalTreeID, vcHash)
if err != nil {
	panic(err)
}

// Authen Service checks its verified cache first. If the VC hash is not cached,
// it verifies this full receipt proof and stores the verified result.
verified, err := client.VerifyReceipt(ctx, *receipt)
if err != nil {
	panic(err)
}
_ = verified
```

`SubmitRoot` must be called with an `Authorization` accessible credential when
using the Authen Service proxy. The proxy authenticates that credential and
derives `x-issuer-did` from the authenticated requester before forwarding the
request. `VerifyReceipt` sends `issuer_did` in the JSON body because the verify
endpoint is public/read-style.

## Low-level usage

```go
package main

import (
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/vcanchor"
)

func main() {
	hashes := []string{
		"0x0000000000000000000000000000000000000000000000000000000000000001",
		"0x0000000000000000000000000000000000000000000000000000000000000002",
	}

	batch, err := vcanchor.BuildBatch(vcanchor.BatchInput{
		IssuerDID:      "did:pila:testnet:0xissuer",
		ExternalTreeID: "app-tree-001",
		VCHashes:       hashes,
	})
	if err != nil {
		panic(err)
	}

	// Send this payload to Authen Service SubmitExternalMerkleRoot.
	rootReq := batch.RootRequest()
	fmt.Println(rootReq.Root)

	// Use the tx_hash returned by Authen Service after root anchoring.
	receipt, err := batch.Receipt(hashes[0], "0xtxhash")
	if err != nil {
		panic(err)
	}

	verified, err := vcanchor.VerifyReceiptLocal(*receipt)
	if err != nil {
		panic(err)
	}
	fmt.Println(verified)
}
```

## Receipt

```json
{
  "issuer_did": "did:pila:testnet:0xissuer",
  "external_tree_id": "app-tree-001",
  "vc_hash": "0x...",
  "leaf_index": 0,
  "root": "0x...",
  "proof": ["0x..."],
  "tx_hash": "0x...",
  "hash_scheme": "keccak256-sorted-pairs-no-leaf-hash-v1"
}
```

`VerifyReceiptLocal` only checks that `vc_hash + proof` reconstructs `root`.
Authen Service must still check that the root exists, belongs to the issuer and
external tree, and was anchored on-chain by the recorded transaction.

## Storage responsibility

For external-managed anchoring, Authen Service does not store all leaves. The
integrating application must preserve enough data to regenerate receipts:

- `ordered_vc_hashes`
- `vc_hash -> leaf_index` can be derived from the ordered list
- `root`
- `leaf_count`
- `hash_scheme`
- `leaves_digest`
- `tx_hash` after anchoring

Implement `Store` on top of your own database or object storage. Do not hard
delete anchored batches unless every holder already has a receipt and your
retention policy accepts that trade-off. The SDK does not provide memory or file
stores because those choices are application-specific persistence concerns.
