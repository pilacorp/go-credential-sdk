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
-> verifier checks receipt locally
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
`Manager`:

```go
client := vcanchor.NewServiceClient(
	"https://authen.example.com",
	"did:pila:testnet:0xissuer",
	vcanchor.WithAuthorization("Bearer <accessible-credential>"),
)

_, err := manager.SubmitRoot(ctx, issuerDID, externalTreeID)
if err != nil {
	panic(err)
}
```

`SubmitRoot` must be called with an `Authorization` accessible credential when
using the Authen Service proxy. The proxy authenticates that credential and
derives `x-issuer-did` from the authenticated requester before forwarding the
request.

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

	// leaf_count must come from the anchored root record, not from the receipt.
	verified, err := vcanchor.VerifyReceiptLocal(*receipt, batch.LeafCount)
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
  "leaf_count": 4,
  "root": "0x...",
  "proof": ["0x..."],
  "tx_hash": "0x...",
  "hash_scheme": "keccak256-sorted-pairs-no-leaf-hash-v1"
}
```

`VerifyReceiptLocal` checks that `vc_hash + proof` reconstructs `root`, and that
the proof has exactly `ceil(log2(leaf_count))` siblings. The length check is not
cosmetic: this scheme feeds leaves into the tree unhashed, so an internal node is
indistinguishable from a leaf to the fold, and an internal node recomputed from any
published receipt would otherwise verify as a VC hash.

The `leaf_count` it measures against is the second argument, and it must come from
the anchored root record — on-chain, or from Authen Service. Passing
`receipt.LeafCount` defeats the check: the receipt is the thing under test, and a
sender who lowers its declared count to match a short proof would pass. The receipt's
own `leaf_count` is compared against the anchored one and a mismatch is rejected.

`SubmitRoot` is synchronous all the way through mining: Authen Service waits for the
transaction to be mined before it answers, up to 2 minutes, which is why the default
HTTP timeout sits above that. If a call does time out, the transaction usually still
lands and the service still records the root as anchored — call `SubmitRoot` again for
the same batch and it returns the anchored row, which marks the batch locally and
heals the receipt path.

Local verification stops there. The SDK no longer calls an Authen Service
verify-receipt API; applications that need server-side verification should use a
dedicated verifier flow outside `ServiceClient`.

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
