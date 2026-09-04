# VC Anchor

`vcanchor` helps applications build their own Merkle tree for VC hashes, keep it, and
issue receipts that prove one VC hash belongs to an anchored root.

The anchoring call itself is not in here. Handing a root to Authen Service is an
internal-service concern, so the application makes that call with its own client and
reports the resulting transaction back through `MarkAnchored`. Everything this package
does — building trees, storing them, generating receipts, verifying them — is local and
needs no network.

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
-> application submits {root, leaf_count} to Authen Service (its own client)
-> Authen Service anchors root on-chain asynchronously
-> application polls its own call, then reports tx_hash via MarkAnchored
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
manager := vcanchor.NewManager(store)

batch, err := manager.CreateBatch(ctx, vcanchor.BatchInput{
	IssuerDID:      "did:pila:testnet:0xissuer",
	ExternalTreeID: "app-tree-001",
	VCHashes:       hashes,
})
if err != nil {
	panic(err)
}

// Hand the root to Authen Service with your own client. The submission is
// {root, leaf_count}; the issuer comes from the credential you authenticate
// with. Anchoring is asynchronous, so the first answer is "pending" with an
// empty tx_hash.
txHash, err := yourapp.AnchorRoot(ctx, batch.Root, batch.LeafCount)
if err != nil {
	panic(err)
}
if txHash == "" {
	// not anchored yet — poll your own call again later
	return
}

// Reporting the transaction is what unlocks receipts. Only pass a hash the
// service reported as anchored: a hash from a broadcast whose confirmation
// failed would produce receipts pointing at a transaction that anchored nothing.
if err := manager.MarkAnchored(ctx, batch.IssuerDID, batch.ExternalTreeID, txHash); err != nil {
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

	// Send this payload to Authen Service with your own client: the root and the
	// number of leaves it commits to, and nothing else.
	fmt.Println(batch.Root, batch.LeafCount)

	// Use the tx_hash returned by Authen Service after root anchoring.
	receipt, err := batch.Receipt(hashes[0], "0xtxhash")
	if err != nil {
		panic(err)
	}

	// A verifier holds only the receipt. Both the root and the leaf_count it checks
	// against must come from the anchored record — read on chain by tx_hash, or from
	// what Authen Service reported — never from the batch or receipt under test. Shown
	// here as anchoredRoot/anchoredLeafCount, which this issuing-side example
	// happens to know.
	anchoredRoot, anchoredLeafCount := batch.Root, batch.LeafCount

	verified, err := vcanchor.VerifyReceiptLocal(*receipt, anchoredRoot, anchoredLeafCount)
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

`VerifyReceiptLocal` checks that `vc_hash + proof` folds to the **anchored** root,
and that the proof has exactly `ceil(log2(leaf_count))` siblings. The length check is
not cosmetic: this scheme feeds leaves into the tree unhashed, so an internal node is
indistinguishable from a leaf to the fold, and an internal node recomputed from any
published receipt would otherwise verify as a VC hash.

Both the root and the `leaf_count` it measures against are arguments, and both must
come from the anchored root record — on-chain, or from Authen Service — never from
the receipt. The receipt is the thing under test:

- folding to `receipt.Root` alone proves nothing. A forger builds their own tree over
  their own leaves, and every receipt cut from it is internally consistent. The
  anchored root is what ties the proof to something the issuer committed on chain.
- passing `receipt.LeafCount` defeats the length check: a sender who lowers its
  declared count to match a short proof would pass.

The receipt's own `root` and `leaf_count` are compared against the anchored ones and
a mismatch is rejected.

Anchoring is asynchronous on the service side: submitting a root records it and
answers `pending`, and the transaction hash only appears once it is on chain. Poll
with whatever read call your service exposes, and call `MarkAnchored` when it reports
the root anchored. Until then `GenerateReceipt` refuses to issue anything, which is
the behaviour you want — a receipt naming no transaction proves nothing.

The service identifies a tree by what it commits to — `issuer_did`, `root` and
`leaf_count` — so no batch identifier is sent, and `issuer_did` is taken from the
credential you authenticate with rather than from the body. The submission is therefore
`{root, leaf_count}` and nothing more: `external_tree_id`, `hash_scheme` and
`leaves_digest` stay local, and the service reserves those field numbers permanently.
`external_tree_id` is an SDK-local key: it names the batch in your `Store` and appears
on receipts, and never goes on the wire.
Two batches of the same issuer with identical leaves are therefore the same tree to the
service, anchored once, no matter what you called them locally.

Local verification stops there, and it is all this package does. The SDK makes no
network calls at all; applications that need server-side verification should use their
own client against Authen Service.

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
