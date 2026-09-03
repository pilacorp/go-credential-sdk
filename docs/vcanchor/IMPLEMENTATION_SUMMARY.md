# VC Anchor SDK Implementation Summary

This package adds the SDK-side foundation for external applications to manage
their own Merkle trees while Authen Service only anchors roots and verifies
receipts.

## Package

Path:

```text
credential/vcanchor
```

Public concept:

```text
External-managed VC anchor
```

No public naming uses `L3`; the package is intended for any application or
integrator.

## Merkle Scheme

The SDK hardcodes one scheme to match Authen Service's current Merkle behavior:

```text
keccak256-sorted-pairs-no-leaf-hash-v1
```

Rules:

- leaf is the raw 32-byte `vc_hash`
- leaf hashing is disabled
- parent node is `keccak256(sort(left, right))`
- odd rightmost node is paired with itself
- receipt proof is a list of sibling hashes

## Core APIs

Low-level APIs:

```go
BuildBatch(input BatchInput) (*Batch, error)
(*Batch) Manifest() Manifest
(*Batch) Receipt(vcHash, txHash string) (*Receipt, error)
VerifyReceiptLocal(receipt Receipt, anchoredRoot string, anchoredLeafCount int) (bool, error)
```

Recommended high-level APIs:

```go
NewManager(store Store) *Manager
(*Manager) CreateBatch(ctx, input) (*Batch, error)
(*Manager) MarkAnchored(ctx, issuerDID, externalTreeID, txHash) error
(*Manager) GenerateReceipt(ctx, issuerDID, externalTreeID, vcHash) (*Receipt, error)
(*Manager) ValidateStoredBatch(ctx, issuerDID, externalTreeID) error
```

There is no Authen Service client here. Anchoring is an internal-service call, so the
application makes it with its own client, using `Batch.Manifest()` as the payload, and
reports the transaction back through `MarkAnchored`. This package makes no network
calls.

## Persistence

The SDK adds a `Store` interface so applications do not lose the data required
to regenerate receipts:

```go
type Store interface {
    SaveBatch(ctx context.Context, batch StoredBatch) error
    GetBatch(ctx context.Context, issuerDID, externalTreeID string) (*StoredBatch, error)
    MarkAnchored(ctx context.Context, issuerDID, externalTreeID, txHash string) error
}
```

Provided storage backend:

- None. Applications must implement `Store` using their own database or object
  storage.

Stored data includes:

- issuer DID
- external tree ID
- ordered VC hashes
- root
- leaf count
- hash scheme
- leaves digest
- anchor transaction hash
- status

## Data Integrity Checks

The SDK computes `leaves_digest` as `keccak256` over the ordered raw 32-byte
leaf list. `ValidateStoredBatch` rebuilds the batch from stored ordered leaves
and checks:

- root matches
- leaf count matches
- hash scheme matches
- leaves digest matches

This detects local corruption or accidental rebuilds with different data.

## Workflow Protected By Manager

The manager enforces this order:

```text
CreateBatch
-> persist StoredBatch
-> application anchors batch.Manifest() through its own client
-> MarkAnchored(tx_hash)
-> GenerateReceipt from persisted data
```

This prevents the unsafe flow:

```text
build root in memory
-> submit root
-> process crashes
-> ordered leaves are lost
-> receipt cannot be generated
```

## Receipt

Receipt format:

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

`VerifyReceiptLocal` proves only:

```text
vc_hash + proof reconstructs the anchored root passed in
```

The caller supplies that root (and leaf_count) from the anchored record — on chain or
from Authen Service. The receipt's own values are compared against them, never trusted.

Authen Service must still verify:

- root exists in service DB
- root belongs to issuer and external tree
- root was anchored
- tx hash matches the anchored root

## Limitations

- The SDK cannot guarantee availability if an integrator deletes all stored
  batches and receipts.
- `GenerateReceipt` currently rebuilds proof from ordered hashes. This is simple
  and correct, but for multi-million-leaf trees a production store should persist
  tree levels or chunk nodes to avoid rebuilding large trees on every receipt.
- Anchoring is not implemented here. The Authen Service API is internal while this SDK
  is public, so the transport stays on the application side and this package keeps to
  what is verifiable offline.

## Tests Added

Test file:

```text
credential/vcanchor/vcanchor_test.go
credential/vcanchor/manager_test.go
```

Covered behavior:

- build batch and generate verifiable receipt
- reject tampered receipt leaf
- reject duplicate VC hashes
- persist batch and generate receipt from store
- reject same external tree ID with different content
- store contract save/load/mark-anchored round trip through test-only fake store
- Authen Service client submit-root and receipt verification payloads
