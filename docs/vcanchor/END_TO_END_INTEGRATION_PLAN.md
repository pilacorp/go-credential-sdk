# VC Anchor End-to-End Integration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `credential/vcanchor` from a Merkle helper package into an end-to-end integration kit for applications that want to self-manage VC hash Merkle trees while Authen Service anchors roots and verifies receipts.

**Architecture:** The SDK owns deterministic tree building, receipt generation, local persistence contracts, Authen Service API calls, and safe operational workflow. Applications still own their storage backend and business trigger points, but they integrate through a small set of SDK interfaces instead of reimplementing Merkle/anchor/verify logic.

**Tech Stack:** Go SDK, `credential/vcanchor`, Authen Service external Merkle root APIs, existing Merkle scheme `keccak256-sorted-pairs-no-leaf-hash-v1`, application-provided persistent store.

## Global Constraints

- Do not use public names that include `L3`; this package is for any application/integrator.
- Keep one Merkle scheme only: `keccak256-sorted-pairs-no-leaf-hash-v1`.
- Authen Service is the anchor and verification source for roots; the application is responsible for leaf/proof availability.
- SDK must prevent unsafe flows where a root is anchored but ordered leaves are lost before receipts can be generated.
- SDK should provide production interfaces and examples, not force one database, queue, or deployment model.
- No new dependency unless the standard library or existing dependencies cannot cover the requirement.

---

## Current State

The current SDK is a correct foundation, not yet a full integration kit.

Already available:

- `BuildBatch` builds a deterministic Merkle batch from ordered VC hashes.
- `Batch.Manifest` creates the payload needed by Authen Service root submission; the application makes that call itself, the SDK does not.
- `Batch.Receipt` generates a Merkle receipt after `tx_hash` is known.
- `VerifyReceiptLocal` verifies `vc_hash + proof -> anchored root`.
- `Manager` enforces safe order: create batch, persist batch, submit root, mark anchored, generate receipt.
- `Store` lets applications plug in their own durable storage.
- No SDK storage backend is provided; applications implement `Store` using their
  own database or object storage.

Missing for end-to-end integrators:

- Opinionated worker flow for sealing, submitting, retrying, and receipt generation.
- Production store examples for SQL/object storage.
- End-to-end sample application.
- Operational checklist for retention, retry, idempotency, monitoring, and disaster recovery.
- Verification guide covering local receipt proof checks.

Recently added:

- Authen Service HTTP client for submit-root.

---

## Target Integrator Experience

An application should only need to implement these business-level decisions:

- How to compute or receive `vc_hash`.
- Which persistent backend stores ordered hashes and batch metadata.
- When to seal a batch: by count, by time, or by explicit flush.
- Where to attach/store receipts for holders.

The SDK should provide these building blocks:

- `Client`: calls Authen Service submit-root API.
- `Manager`: orchestrates create/submit/receipt flow.
- `Store`: durable storage contract.
- `Worker`: optional batching loop for high-throughput apps.
- `examples/`: runnable service and CLI examples.
- `docs/`: exact API flow, request/response examples, and failure handling.

---

## End-to-End Flow To Document And Support

### 1. Create VC Hash

Application creates or receives a VC, then computes a normalized `0x`-prefixed 32-byte `vc_hash`.

SDK responsibility:

- Validate hash format.
- Normalize casing and `0x` prefix.
- Reject duplicates inside the same batch.

Application responsibility:

- Decide whether the VC document embeds the receipt later, stores it beside the VC, or exposes it through an API.

### 2. Add Hash To A Pending Batch

Application appends `vc_hash` into a pending batch for one issuer.

SDK responsibility:

- Keep ordered hash list deterministic.
- Track `issuer_did`, `external_tree_id` (local key), `root`, `leaf_count`, `leaves_digest`, and status.
- Refuse mutation after the batch is sealed/anchored.

Application responsibility:

- Provide durable storage.
- Choose batch boundary policy.

Recommended batch policy:

- Seal by count for high traffic, for example 10,000 to 100,000 leaves per root.
- Seal by time for low traffic, for example every 5 to 15 minutes.
- Seal manually for one-off products with very low VC volume.

### 3. Build Root And Persist Before Submit

SDK builds the Merkle root from ordered leaves and persists the full batch before calling Authen Service.

This ordering is mandatory:

```text
ordered leaves persisted
-> root computed
-> manifest persisted
-> submit root
-> mark anchored with tx_hash
```

Reason:

If the process crashes after anchoring but before leaves are persisted, the root is on-chain but the application may never be able to generate receipts.

### 4. Submit Root To Authen Service

SDK client sends:

```json
{
  "root": "0x...",
  "leaf_count": 10000,
  "hash_scheme": "keccak256-sorted-pairs-no-leaf-hash-v1",
  "leaves_digest": "0x..."
}
```

No batch identifier goes on the wire: the service identifies a tree by `issuer_did +
root + leaf_count`. `external_tree_id` stays an SDK-local key for the Store.

Authen Service returns:

```json
{
  "id": 123,
  "issuer_did": "did:pila:...",
  "onchain_tree_index": 12,
  "root": "0x...",
  "leaf_count": 10000,
  "tx_hash": "",
  "status": "pending",
  "anchored_at": ""
}
```

Anchoring is asynchronous: a first submit answers `pending` with an empty `tx_hash`,
and resubmitting the same tree polls it until `status` is `anchored`.

SDK responsibility:

- Implement idempotent submit.
- Retry transient network/server errors.
- Treat a resubmit of the same tree as a poll, not a second anchor.
- Persist `tx_hash` before generating receipts.

### 5. Generate Receipt

SDK generates a receipt for each VC hash on demand or in a background job.

Receipt shape:

```json
{
  "issuer_did": "did:pila:...",
  "external_tree_id": "issuer-2026-08-14-000001",
  "vc_hash": "0x...",
  "leaf_index": 42,
  "root": "0x...",
  "proof": ["0x..."],
  "tx_hash": "0x...",
  "hash_scheme": "keccak256-sorted-pairs-no-leaf-hash-v1"
}
```

SDK responsibility:

- Generate receipt from persisted batch, not from in-memory state.
- Return clear error if batch is not anchored.
- Return clear error if `vc_hash` does not exist in the batch.

Application responsibility:

- Store receipt with VC, return it to holder, or expose a receipt API.
- Keep ordered leaves or enough tree data to regenerate receipts.

### 6. Verify Locally

Applications verify the receipt proof locally against the anchored root metadata
they trust for the batch. The SDK no longer submits receipts to an Authen Service
verify-receipt API.

SDK responsibility:

- Provide `VerifyReceiptLocal(receipt, anchoredRoot, anchoredLeafCount)` for offline proof/root reconstruction.
- Make docs explicit that local verification does not prove the root is anchored.

---

## Implementation Tasks

### Task 1: Add Authen Service Client Interfaces

**Files:**

- Modify: `credential/vcanchor/types.go`
- Create: `credential/vcanchor/client.go`
**Status:** Dropped. The anchoring API is internal to Authen Service, while this SDK is public and shared, so no HTTP client ships here. Applications call the API with their own client using `Batch.Manifest()` and report the transaction back through `Manager.MarkAnchored`.

### Task 2: Add Production Batch Worker

**Files:**

- Create: `credential/vcanchor/worker.go`
- Test: `credential/vcanchor/worker_test.go`

**Interfaces:**

- Consumes: `Manager`, `Store`
- Produces:
  - `type Worker struct`
  - `type WorkerConfig struct`
  - `func NewWorker(manager *Manager, cfg WorkerConfig) *Worker`
  - `func (w *Worker) Add(ctx context.Context, issuerDID, vcHash string) (*QueuedLeaf, error)`
  - `func (w *Worker) Flush(ctx context.Context, issuerDID string) (*Manifest, error)`

Steps:

- [ ] Write failing test that `Add` persists a pending leaf.
- [ ] Write failing test that `Flush` seals a batch and submits root.
- [ ] Write failing test that count threshold automatically seals a batch.
- [ ] Write failing test that low-volume manual flush supports fewer than threshold leaves.
- [ ] Implement the smallest synchronous worker first; do not add goroutines until tests require them.
- [ ] Add one comment if a simple in-memory issuer lock is used, including the scale ceiling and DB-lock upgrade path.
- [ ] Run `go test ./credential/vcanchor`.

### Task 3: Add Store Guidance And SQL Example

**Files:**

- Create: `credential/vcanchor/examples/sqlstore/schema.sql`
- Create: `credential/vcanchor/examples/sqlstore/store.go`
- Test: `credential/vcanchor/examples/sqlstore/store_test.go`

**Interfaces:**

- Consumes: `Store`, `StoredBatch`
- Produces: example SQL store implementing `Store`

Steps:

- [ ] Write failing store round-trip test using a local test DB only if the repo already has DB test helpers; otherwise keep this as documented example without package tests.
- [ ] Add schema for `vc_anchor_batches` and `vc_anchor_batch_leaves`.
- [ ] Store ordered leaves in a separate table keyed by `(issuer_did, external_tree_id, leaf_index)`.
- [ ] Enforce unique `(issuer_did, external_tree_id)` and unique `(issuer_did, external_tree_id, vc_hash)`.
- [ ] Implement `SaveBatch`, `GetBatch`, and `MarkAnchored`.
- [ ] Document that production apps may replace this with Postgres, MySQL, S3, or object storage as long as `Store` semantics are preserved.

### Task 4: Add End-to-End Example Application

**Files:**

- Create: `credential/examples/vcanchor-service/main.go`
- Create: `credential/examples/vcanchor-service/README.md`

**Interfaces:**

- Consumes: `vcanchor.Manager`, an application-owned
  `vcanchor.Store` implementation
- Produces: runnable example with create, submit, receipt, verify commands

Steps:

- [ ] Add example command `create-batch` that reads VC hashes from JSON file.
- [ ] Add example command `submit-root` that calls Authen Service.
- [ ] Add example command `receipt` that prints one receipt.
- [ ] Add example command `verify-local` that verifies proof/root reconstruction only.
- [ ] Add example command `verify-service` that calls Authen Service.
- [ ] Add README with exact commands and sample JSON files.
- [ ] Run `go test ./credential/...`.

### Task 5: Add Operational Guide

**Files:**

- Create: `credential/vcanchor/PRODUCTION_GUIDE.md`
- Modify: `credential/vcanchor/README.md`

**Interfaces:**

- Consumes: all public SDK APIs
- Produces: integrator-facing operation checklist

Content required:

- [ ] Explain trust model: Authen Service anchors and verifies roots; application must preserve leaf/proof availability.
- [ ] Explain retention rule: never hard-delete anchored ordered leaves unless every holder already has receipt and the business accepts no future regeneration.
- [ ] Explain crash-safe sequence: persist leaves before submit, persist `tx_hash` before receipt generation.
- [ ] Explain retry policy: resubmitting the same root and leaf_count is a poll; a different root is a different tree.
- [ ] Explain batch sizing: count-based for high traffic, time-based/manual flush for low traffic.
- [ ] Explain verification path: application submits full receipt; service cache-hit returns `source=cache`, cache-miss verifies proof and returns `source=proof`.
- [ ] Explain monitoring: pending batches, failed submits, anchored batches without receipts, cache miss rate.
- [ ] Explain backup/restore: restore store, run `ValidateStoredBatch`, then resume receipt generation.

### Task 6: Add Compatibility Tests With Authen Service

**Files:**

- Create: `credential/vcanchor/compat_test.go`

**Interfaces:**

- Consumes: SDK Merkle root/proof logic
- Produces: golden vectors usable by Authen Service tests

Steps:

- [ ] Add golden leaves, expected root, expected proof for at least 1, 2, 3, 4, and 5 leaves.
- [ ] Verify odd leaf duplication behavior.
- [ ] Verify sorted pair behavior by reversing sibling order.
- [ ] Export golden vector JSON into `credential/vcanchor/testdata/golden_vectors.json`.
- [ ] Run `go test ./credential/vcanchor`.

---

## Recommended Delivery Order

1. Authen Service client first, because it removes the biggest custom implementation burden from applications.
2. Operational guide second, because integrators need the correct mental model before production.
3. End-to-end example third, because it becomes the canonical copy/paste integration.
4. Worker fourth, because some apps may prefer manual batching and we should not over-abstract too early.
5. SQL/object-store examples fifth, because storage choice is app-specific.
6. Golden compatibility tests continuously, because service and SDK must never drift on Merkle behavior.

---

## What The Integrator Still Owns

The SDK should not own these decisions:

- Application database choice.
- Business trigger for VC creation.
- Product-specific receipt placement.
- Retention period.
- Queue technology.
- Deployment topology.

The SDK should own these decisions:

- Hash normalization.
- Merkle root/proof algorithm.
- Receipt shape.
- Safe state machine.
- Authen Service API payloads.
- Retry/idempotency semantics around root submission.
- Verification client behavior.

---

## Success Criteria

The integration is complete when a new application team can do this without reading Authen Service internals:

1. Install SDK.
2. Configure a `Store`.
4. Add VC hashes to batches.
5. Submit roots.
6. Generate receipts.
7. Verify locally and through Authen Service.
8. Recover after restart without losing ability to generate receipts.
