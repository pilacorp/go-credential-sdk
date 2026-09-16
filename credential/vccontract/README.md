# vccontract — verify a VC hash on-chain

`vccontract` is a lightweight, **read-only** client for the Credential Registry
smart contract. It lets a holder or any third party verify that a Verifiable
Credential (VC) hash is anchored on-chain — without a private key and without
spending gas (every call is an `eth_call` or a receipt read).

## How anchoring works

The issuer service groups VC hashes per issuer into Merkle trees and publishes
each tree's **root** on-chain (one root per `issuer` + `treeIndex`). A VC hash is
a **leaf**. Membership is proven with a Merkle **proof** — the ordered list of
sibling hashes that fold up to the root.

An **unsealed** tree keeps growing: each new anchoring overwrites the tree's
stored root. So a proof captured at an earlier anchoring no longer folds to the
*current* root — only to the root that was live when the proof was taken. That is
why there are two verification paths.

## Two ways to verify

- **`VerifyVCHashByTx`** — the one to use. It folds the proof locally
  (sorted-pair keccak256) and asks whether that exact root appears in the logs of
  the given transaction, emitted by a trusted contract for that issuer.
- **`VerifyVCHashOnChain`** — **deprecated**. It calls `verifyVC(...)`, which the
  current contract does not have, so against it this can only fail. It works
  solely against an older deployment that still keeps roots in storage.

### Why the by-tx path asks about a root instead of fetching one

The contract records an anchoring as `(issuer, root)` and carries **no tree
index**. So "what root did tree 7 get?" has no single answer — one transaction
anchors many of an issuer's trees and nothing in the log tells them apart.

Folding first removes the need for a tiebreaker: every root in the log is one the
issuer really anchored, so finding your folded root among them proves exactly what
verification is for. The tree index was only ever a lookup key, never part of what
an anchoring asserts, so nothing is lost.

### Roots anchored before the contract changed

Still verify, with no re-anchoring and no migration. Five event shapes are read —
three current (`TreeRootAnchored`, `BatchRootsAnchored`, `IssuerRootsAnchored`)
and two legacy (`TreeUpdated`, `BatchTreesUpdated`). The legacy events carry a
tree index; it is skipped rather than matched.

Two things must be true for this to hold:

1. The embedded ABI keeps all five events. It is a **hand-merged** file — the
   current contract's ABI does not contain the legacy two, so regenerating it
   blindly silently breaks every pre-upgrade credential.
2. The previous deployment's address is passed to `NewCredentialRegistry` via
   `alsoTrust`. The current contract is at a new address, so without this its
   predecessor's logs are dropped at the emitter check.

## Inputs

You supply the proof components directly (this package does not call the
authen-service API). They typically come from the authen-service proof endpoint
`GetVCProofByHash` / `GetVCProofByID`, which returns exactly these fields
(including `TxHash` for the by-transaction path):

- `IssuerAddress` — issuer's Ethereum address (`0x…`)
- `TreeIndex` — **deprecated, ignored.** Kept so callers still setting it compile.
- `Leaf` — the VC hash (32-byte hex)
- `Proof` — ordered sibling hashes (32-byte hex each; empty for a single-leaf tree)
- `TxHash` — hash of the anchoring transaction (32-byte hex) — **`VerifyVCHashByTx` only**

## Usage

```go
registry, err := vccontract.NewCredentialRegistry(
    "https://rpc.example.com",
    "0x...CredentialRegistry",
    // Every earlier deployment whose anchorings must keep verifying. Leave one
    // out and every credential anchored by it reads as never anchored.
    "0x...PreviousDeployment",
)
if err != nil {
    // handle
}
defer registry.Close()
```

Verify against the anchoring transaction:

```go
req := &vccontract.VerifyByTxRequest{
    IssuerAddress: "0x...Issuer",
    Leaf:          "0x...vcHash",
    Proof:         []string{"0x...", "0x..."},
    TxHash:        "0x...anchoringTx",
}

ok, err := registry.VerifyVCHashByTx(context.Background(), req)
if errors.Is(err, vccontract.ErrTxNotFound) {
    // the tx is unknown or not yet mined — retry later
}
```

`ok == true` means the VC hash is anchored. `ok == false` with a `nil` error means
it is not — the proof does not fold to any root this transaction anchored for this
issuer, or the transaction reverted (`ErrTxReverted`) and so anchored nothing.
Either way the transaction cannot attest the leaf; that is a verdict, not a
failure. A non-nil error means the check could not be completed — bad input, an
RPC error, or the transaction not being found (`ErrTxNotFound`).

## API

- `NewCredentialRegistry(rpcURL, contractAddress string, alsoTrust ...string) (*CredentialRegistry, error)` —
  connect to the chain (RPC connection is required). `alsoTrust` names earlier
  deployments whose anchoring logs are still to be believed.
- `(*CredentialRegistry) VerifyVCHashByTx(ctx, *VerifyByTxRequest) (bool, error)` —
  verify a VC hash against the anchoring transaction it belongs to.
- `(*CredentialRegistry) VerifyVCHashOnChain(ctx, *VerifyRequest) (bool, error)` —
  **deprecated**, see above.
- `(*CredentialRegistry) IsRootAnchored(ctx, txHash, issuer, root) (bool, error)` —
  whether a transaction records this issuer anchoring this root. Returns
  `ErrTxNotFound` or `ErrTxReverted` where they apply; a transaction that simply
  does not carry the root is `(false, nil)`.
- `(*CredentialRegistry) IsRootAnchoredAtContract(ctx, txHash, issuer, root, contractAddress) (bool, error)` —
  the same, restricted to one deployment. The address must already be trusted:
  pinning narrows what is believed and can never widen it.
- `(*CredentialRegistry) GetTreeRoot(...)`, `HasTree(...)` — **deprecated**, see
  `VerifyVCHashOnChain` above.
- `(*CredentialRegistry) Close()` — release the RPC connection.

Reuse a single `CredentialRegistry` across calls (it holds a live, concurrency-safe
RPC client) and `Close()` it on shutdown rather than creating one per request.

## Examples

Runnable examples against the testnet live under `credential/examples/vccontract/`:

```
go run ./credential/examples/vccontract/verifyonchain # verify against current root
go run ./credential/examples/vccontract/verifybytx    # verify against a tx's anchored root
```
