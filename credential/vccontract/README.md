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

- **`VerifyVCHashOnChain`** — checks the proof against the tree's **current**
  root. The contract's `verifyVC(...)` view function folds the proof and returns
  the verdict. Use this for a sealed tree, or when the proof was taken against the
  latest anchoring.
- **`VerifyVCHashByTx`** — checks the proof against the root that a **specific
  transaction** anchored, read from that transaction's receipt logs
  (`BatchTreesUpdated`). The proof is folded locally (sorted-pair keccak256, the
  same rule the contract uses). Use this when the tree is unsealed and its current
  root has moved on: pass the tx hash of the anchoring the proof belongs to.

## Inputs

You supply the proof components directly (this package does not call the
authen-service API). They typically come from the authen-service proof endpoint
`GetVCProofByHash` / `GetVCProofByID`, which returns exactly these fields
(including `TxHash` for the by-transaction path):

- `IssuerAddress` — issuer's Ethereum address (`0x…`)
- `TreeIndex` — which tree of that issuer
- `Leaf` — the VC hash (32-byte hex)
- `Proof` — ordered sibling hashes (32-byte hex each; empty for a single-leaf tree)
- `TxHash` — hash of the anchoring transaction (32-byte hex) — **`VerifyVCHashByTx` only**

## Usage

```go
registry, err := vccontract.NewCredentialRegistry(
    "https://rpc.example.com",
    "0x...CredentialRegistry",
)
if err != nil {
    // handle
}
defer registry.Close()
```

Against the current root:

```go
req := &vccontract.VerifyRequest{
    IssuerAddress: "0x...Issuer",
    TreeIndex:     0,
    Leaf:          "0x...vcHash",
    Proof:         []string{"0x...", "0x..."},
}

ok, err := registry.VerifyVCHashOnChain(context.Background(), req)
```

Against the root a specific transaction anchored:

```go
req := &vccontract.VerifyByTxRequest{
    IssuerAddress: "0x...Issuer",
    TreeIndex:     0,
    Leaf:          "0x...vcHash",
    Proof:         []string{"0x...", "0x..."},
    TxHash:        "0x...anchoringTx",
}

ok, err := registry.VerifyVCHashByTx(context.Background(), req)
if errors.Is(err, vccontract.ErrTxNotFound) {
    // the tx is unknown or not yet mined — retry later
}
```

For both, `ok == true` means the VC hash is anchored; `ok == false` with a
`nil` error means the proof does not validate. For `VerifyVCHashByTx`, a `false`
with `nil` error also covers a reverted transaction (`ErrTxReverted`) or a
transaction that anchored no root for this issuer and tree index
(`ErrRootNotAnchored`) — in both cases the transaction simply cannot attest the
leaf. A non-nil error means the check could not be completed — bad input, an RPC
error, or (for the by-tx path) the transaction not being found (`ErrTxNotFound`).

## API

- `NewCredentialRegistry(rpcURL, contractAddress string) (*CredentialRegistry, error)` —
  connect to the chain (RPC connection is required).
- `(*CredentialRegistry) VerifyVCHashOnChain(ctx, *VerifyRequest) (bool, error)` —
  verify a VC hash against the tree's current on-chain root.
- `(*CredentialRegistry) VerifyVCHashByTx(ctx, *VerifyByTxRequest) (bool, error)` —
  verify a VC hash against the root a specific transaction anchored.
- `(*CredentialRegistry) GetAnchoredRoot(ctx, txHash, issuer, treeIndex) ([32]byte, error)` —
  read the root a transaction recorded for an issuer/tree (returns `ErrTxNotFound`,
  `ErrTxReverted`, or `ErrRootNotAnchored` as appropriate).
- `(*CredentialRegistry) GetTreeRoot(ctx, issuer, treeIndex) ([32]byte, error)` —
  read the current anchored Merkle root (zero value = no such tree).
- `(*CredentialRegistry) HasTree(ctx, issuer, treeIndex) (bool, error)` —
  whether the issuer has an anchored tree at that index.
- `(*CredentialRegistry) Close()` — release the RPC connection.

Reuse a single `CredentialRegistry` across calls (it holds a live, concurrency-safe
RPC client) and `Close()` it on shutdown rather than creating one per request.

## Examples

Runnable examples against the testnet live under `example/`:

```
go run ./credential/vccontract/example            # verify against current root
go run ./credential/vccontract/example/verifybytx # verify against a tx's anchored root
```
