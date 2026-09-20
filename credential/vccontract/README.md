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
- **`VerifyVCHashOnChain`** — **deprecated, old contract only**. It calls
  `verifyVC(...)`, which the current contract does not have, so against it this
  can only fail. It works solely against an older deployment that still keeps
  roots in storage.

`GetTreeRoot`, `HasTree` and `GetAnchoredRoot` are old-contract-only for the same
reason — see the table under [API](#api).

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
2. Every deployment that ever anchored is named to `NewCredentialRegistry` —
   `contractAddress`, `alsoTrust`, or both; position does not matter, only
   membership. An address left out has its logs dropped at the emitter check, and
   every credential anchored by it verifies as `false` **with no error**.

### ⚠️ Naming no address at all turns the emitter check off

Pass no address in either parameter and **every log is believed, whichever
contract emitted it**. This is allowed on purpose, so a caller who does not want
to enumerate deployments is not forced to. Understand what it costs.

The event signatures are public. With the check off, an attacker:

1. builds a Merkle tree over leaves they invented;
2. deploys their own contract that emits `TreeRootAnchored(issuer, root)`;
3. calls it naming **an issuer address they do not control** and their own root;
4. hands you a proof bundle pointing at that transaction.

It verifies as `true`. There is no other check standing between a real anchoring
and that one — the emitter is the whole of it.

So: name at least one address in anything that accepts a credential from outside.
An empty trusted set is for a local experiment, or for exploring a chain whose
deployments you are still discovering — cases where a `true` does not have to mean
anything.

## Inputs

You supply the proof components directly (this package does not call the
authen-service API). They typically come from the authen-service proof endpoint
`GetVCProofByHash` / `GetVCProofByID`, which returns exactly these fields
(including `TxHash` for the by-transaction path):

- `IssuerAddress` — issuer's Ethereum address (`0x…`). **Derive it from the VC's
  own `issuer` and check it against the issuers you trust; never take it from the
  proof bundle.** See below.
- `TreeIndex` — **deprecated, ignored.** Kept so callers still setting it compile.
- `Leaf` — the VC hash (32-byte hex). Compute it yourself from the VC being
  verified; never accept it from the holder. An inner node of the tree also
  folds to the anchored root, so an unverified leaf proves nothing.
- `Proof` — ordered sibling hashes (32-byte hex each; empty for a single-leaf tree)
- `TxHash` — hash of the anchoring transaction (32-byte hex) — **`VerifyVCHashByTx` only**
- `ContractAddress` — optional, **`VerifyVCHashByTx` only.** The deployment that
  anchored this proof, as the proof API reported it for that anchoring. Leave it
  empty and any trusted deployment may supply the root; set it and only that one
  may. Setting it is strictly safer, and it must name an address already passed
  to `NewCredentialRegistry` — pinning narrows what is believed and can never
  widen it (`ErrUntrustedContract`). It travels with `TxHash` rather than with the
  tree, because a tree left open across a migration is anchored first at one
  address and later at another.

### What this package proves, and what it does not

A `true` means exactly one thing:

> **an anchoring of this root was recorded under this issuer address — by the issuer itself or by a WRITER of a trusted deployment — and this leaf is in it.**

Two of the inputs decide what that sentence is *about*, and neither can be taken
from whoever is presenting the credential.

**`Leaf` — hash the VC yourself.** The tree hashes sibling pairs but does not hash
leaves, so a leaf and an inner node are both just 32 bytes and the fold cannot
tell them apart. An inner node, presented with the rest of its path, reproduces
the anchored root one step shorter — and verification says true, correctly: that
value really is in the tree. It says nothing about any credential. Only hashing
the document in front of you ties the answer to that document.

**`IssuerAddress` — derive it from the VC and check it against issuers you trust.**
The contract lets any address anchor roots under itself (`anchorTreeRoot` and
`batchAnchorIssuerTreeRoots` accept the caller as its own issuer). So anyone can
build a tree containing anything, anchor it under an address they control, and
hand over a perfectly valid proof. `true` then means "that address anchored this"
— which is true and worthless. The address has to be the one the VC names, and
one you recognise.

`TxHash`, `Proof` and `ContractAddress` are safe to take from the bundle: they
cannot make a false claim verify. A bad one yields `false`, or an error —
`ErrTxNotFound` for an unknown hash, `ErrUntrustedContract` for an untrusted
pin — so cap retries on `ErrTxNotFound` when the hash came from the holder.

## Usage

```go
registry, err := vccontract.NewCredentialRegistry(
    "https://rpc.example.com",
    // Who to call. Only the three deprecated view functions call anything, so
    // pass "" unless you use them — there is no placeholder address to invent.
    "",
    // Whose logs to believe. Every deployment whose anchorings must keep
    // verifying, including the current one. Leave one out and every credential
    // anchored by it reads as never anchored — false, with no error.
    "0x...CredentialRegistry",
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

### Reading the result

The two return values answer two different questions, and the distinction is the
whole contract of this call:

| Result | Meaning |
|---|---|
| `(true, nil)` | The chain was asked, and it attests the leaf. |
| `(false, nil)` | **The chain was asked, and it does not.** |
| `(_, err)` | **The chain could not be asked.** Nothing was established either way. |

A `false` is a verdict, not a failure. It covers all three of these:

- the proof does not fold to any root this transaction anchored for this issuer;
- the transaction **reverted**, and so anchored nothing at all;
- the proof folds to an **all-zero root**, which no transaction can ever have
  anchored — the contract rejects an empty root with `EmptyRoot`, so it never
  reaches a log. The receipt is not even fetched. (`FoldProof` returns the leaf
  unchanged when the path is empty, so a caller asking about the zero hash with
  no siblings lands here: a well-formed question whose answer is simply no.)

The second one is deliberately not an error. A reverted transaction did run, and
it wrote nothing — so "this transaction does not attest the leaf" is the true and
complete answer, already known. Returning an error would claim the check never
happened.

It is also close to unreachable in practice: a `tx_hash` obtained from the
authen-service proof API is always a successful anchoring, because the anchoring
row is only written after a successful receipt. A reverted hash arriving here
means the caller supplied one that did not come from there.

An error means bad input, an RPC failure, or the transaction not being found
(`ErrTxNotFound` — unknown or not yet mined, so worth retrying).

**If you do need to tell a reverted transaction apart** — an auditing tool, an
operator script — call `IsRootAnchored` directly. It is the layer below and
returns `ErrTxReverted` unchanged. `VerifyVCHashByTx` exists to give a verdict;
`IsRootAnchored` exists to report what the chain said.

It is keyed on the root rather than the leaf, so fold first. `FoldProof` is
exported for exactly this: reimplementing the rule risks a fold that differs in
some detail and produces a different root with nothing to signal it.

```go
root := vccontract.FoldProof(leaf, proof) // [32]byte, [][32]byte

anchored, err := registry.IsRootAnchored(ctx, txHash, issuer, root)
switch {
case errors.Is(err, vccontract.ErrTxReverted):
    // the anchoring transaction failed — an operational problem, not a bad proof
case errors.Is(err, vccontract.ErrTxNotFound):
    // unknown or not yet mined — retry
case err != nil:
    // could not reach the chain
case !anchored:
    // the chain was asked, and this transaction does not carry that root
}
```

## API

### Which contract each function works against

| Function | Old contract | Current contract |
| --- | --- | --- |
| `VerifyVCHashByTx` | ✅ | ✅ |
| `IsRootAnchored`, `IsRootAnchoredAtContract` | ✅ | ✅ |
| `FoldProof` | — pure computation, no chain | — |
| `VerifyVCHashOnChain` | ✅ | ❌ `eth_call` fails — no `verifyVC` |
| `GetTreeRoot` | ✅ | ❌ `eth_call` fails — no `getTreeRoot` |
| `HasTree` | ✅ | ❌ `eth_call` fails — no `treeExists` |
| `GetAnchoredRoot` | ✅ | ❌ always `ErrRootNotAnchored` |

The four marked ❌ all resolve `(issuer, treeIndex)`, and the current contract
records no tree index anywhere — not in storage, not in an event. So there is no
replacement that takes one, and none can be written: `(issuer, treeIndex) → root`
is not derivable from chain data any more. That mapping now lives off-chain, in
the issuer service's database.

Which is why migrating off them splits in two:

- **A caller that can carry a tx hash** uses `VerifyVCHashByTx`. The proof API
  already returns one alongside the proof, so usually nothing extra is needed.
- **A caller that must keep the old call shape** — issuer, tree index, leaf,
  proof — goes through the issuer service's `POST /api/v1/credentials/verify-hash`
  instead. It holds the database that still maps a tree index to its anchoring
  transaction; this package has no database and cannot.

`GetAnchoredRoot` fails differently from the other three, and worse: they fail at
the RPC layer, while it returns a **well-formed negative**, so a caller that
reads `ErrRootNotAnchored` as "not anchored" reports every valid credential as
unanchored, silently.

`alsoTrust` does not bridge this. It widens whose *logs* are believed and never
changes which address is called — `eth_call` always goes to `contractAddress`.
Serving both the view functions and log reading needs **two `CredentialRegistry`
instances**, one per deployment.

- `NewCredentialRegistry(rpcURL, contractAddress string, alsoTrust ...string) (*CredentialRegistry, error)` —
  connect to the chain (RPC connection is required). The two address parameters
  answer two different questions: `contractAddress` is **who to call**, needed
  only by the three view functions, and `alsoTrust` is **whose logs to believe** —
  those addresses are never called. Both feed the trusted set and position in it
  means nothing. The zero address is refused in either position
  (`common.IsHexAddress` accepts it, so an unset variable arrives looking valid).
  Naming **no** address is allowed and turns the emitter check off — see the
  warning below.
- `(*CredentialRegistry) VerifyVCHashByTx(ctx, *VerifyByTxRequest) (bool, error)` —
  verify a VC hash against the anchoring transaction it belongs to.
- `(*CredentialRegistry) VerifyVCHashOnChain(ctx, *VerifyRequest) (bool, error)` —
  **deprecated**, see above.
- `(*CredentialRegistry) IsRootAnchored(ctx, txHash, issuer, root) (bool, error)` —
  whether a transaction records this issuer anchoring this root. Unlike
  `VerifyVCHashByTx` above, this reports the chain's state rather than a verdict:
  it returns `ErrTxNotFound` and `ErrTxReverted` to the caller instead of folding
  them into `false`. A transaction that simply does not carry the root is still
  `(false, nil)`.
- `(*CredentialRegistry) IsRootAnchoredAtContract(ctx, txHash, issuer, root, contractAddress) (bool, error)` —
  the same, restricted to one deployment. The address must already be trusted:
  pinning narrows what is believed and can never widen it.
- `(*CredentialRegistry) GetAnchoredRoot(ctx, txHash, issuer, treeIndex) ([32]byte, error)` —
  **deprecated**, kept for source compatibility with v1.9.x. Reads the legacy
  `BatchTreesUpdated` event only, so a root anchored by the current contract is
  never found through it (`ErrRootNotAnchored`). Use `IsRootAnchored`.
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
