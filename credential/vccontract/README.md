# vccontract — verify a VC hash on-chain

`vccontract` is a lightweight, **read-only** client for the Credential Registry
smart contract. It lets a holder or any third party verify that a Verifiable
Credential (VC) hash is anchored on-chain, without a private key and without
spending gas (every call is an `eth_call`).

## How anchoring works

The issuer service groups VC hashes per issuer into Merkle trees and publishes
each tree's **root** on-chain (one root per `issuer` + `treeIndex`). A VC hash is
a **leaf**. Membership is proven with a Merkle proof — the ordered list of
sibling hashes that fold up to the root. Nodes are combined with
`keccak256(sort(a, b))` (sorted-pair hashing), matching the tree construction in
the issuer service.

## Inputs

You supply the proof components directly (this package does not call the
authen-service API). They typically come from the authen-service proof endpoint
`GetVCProofByHash` / `GetVCProofByID`, which returns exactly these fields:

- `IssuerAddress` — issuer's Ethereum address (`0x…`)
- `TreeIndex` — which tree of that issuer
- `Leaf` — the VC hash (32-byte hex)
- `Proof` — ordered sibling hashes (32-byte hex each; empty for a single-leaf tree)

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

req := &vccontract.VerifyRequest{
    IssuerAddress: "0x...Issuer",
    TreeIndex:     0,
    Leaf:          "0x...vcHash",
    Proof:         []string{"0x...", "0x..."},
}

ok, err := registry.VerifyOnChain(context.Background(), req)
```

## Two verification strategies

- **`VerifyOnChain`** — calls the contract's `verifyVC(issuer, treeIndex, leaf, proof)`
  view function. The contract does the folding, so the result is exactly what the
  chain accepts.
- **`VerifyByCompareRoot`** — fetches the root via `getTreeRoot(issuer, treeIndex)` and
  re-computes it locally from `leaf` + `proof`, then compares. This is an
  independent check that does not rely on the contract's verify logic — useful for
  cross-validating `VerifyOnChain`.

For a well-formed proof both return the same result. A `false` result (with a
`nil` error) means the proof does not validate; a non-nil error means the call
itself failed (bad input, RPC error, or the tree does not exist).

Helper reads: `GetTreeRoot` and `TreeExists`.
