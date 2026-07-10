# vccontract — verify a VC hash on-chain

`vccontract` is a lightweight, **read-only** client for the Credential Registry
smart contract. It lets a holder or any third party verify that a Verifiable
Credential (VC) hash is anchored on-chain — without a private key and without
spending gas (every call is an `eth_call`).

## How anchoring works

The issuer service groups VC hashes per issuer into Merkle trees and publishes
each tree's **root** on-chain (one root per `issuer` + `treeIndex`). A VC hash is
a **leaf**. Membership is proven with a Merkle **proof** — the ordered list of
sibling hashes that fold up to the root. Verification (folding the proof and
comparing to the stored root) is done by the contract itself, so this package
only has to pass the proof through.

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

ok, err := registry.VerifyVCHashOnChain(context.Background(), req)
```

`VerifyVCHashOnChain` calls the contract's `verifyVC(issuer, treeIndex, leaf, proof)`
view function. A `true` result means the VC hash is anchored in the issuer's tree;
a `false` result (with a `nil` error) means the proof does not validate. A non-nil
error means the call itself failed — bad input, RPC error, or the tree does not
exist.

## API

- `NewCredentialRegistry(rpcURL, contractAddress string) (*CredentialRegistry, error)` —
  connect to the chain (RPC connection is required).
- `(*CredentialRegistry) VerifyVCHashOnChain(ctx, *VerifyRequest) (bool, error)` —
  verify a VC hash against its on-chain tree.
- `(*CredentialRegistry) GetTreeRoot(ctx, issuer, treeIndex) ([32]byte, error)` —
  read the anchored Merkle root (zero value = no such tree).
- `(*CredentialRegistry) HasTree(ctx, issuer, treeIndex) (bool, error)` —
  whether the issuer has an anchored tree at that index.
- `(*CredentialRegistry) Close()` — release the RPC connection.

Reuse a single `CredentialRegistry` across calls (it holds a live, concurrency-safe
RPC client) and `Close()` it on shutdown rather than creating one per request.

## Example

A runnable example against the testnet lives in `example/`:

```
go run ./credential/vccontract/example
```
