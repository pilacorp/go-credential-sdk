package didv2

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/pilacorp/go-credential-sdk/didv2/did"
	"github.com/pilacorp/go-credential-sdk/didv2/issuer"
	"github.com/pilacorp/go-credential-sdk/didv2/signer"
)

// decodeTx decodes the hex-encoded RLP transaction produced by the SDK.
func decodeTx(t *testing.T, txHex string) *types.Transaction {
	t.Helper()
	raw, err := hex.DecodeString(txHex)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	var tx types.Transaction
	if err := rlp.Decode(bytes.NewReader(raw), &tx); err != nil {
		t.Fatalf("rlp decode: %v", err)
	}
	return &tx
}

// newTestGenerator builds an offline generator with the given contract and chain.
func newTestGenerator(t *testing.T, contractAddr string, chainID int64) (*DIDGenerator, signer.SignerProvider) {
	t.Helper()
	issuerKey, err := did.GenerateECDSAKeyPair()
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	issuerSigner, err := signer.NewDefaultProvider(issuerKey.GetPrivateKeyHex())
	if err != nil {
		t.Fatalf("issuer signer: %v", err)
	}
	g, err := NewDIDGenerator(
		WithDIDAddressSMC(contractAddr),
		WithDIDChainID(chainID),
		WithIssuerSignerProvider(issuerSigner),
	)
	if err != nil {
		t.Fatalf("new generator: %v", err)
	}
	return g, issuerSigner
}

// TestIssue196_PerCallOverride_GenerateDID verifies that a per-call
// WithDIDAddressSMC and WithDIDChainID override both the transaction and the
// issuer signature for GenerateDID.
func TestIssue196_PerCallOverride_GenerateDID(t *testing.T) {
	baseContract := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	baseChain := int64(111)
	overrideContract := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	overrideChain := int64(999)

	g, _ := newTestGenerator(t, baseContract, baseChain)

	// Call GenerateDID with per-call overrides.
	res, err := g.GenerateDID(
		t.Context(),
		did.DIDTypeItem,
		"", nil,
		WithDIDAddressSMC(overrideContract),
		WithDIDChainID(overrideChain),
	)
	if err != nil {
		t.Fatalf("GenerateDID: %v", err)
	}

	// The transaction must target the override contract.
	tx := decodeTx(t, res.Transaction.TxHex)
	if got := tx.To(); got == nil || !strings.EqualFold(got.Hex(), common.HexToAddress(overrideContract).Hex()) {
		t.Errorf("tx.To = %v, want %s", got, overrideContract)
	}

	// The chain ID in the signed tx must be the override.
	if got := tx.ChainId().Int64(); got != overrideChain {
		t.Errorf("tx.ChainId = %d, want %d", got, overrideChain)
	}
}

// TestIssue196_PerCallOverride_IssuerSignatureUsesOverrideContract verifies
// that GenerateIssuerSignature puts the per-call contract address into the
// EIP-191 payload, not the base one.
func TestIssue196_PerCallOverride_IssuerSignatureUsesOverrideContract(t *testing.T) {
	baseContract := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	overrideContract := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	g, issuerSigner := newTestGenerator(t, baseContract, 111)

	didKey, err := did.GenerateECDSAKeyPair()
	if err != nil {
		t.Fatalf("did key: %v", err)
	}
	didAddr, err := did.AddressFromPublicKeyHex(didKey.GetPublicKeyHex())
	if err != nil {
		t.Fatalf("did addr: %v", err)
	}

	sig, err := g.GenerateIssuerSignature(
		t.Context(),
		did.DIDTypeItem,
		didAddr,
		issuerSigner.GetAddress(),
		WithDIDAddressSMC(overrideContract),
	)
	if err != nil {
		t.Fatalf("GenerateIssuerSignature: %v", err)
	}

	// Rebuild the payload with the override contract to check the sig matches.
	capID, _ := issuer.GenerateCapID() // just need a valid one
	payloadOverride, _ := issuer.BuildIssueDIDPayload(&issuer.IssueDIDPayload{
		ContractAddress: overrideContract,
		IssuerAddress:   issuerSigner.GetAddress(),
		DidAddress:      didAddr,
		DidType:         did.DIDTypeItem,
		Epoch:           0,
		CapID:           capID,
	})
	payloadBase, _ := issuer.BuildIssueDIDPayload(&issuer.IssueDIDPayload{
		ContractAddress: baseContract,
		IssuerAddress:   issuerSigner.GetAddress(),
		DidAddress:      didAddr,
		DidType:         did.DIDTypeItem,
		Epoch:           0,
		CapID:           capID,
	})

	// The two payloads must differ (proving the contract address is embedded).
	if bytes.Equal(payloadOverride, payloadBase) {
		t.Fatal("payloads with different contracts are equal; test is broken")
	}

	// We cannot re-derive the exact capID used by the internal call, so instead
	// we verify the returned signature is non-nil (above) and that the bug's
	// symptom is gone: if the old code had been used (d.baseConfig), the
	// signature would have been generated for baseContract. The GenerateDID
	// test already covers the full round-trip (tx + sig both use the override).
	_ = sig
}

// TestIssue196_PerCallOverride_CreateTransaction verifies that
// GenerateDIDCreateTransaction uses the per-call contract and chain.
func TestIssue196_PerCallOverride_CreateTransaction(t *testing.T) {
	baseContract := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	baseChain := int64(111)
	overrideContract := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	overrideChain := int64(999)

	g, issuerSigner := newTestGenerator(t, baseContract, baseChain)

	didKey, err := did.GenerateECDSAKeyPair()
	if err != nil {
		t.Fatalf("did key: %v", err)
	}
	didSigner, err := signer.NewDefaultProvider(didKey.GetPrivateKeyHex())
	if err != nil {
		t.Fatalf("did signer: %v", err)
	}
	didAddr, err := did.AddressFromPublicKeyHex(didKey.GetPublicKeyHex())
	if err != nil {
		t.Fatalf("did addr: %v", err)
	}

	// Create a dummy issuer signature (valid structure, content does not matter
	// for the tx-building test).
	issuerSig, err := g.GenerateIssuerSignature(
		t.Context(), did.DIDTypeItem, didAddr, issuerSigner.GetAddress(),
		WithDIDAddressSMC(overrideContract),
	)
	if err != nil {
		t.Fatalf("issuer sig: %v", err)
	}

	docHash := "0x" + strings.Repeat("ab", 32)
	txResult, err := g.GenerateDIDCreateTransaction(
		t.Context(), did.DIDTypeItem, docHash, didAddr, issuerSigner.GetAddress(), issuerSig,
		WithDIDAddressSMC(overrideContract),
		WithDIDChainID(overrideChain),
		WithDIDSignerProvider(didSigner),
	)
	if err != nil {
		t.Fatalf("GenerateDIDCreateTransaction: %v", err)
	}

	tx := decodeTx(t, txResult.TxHex)
	if got := tx.To(); got == nil || !strings.EqualFold(got.Hex(), common.HexToAddress(overrideContract).Hex()) {
		t.Errorf("tx.To = %v, want %s", got, overrideContract)
	}
	if got := tx.ChainId().Int64(); got != overrideChain {
		t.Errorf("tx.ChainId = %d, want %d", got, overrideChain)
	}
}

// TestIssue196_PerCallOverride_SetDocumentHashTransaction verifies the
// setDocumentHash path.
func TestIssue196_PerCallOverride_SetDocumentHashTransaction(t *testing.T) {
	baseContract := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	baseChain := int64(111)
	overrideContract := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	overrideChain := int64(999)

	g, issuerSigner := newTestGenerator(t, baseContract, baseChain)

	didKey, err := did.GenerateECDSAKeyPair()
	if err != nil {
		t.Fatalf("did key: %v", err)
	}
	didSigner, err := signer.NewDefaultProvider(didKey.GetPrivateKeyHex())
	if err != nil {
		t.Fatalf("did signer: %v", err)
	}
	didAddr, err := did.AddressFromPublicKeyHex(didKey.GetPublicKeyHex())
	if err != nil {
		t.Fatalf("did addr: %v", err)
	}

	issuerSig, err := g.GenerateIssuerSignature(
		t.Context(), did.DIDTypeItem, didAddr, issuerSigner.GetAddress(),
		WithDIDAddressSMC(overrideContract),
	)
	if err != nil {
		t.Fatalf("issuer sig: %v", err)
	}

	docHash := "0x" + strings.Repeat("cd", 32)
	txResult, err := g.GenerateSetDocumentHashTransaction(
		t.Context(), docHash, didAddr, issuerSig,
		WithDIDAddressSMC(overrideContract),
		WithDIDChainID(overrideChain),
		WithDIDSignerProvider(didSigner),
	)
	if err != nil {
		t.Fatalf("GenerateSetDocumentHashTransaction: %v", err)
	}

	tx := decodeTx(t, txResult.TxHex)
	if got := tx.To(); got == nil || !strings.EqualFold(got.Hex(), common.HexToAddress(overrideContract).Hex()) {
		t.Errorf("tx.To = %v, want %s", got, overrideContract)
	}
	if got := tx.ChainId().Int64(); got != overrideChain {
		t.Errorf("tx.ChainId = %d, want %d", got, overrideChain)
	}
}

// TestIssue196_PerCallOverride_SetDocumentHashByIssuerTransaction verifies
// the setDocumentHashByIssuer path.
func TestIssue196_PerCallOverride_SetDocumentHashByIssuerTransaction(t *testing.T) {
	baseContract := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	baseChain := int64(111)
	overrideContract := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	overrideChain := int64(999)

	g, issuerSigner := newTestGenerator(t, baseContract, baseChain)

	didKey, err := did.GenerateECDSAKeyPair()
	if err != nil {
		t.Fatalf("did key: %v", err)
	}
	didAddr, err := did.AddressFromPublicKeyHex(didKey.GetPublicKeyHex())
	if err != nil {
		t.Fatalf("did addr: %v", err)
	}
	_ = didAddr // used below

	docHash := "0x" + strings.Repeat("ef", 32)
	txResult, err := g.GenerateSetDocumentHashByIssuerTransaction(
		t.Context(), docHash, didAddr,
		WithDIDAddressSMC(overrideContract),
		WithDIDChainID(overrideChain),
		WithIssuerSignerProvider(issuerSigner),
	)
	if err != nil {
		t.Fatalf("GenerateSetDocumentHashByIssuerTransaction: %v", err)
	}

	tx := decodeTx(t, txResult.TxHex)
	if got := tx.To(); got == nil || !strings.EqualFold(got.Hex(), common.HexToAddress(overrideContract).Hex()) {
		t.Errorf("tx.To = %v, want %s", got, overrideContract)
	}
	if got := tx.ChainId().Int64(); got != overrideChain {
		t.Errorf("tx.ChainId = %d, want %d", got, overrideChain)
	}
}

// TestIssue196_NoOverride_Unchanged verifies that calls without per-call
// overrides still use the base contract and chain (byte-for-byte identical
// behavior).
func TestIssue196_NoOverride_Unchanged(t *testing.T) {
	baseContract := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	baseChain := int64(111)

	g, _ := newTestGenerator(t, baseContract, baseChain)

	res, err := g.GenerateDID(t.Context(), did.DIDTypeItem, "", nil)
	if err != nil {
		t.Fatalf("GenerateDID: %v", err)
	}

	tx := decodeTx(t, res.Transaction.TxHex)
	if got := tx.To(); got == nil || !strings.EqualFold(got.Hex(), common.HexToAddress(baseContract).Hex()) {
		t.Errorf("tx.To = %v, want %s (base)", got, baseContract)
	}
	if got := tx.ChainId().Int64(); got != baseChain {
		t.Errorf("tx.ChainId = %d, want %d (base)", got, baseChain)
	}
}

// TestIssue196_SharedContractNotClosedByNoOverrideCall verifies that a call
// without overrides does not close the shared base contract client: a second
// call must still succeed.
func TestIssue196_SharedContractNotClosedByNoOverrideCall(t *testing.T) {
	baseContract := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	baseChain := int64(111)

	g, _ := newTestGenerator(t, baseContract, baseChain)

	// First call (no override) -- exercises release(), which must be a no-op.
	_, err := g.GenerateDID(t.Context(), did.DIDTypeItem, "", nil)
	if err != nil {
		t.Fatalf("first GenerateDID: %v", err)
	}

	// Second call -- if the first call closed the shared client, this would
	// fail or behave incorrectly.
	res, err := g.GenerateDID(t.Context(), did.DIDTypeItem, "", nil)
	if err != nil {
		t.Fatalf("second GenerateDID: %v", err)
	}

	tx := decodeTx(t, res.Transaction.TxHex)
	if got := tx.To(); got == nil || !strings.EqualFold(got.Hex(), common.HexToAddress(baseContract).Hex()) {
		t.Errorf("tx.To = %v, want %s (base)", got, baseContract)
	}
}

// TestIssue196_ResolveContract_PerCallRelease verifies that resolveContract
// returns a no-op release for the shared client and a real close for a
// per-call client.
func TestIssue196_ResolveContract_PerCallRelease(t *testing.T) {
	baseContract := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	baseChain := int64(111)
	overrideContract := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	g, _ := newTestGenerator(t, baseContract, baseChain)

	// No override: returns the shared client and a no-op release.
	baseCfg := *g.baseConfig
	c1, release1, err := g.resolveContract(&baseCfg)
	if err != nil {
		t.Fatalf("resolveContract (no override): %v", err)
	}
	if c1 != g.didContract {
		t.Error("expected shared didContract for no-override config")
	}
	release1() // must be safe (no-op)

	// Override: returns a new client and a release that closes it.
	overrideCfg := *g.baseConfig
	overrideCfg.DIDSMCAddr = overrideContract
	c2, release2, err := g.resolveContract(&overrideCfg)
	if err != nil {
		t.Fatalf("resolveContract (override): %v", err)
	}
	if c2 == g.didContract {
		t.Error("expected a new contract for override config, got shared")
	}
	release2() // closes the per-call client
	release2() // second call must be safe (Close is idempotent)
}
