package didv2

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/gorilla/websocket"
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

	g, issuerSigner := newTestGenerator(t, baseContract, baseChain)

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
	assertIssuerSigBindsContract(t, tx, res.DID, issuerSigner.GetAddress(), overrideContract, baseContract)
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

	capID, err := issuer.GenerateCapID()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := g.GenerateIssuerSignature(
		t.Context(),
		did.DIDTypeItem,
		didAddr,
		issuerSigner.GetAddress(),
		WithDIDAddressSMC(overrideContract),
		WithCapID(capID),
	)
	if err != nil {
		t.Fatalf("GenerateIssuerSignature: %v", err)
	}
	payload := func(contract string) []byte {
		t.Helper()
		out, err := issuer.BuildIssueDIDPayload(&issuer.IssueDIDPayload{
			ContractAddress: contract,
			IssuerAddress:   issuerSigner.GetAddress(),
			DidAddress:      didAddr,
			DidType:         did.DIDTypeItem,
			Epoch:           0,
			CapID:           capID,
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := recoverIssuer(t, payload(overrideContract), sig); !strings.EqualFold(got, issuerSigner.GetAddress()) {
		t.Fatalf("signature recovers %s, want issuer %s for the override contract", got, issuerSigner.GetAddress())
	}
	if got := recoverIssuer(t, payload(baseContract), sig); strings.EqualFold(got, issuerSigner.GetAddress()) {
		t.Fatal("signature also recovers the issuer for the base contract")
	}
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
// overrides still target the base contract and chain.
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
// without overrides does not close the shared base contract client. SyncNonce
// reads the nonce from that client, so a second read must hit the same server
// and the websocket must still be open.
func TestIssue196_SharedContractNotClosedByNoOverrideCall(t *testing.T) {
	baseContract := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	srv := newWSServer(t)
	defer srv.close()

	g, issuerSigner := newTestGeneratorRPC(t, baseContract, srv.url, 111)
	before := srv.reads.Load()
	if srv.conns.Load() != 1 {
		t.Fatalf("shared client connections = %d, want 1", srv.conns.Load())
	}

	for i := 0; i < 2; i++ {
		if err := syncNonce(t, g, issuerSigner); err != nil {
			t.Fatalf("read %d: %v", i+1, err)
		}
	}
	if got := srv.reads.Load() - before; got < 2 {
		t.Fatalf("shared server reads = %d, want at least 2", got)
	}
	if srv.conns.Load() != 1 {
		t.Fatalf("shared client connections after two reads = %d, want 1", srv.conns.Load())
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
	c1, release1, err := g.resolveContract(context.Background(), &baseCfg, true)
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
	c2, release2, err := g.resolveContract(context.Background(), &overrideCfg, true)
	if err != nil {
		t.Fatalf("resolveContract (override): %v", err)
	}
	if c2 == g.didContract {
		t.Error("expected a new contract for override config, got shared")
	}
	release2() // closes the per-call client
	release2() // a second release must not panic
}

// TestIssue196_WithRPC_ReadUsesOverrideServer requires a SyncNonce read to
// reach only the per-call RPC, and the per-call websocket to be gone after
// the call returns. The shared client stays connected.
func TestIssue196_WithRPC_ReadUsesOverrideServer(t *testing.T) {
	baseContract := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	base := newWSServer(t)
	override := newWSServer(t)
	defer base.close()
	defer override.close()

	g, issuerSigner := newTestGeneratorRPC(t, baseContract, base.url, 111)
	baseBefore := base.reads.Load()
	if err := syncNonce(t, g, issuerSigner, WithRPC(override.url)); err != nil {
		t.Fatalf("SyncNonce via override RPC: %v", err)
	}
	if override.reads.Load() < 1 {
		t.Fatal("per-call RPC received no read")
	}
	if base.reads.Load() != baseBefore {
		t.Fatalf("base RPC reads changed by %d during an override call", base.reads.Load()-baseBefore)
	}
	waitConns(t, &override.conns, 0)
	if base.conns.Load() != 1 {
		t.Fatalf("shared connections = %d, want 1", base.conns.Load())
	}
}

func newTestGeneratorRPC(t *testing.T, contractAddr, rpcURL string, chainID int64) (*DIDGenerator, signer.SignerProvider) {
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
		WithRPC(rpcURL),
		WithIssuerSignerProvider(issuerSigner),
	)
	if err != nil {
		t.Fatalf("new generator: %v", err)
	}
	return g, issuerSigner
}

// syncNonce performs one SyncNonce read through GenerateDIDCreateTransaction.
func syncNonce(t *testing.T, g *DIDGenerator, issuerSigner signer.SignerProvider, opts ...DIDOption) error {
	t.Helper()
	didKey, err := did.GenerateECDSAKeyPair()
	if err != nil {
		return err
	}
	didSigner, err := signer.NewDefaultProvider(didKey.GetPrivateKeyHex())
	if err != nil {
		return err
	}
	didAddr, err := did.AddressFromPublicKeyHex(didKey.GetPublicKeyHex())
	if err != nil {
		return err
	}
	sig, err := g.GenerateIssuerSignature(t.Context(), did.DIDTypeItem, didAddr, issuerSigner.GetAddress())
	if err != nil {
		return err
	}
	callOpts := append([]DIDOption{
		WithSyncNonce(true),
		WithDIDSignerProvider(didSigner),
	}, opts...)
	_, err = g.GenerateDIDCreateTransaction(
		t.Context(), did.DIDTypeItem, "0x"+strings.Repeat("ab", 32),
		didAddr, issuerSigner.GetAddress(), sig, callOpts...,
	)
	return err
}

const createDIDABI = `[{"name":"createDID","type":"function","stateMutability":"nonpayable","inputs":[{"name":"issuer","type":"address"},{"name":"didType","type":"uint8"},{"name":"docHash","type":"bytes32"},{"name":"capId","type":"bytes32"},{"name":"v","type":"uint8"},{"name":"r","type":"bytes32"},{"name":"s","type":"bytes32"}]}]`

func assertIssuerSigBindsContract(t *testing.T, tx *types.Transaction, didIdentifier, issuerAddr, overrideContract, baseContract string) {
	t.Helper()
	parsed, err := abi.JSON(strings.NewReader(createDIDABI))
	if err != nil {
		t.Fatal(err)
	}
	out, err := parsed.Methods["createDID"].Inputs.Unpack(tx.Data()[4:])
	if err != nil {
		t.Fatalf("unpack createDID: %v", err)
	}
	capID := out[3].([32]byte)
	v := out[4].(uint8)
	r := out[5].([32]byte)
	s := out[6].([32]byte)
	sig := &issuer.Signature{V: big.NewInt(int64(v)), R: new(big.Int).SetBytes(r[:]), S: new(big.Int).SetBytes(s[:])}
	didAddr := strings.TrimPrefix(strings.ToLower(didIdentifier), DefaultMethod+":")
	payload := func(contract string) []byte {
		t.Helper()
		b, err := issuer.BuildIssueDIDPayload(&issuer.IssueDIDPayload{
			ContractAddress: contract,
			IssuerAddress:   issuerAddr,
			DidAddress:      didAddr,
			DidType:         did.DIDTypeItem,
			CapID:           "0x" + hex.EncodeToString(capID[:]),
		})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if got := recoverIssuer(t, payload(overrideContract), sig); !strings.EqualFold(got, issuerAddr) {
		t.Fatalf("tx signature recovers %s, want issuer %s for %s", got, issuerAddr, overrideContract)
	}
	if got := recoverIssuer(t, payload(baseContract), sig); strings.EqualFold(got, issuerAddr) {
		t.Fatal("tx signature also recovers the issuer for the base contract")
	}
}

func recoverIssuer(t *testing.T, payload []byte, sig *issuer.Signature) string {
	t.Helper()
	var packed [65]byte
	r, s := sig.R.Bytes(), sig.S.Bytes()
	copy(packed[32-len(r):32], r)
	copy(packed[64-len(s):64], s)
	packed[64] = byte(sig.V.Uint64() - 27)
	pub, err := crypto.SigToPub(crypto.Keccak256(payload), packed[:])
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	return crypto.PubkeyToAddress(*pub).Hex()
}

type wsRPC struct {
	url   string
	reads atomic.Int32
	conns atomic.Int32 // open now
	dials atomic.Int32 // opened in total
	close func()
}

func newWSServer(t *testing.T) *wsRPC {
	t.Helper()
	srv := &wsRPC{}
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		srv.dials.Add(1)
		srv.conns.Add(1)
		defer srv.conns.Add(-1)
		defer conn.Close()
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if strings.Contains(string(msg), "eth_getTransactionCount") {
				srv.reads.Add(1)
			}
			_ = conn.WriteMessage(websocket.TextMessage, rpcResult(msg))
		}
	}))
	srv.url = "ws" + strings.TrimPrefix(httpSrv.URL, "http")
	srv.close = httpSrv.Close
	return srv
}

func rpcResult(msg []byte) []byte {
	var one struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(msg, &one); err != nil || len(one.ID) == 0 {
		return []byte(`{"jsonrpc":"2.0","id":1,"result":"0x0"}`)
	}
	result := `"0x0"`
	if strings.Contains(string(msg), "eth_call") {
		// One ABI-encoded uint64 word, so getCapabilityEpoch decodes to 0.
		result = `"0x` + strings.Repeat("0", 64) + `"`
	}
	return []byte(`{"jsonrpc":"2.0","id":` + string(one.ID) + `,"result":` + result + `}`)
}

func waitConns(t *testing.T, n *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if n.Load() == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("connections = %d, want %d", n.Load(), want)
}

// TestIssue196_PerCallRPCDialHonoursContext checks that a per-call RPC override
// is dialled under the caller's context: a ws endpoint that accepts the TCP
// connection but never answers the handshake must not block past the deadline.
func TestIssue196_PerCallRPCDialHonoursContext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { conn.Close() })
		}
	}()

	g, issuerSigner := newTestGenerator(t, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 111)
	key, err := did.GenerateECDSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	capID, err := issuer.GenerateCapID()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = g.GenerateIssuerSignature(ctx, did.DIDTypeItem, key.GetAddress(), issuerSigner.GetAddress(),
			WithRPC("ws://"+ln.Addr().String()), WithCapID(capID), WithSyncEpoch(true))
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("GenerateIssuerSignature still blocked 5s after a 200ms deadline")
	}
}

// TestIssue196_NoReadNoDial checks that a per-call RPC is not dialled by a call
// that reads nothing from the chain, and that GenerateDIDTX dials it once when
// it reads both the epoch and the nonce.
func TestIssue196_NoReadNoDial(t *testing.T) {
	srv := newWSServer(t)
	t.Cleanup(srv.close)
	g, issuerSigner := newTestGenerator(t, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 111)
	key, err := did.GenerateECDSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := g.GenerateDID(t.Context(), did.DIDTypeItem, "", nil, WithRPC(srv.url)); err != nil {
		t.Fatalf("GenerateDID: %v", err)
	}
	if _, err := g.GenerateIssuerSignature(t.Context(), did.DIDTypeItem, key.GetAddress(), issuerSigner.GetAddress(), WithRPC(srv.url)); err != nil {
		t.Fatalf("GenerateIssuerSignature: %v", err)
	}
	if _, err := g.GenerateDID(t.Context(), did.DIDTypeItem, "", nil,
		WithRPC(srv.url), WithDIDAddressSMC("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")); err != nil {
		t.Fatalf("GenerateDID with a contract override: %v", err)
	}
	if got := srv.dials.Load(); got != 0 {
		t.Fatalf("dials without a chain read = %d, want 0", got)
	}

	if _, err := g.GenerateDID(t.Context(), did.DIDTypeItem, "", nil,
		WithRPC(srv.url), WithSyncNonce(true), WithSyncEpoch(true)); err != nil {
		t.Fatalf("GenerateDID with both syncs: %v", err)
	}
	if got := srv.reads.Load(); got < 1 {
		t.Fatalf("nonce reads = %d, want at least 1", got)
	}
	if got := srv.dials.Load(); got != 1 {
		t.Fatalf("dials for one GenerateDID that reads epoch and nonce = %d, want 1", got)
	}
}

// TestIssue196_PerCallChainOnly checks that a chain-ID override alone, with the
// base contract, signs the transaction for that chain (EIP-155).
func TestIssue196_PerCallChainOnly(t *testing.T) {
	baseContract := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	g, _ := newTestGenerator(t, baseContract, 111)

	res, err := g.GenerateDID(t.Context(), did.DIDTypeItem, "", nil, WithDIDChainID(999))
	if err != nil {
		t.Fatalf("GenerateDID: %v", err)
	}
	tx := decodeTx(t, res.Transaction.TxHex)
	if got := tx.ChainId().Int64(); got != 999 {
		t.Fatalf("tx.ChainId = %d, want 999", got)
	}
	sender, err := types.Sender(types.NewEIP155Signer(big.NewInt(999)), tx)
	if err != nil {
		t.Fatalf("recover sender for chain 999: %v", err)
	}
	if want := common.HexToAddress(strings.TrimPrefix(res.DID, "did:nda:")); sender != want {
		t.Errorf("tx sender = %s, want the DID address %s", sender.Hex(), want.Hex())
	}
}
