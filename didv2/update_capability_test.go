package didv2

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/pilacorp/go-credential-sdk/didv2/did"
	"github.com/pilacorp/go-credential-sdk/didv2/issuer"
	"github.com/pilacorp/go-credential-sdk/didv2/signer"
)

const testCapID = "0x1111111111111111111111111111111111111111111111111111111111111111"

func newSigner(t *testing.T) signer.SignerProvider {
	t.Helper()

	kp, err := did.GenerateECDSAKeyPair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	s, err := signer.NewDefaultProvider(kp.GetPrivateKeyHex())
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	return s
}

// capUpdateHash is DIdRegistry._requireValidCapUpdate's hash, built byte by byte
// from the contract source rather than through the SDK's packer:
//
//	keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x00), address(this),
//	    "CAP_UPDATE", signer, did, _signerEpoch[signer] /* uint64 */, capId))
func capUpdateHash(registry, signerAddr, didAddr string, epoch uint64, capID string) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x19, 0x00})
	buf.Write(common.HexToAddress(registry).Bytes())
	buf.WriteString("CAP_UPDATE")
	buf.Write(common.HexToAddress(signerAddr).Bytes())
	buf.Write(common.HexToAddress(didAddr).Bytes())

	var e [8]byte
	binary.BigEndian.PutUint64(e[:], epoch)
	buf.Write(e[:])

	id, _ := hex.DecodeString(strings.TrimPrefix(capID, "0x"))
	buf.Write(id)

	return crypto.Keccak256(buf.Bytes())
}

// recoverSigner is what ECDSA.recover gives the contract for (v, r, s).
func recoverSigner(t *testing.T, hash []byte, sig *issuer.Signature) common.Address {
	t.Helper()

	raw := make([]byte, 65)
	sig.R.FillBytes(raw[:32])
	sig.S.FillBytes(raw[32:64])
	raw[64] = byte(sig.V.Uint64() - 27)

	pub, err := crypto.SigToPub(hash, raw)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}

	return crypto.PubkeyToAddress(*pub)
}

// authen-service#636 S3: the capability recovers to the issuer over the hash the
// contract computes, at a non-zero epoch so the uint64 packing is exercised.
// The creation signature over the same inputs does not, which is why the
// update needs its own: the contract would revert InvalidCapabilitySignature.
func TestUpdateCapabilityRecoversToTheIssuerOverTheContractsHash(t *testing.T) {
	issuerSigner := newSigner(t)
	didSigner := newSigner(t)

	g, err := NewDIDGenerator(WithIssuerSignerProvider(issuerSigner))
	if err != nil {
		t.Fatalf("new generator: %v", err)
	}

	capability, err := g.GenerateUpdateCapability(context.Background(), didSigner.GetAddress(),
		WithCapID(testCapID), WithEpoch(7))
	if err != nil {
		t.Fatalf("GenerateUpdateCapability: %v", err)
	}

	hash := capUpdateHash(DefaultDIDSMCAddress, issuerSigner.GetAddress(), didSigner.GetAddress(), 7, testCapID)

	if got := recoverSigner(t, hash, capability.Signature); got != common.HexToAddress(issuerSigner.GetAddress()) {
		t.Fatalf("capability recovers to %s, want the issuer %s", got.Hex(), issuerSigner.GetAddress())
	}

	if capability.CapID != testCapID || !strings.EqualFold(capability.IssuerAddress, issuerSigner.GetAddress()) {
		t.Fatalf("capability carries cap %s issuer %s", capability.CapID, capability.IssuerAddress)
	}

	creation, err := g.GenerateIssuerSignature(context.Background(), did.DIDTypePeople,
		didSigner.GetAddress(), issuerSigner.GetAddress(), WithCapID(testCapID), WithEpoch(7))
	if err != nil {
		t.Fatalf("GenerateIssuerSignature: %v", err)
	}

	if got := recoverSigner(t, hash, creation); got == common.HexToAddress(issuerSigner.GetAddress()) {
		t.Fatal("a CAP_CREATE signature recovers to the issuer over the CAP_UPDATE hash")
	}
}

// A signer for one address cannot sign a capability naming another as issuer:
// the payload would claim an authority whose key did not sign it.
// A capability id the contract cannot read as bytes32 would be signed and then
// fail on chain; it is refused before signing.
func TestUpdateCapabilityRefusesACapIDThatIsNotHex(t *testing.T) {
	issuerSigner := newSigner(t)

	_, err := issuer.GenerateUpdateCapabilitySignature(&issuer.UpdateCapabilityPayload{
		ContractAddress: DefaultDIDSMCAddress,
		IssuerAddress:   issuerSigner.GetAddress(),
		DidAddress:      newSigner(t).GetAddress(),
		CapID:           "0x" + strings.Repeat("z", 64),
	}, issuerSigner)
	if err == nil {
		t.Fatal("signed a capability whose id is not hex")
	}

	// The creation capability is held to the same rule.
	_, err = issuer.GenerateIssueDIDSignature(&issuer.IssueDIDPayload{
		ContractAddress: DefaultDIDSMCAddress,
		IssuerAddress:   issuerSigner.GetAddress(),
		DidAddress:      newSigner(t).GetAddress(),
		CapID:           "0x" + strings.Repeat("z", 64),
	}, issuerSigner)
	if err == nil {
		t.Fatal("signed a creation capability whose id is not hex")
	}
}

func TestUpdateCapabilitySignatureRefusesASignerForAnotherIssuer(t *testing.T) {
	_, err := issuer.GenerateUpdateCapabilitySignature(&issuer.UpdateCapabilityPayload{
		ContractAddress: DefaultDIDSMCAddress,
		IssuerAddress:   newSigner(t).GetAddress(),
		DidAddress:      newSigner(t).GetAddress(),
		CapID:           testCapID,
	}, newSigner(t))
	if err == nil {
		t.Fatal("signed a capability for an issuer the signer is not")
	}
}

// decodeCall reads a raw tx the way did-registrar does: sender, chain id, nonce,
// method and arguments.
func decodeCall(t *testing.T, txHex string) (common.Address, *types.Transaction, string, []any) {
	t.Helper()

	raw, err := hex.DecodeString(strings.TrimPrefix(txHex, "0x"))
	if err != nil {
		t.Fatalf("hex: %v", err)
	}

	var tx types.Transaction
	if err := rlp.DecodeBytes(raw, &tx); err != nil {
		t.Fatalf("rlp: %v", err)
	}

	sender, err := types.Sender(types.NewEIP155Signer(tx.ChainId()), &tx)
	if err != nil {
		t.Fatalf("sender: %v", err)
	}

	contractABI := registryABI(t)

	method, err := contractABI.MethodById(tx.Data()[:4])
	if err != nil {
		t.Fatalf("method: %v", err)
	}

	args, err := method.Inputs.Unpack(tx.Data()[4:])
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}

	return sender, &tx, method.Name, args
}

// registryABI reads the contract ABI from the artifact the SDK embeds, the way
// did-registrar reads its own copy, without going through the SDK's loader.
func registryABI(t *testing.T) abi.ABI {
	t.Helper()

	raw, err := os.ReadFile("didcontract/did_registry_smc_abi.json")
	if err != nil {
		t.Fatalf("read abi: %v", err)
	}

	var artifact struct {
		ABI json.RawMessage `json:"abi"`
	}
	if err := json.Unmarshal(raw, &artifact); err != nil {
		t.Fatalf("artifact: %v", err)
	}

	parsed, err := abi.JSON(bytes.NewReader(artifact.ABI))
	if err != nil {
		t.Fatalf("abi: %v", err)
	}

	return parsed
}

func bytes32(s string) [32]byte {
	var b [32]byte
	copy(b[:], s)

	return b
}

const testDocHash = "0x2222222222222222222222222222222222222222222222222222222222222222"

// S2: the DID sends setAttribute carrying the capability as signed, with the
// issuer as the contract's signer argument.
func TestSetAttributeTransactionCarriesTheCapability(t *testing.T) {
	issuerSigner := newSigner(t)
	didSigner := newSigner(t)

	g, err := NewDIDGenerator(WithIssuerSignerProvider(issuerSigner), WithDIDChainID(704))
	if err != nil {
		t.Fatalf("new generator: %v", err)
	}

	capability, err := g.GenerateUpdateCapability(context.Background(), didSigner.GetAddress(), WithCapID(testCapID))
	if err != nil {
		t.Fatalf("GenerateUpdateCapability: %v", err)
	}

	value := []byte(`{"k":"0x02aa","p":["auth"]}`)

	tx, err := g.GenerateSetAttributeTransaction(context.Background(), testDocHash, "key/2", value, capability,
		WithDIDSignerProvider(didSigner), WithNonce(7))
	if err != nil {
		t.Fatalf("GenerateSetAttributeTransaction: %v", err)
	}

	sender, raw, method, args := decodeCall(t, tx.TxHex)

	if sender != common.HexToAddress(didSigner.GetAddress()) {
		t.Errorf("sender %s, want the DID %s", sender.Hex(), didSigner.GetAddress())
	}
	if raw.ChainId().Cmp(big.NewInt(704)) != 0 || raw.Nonce() != 7 {
		t.Errorf("chain %s nonce %d, want 704 and 7", raw.ChainId(), raw.Nonce())
	}
	if method != "setAttribute" {
		t.Fatalf("method %s", method)
	}
	if args[0].(common.Address) != common.HexToAddress(issuerSigner.GetAddress()) {
		t.Errorf("signer argument %s, want the issuer", args[0].(common.Address).Hex())
	}
	if args[1].([32]byte) != bytes32("key/2") || !bytes.Equal(args[2].([]byte), value) {
		t.Errorf("attribute %q %q", args[1], args[2])
	}
	if common.Hash(args[3].([32]byte)).Hex() != testDocHash || common.Hash(args[4].([32]byte)).Hex() != testCapID {
		t.Errorf("docHash %x capId %x", args[3], args[4])
	}
	r, sv := args[6].([32]byte), args[7].([32]byte)
	if uint64(args[5].(uint8)) != capability.Signature.V.Uint64() ||
		new(big.Int).SetBytes(r[:]).Cmp(capability.Signature.R) != 0 ||
		new(big.Int).SetBytes(sv[:]).Cmp(capability.Signature.S) != 0 {
		t.Error("v, r, s do not match the capability")
	}
}

// The contract takes the DID from the tx sender, so a capability signed for
// another DID would revert after a nonce is spent. It is refused here.
func TestSetAttributeTransactionRefusesACapabilityForAnotherDID(t *testing.T) {
	issuerSigner := newSigner(t)

	g, err := NewDIDGenerator(WithIssuerSignerProvider(issuerSigner))
	if err != nil {
		t.Fatalf("new generator: %v", err)
	}

	capability, err := g.GenerateUpdateCapability(context.Background(), newSigner(t).GetAddress(), WithCapID(testCapID))
	if err != nil {
		t.Fatalf("GenerateUpdateCapability: %v", err)
	}

	_, err = g.GenerateSetAttributeTransaction(context.Background(), testDocHash, "key/2", []byte(`{"k":"0x02aa","p":[]}`),
		capability, WithDIDSignerProvider(newSigner(t)))
	if err == nil {
		t.Fatal("signed setAttribute under a capability for another DID")
	}
}

// S1: the issuer sends setAttributeByIssuer naming the DID.
func TestSetAttributeByIssuerTransactionNamesTheDID(t *testing.T) {
	issuerSigner := newSigner(t)
	didAddr := newSigner(t).GetAddress()

	g, err := NewDIDGenerator(WithIssuerSignerProvider(issuerSigner), WithDIDChainID(704))
	if err != nil {
		t.Fatalf("new generator: %v", err)
	}

	value := []byte(`{"k":"0x02aa","p":["auth"]}`)

	tx, err := g.GenerateSetAttributeByIssuerTransaction(context.Background(), testDocHash, didAddr, "key/2", value, WithNonce(7))
	if err != nil {
		t.Fatalf("GenerateSetAttributeByIssuerTransaction: %v", err)
	}

	sender, raw, method, args := decodeCall(t, tx.TxHex)

	if sender != common.HexToAddress(issuerSigner.GetAddress()) || raw.Nonce() != 7 || raw.ChainId().Int64() != 704 {
		t.Errorf("sender %s nonce %d chain %s", sender.Hex(), raw.Nonce(), raw.ChainId())
	}
	if method != "setAttributeByIssuer" ||
		args[0].(common.Address) != common.HexToAddress(didAddr) ||
		args[1].([32]byte) != bytes32("key/2") ||
		!bytes.Equal(args[2].([]byte), value) ||
		common.Hash(args[3].([32]byte)).Hex() != testDocHash {
		t.Errorf("%s(%v)", method, args)
	}
}

// An attribute name the contract would truncate, or an empty value, is refused
// before signing: either reaches the chain and did-registrar refuses it after.
func TestSetAttributeRequestsRefuseWhatTheRegistrarWould(t *testing.T) {
	g, err := NewDIDGenerator(WithIssuerSignerProvider(newSigner(t)))
	if err != nil {
		t.Fatalf("new generator: %v", err)
	}

	didAddr := newSigner(t).GetAddress()

	for name, tc := range map[string]struct {
		docHash string
		attr    string
		value   []byte
	}{
		"name over 32 bytes": {testDocHash, strings.Repeat("k", 33), []byte("v")},
		"empty name":         {testDocHash, "", []byte("v")},
		"empty value":        {testDocHash, "key/1", nil},
		"docHash not hex":    {"0x" + strings.Repeat("g", 64), "key/1", []byte("v")},
	} {
		if _, err := g.GenerateSetAttributeByIssuerTransaction(context.Background(), tc.docHash, didAddr, tc.attr, tc.value); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}
