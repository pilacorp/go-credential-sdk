package did

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/pilacorp/go-credential-sdk/did/blockchain"
	"github.com/pilacorp/go-credential-sdk/did/signer"
)

const (
	defaultChainID    = int64(6789)
	defaultDIDAddress = "0x0000000000000000000000000000000000018888"
	defaultMethod     = "did:nda"
)

// DIDGenerator handles DID generation and transaction creation
type DIDGeneratorV2 struct {
	chainID    int64
	didAddress string
	method     string
	registry   *blockchain.EthereumDIDRegistryV2
}

// NewDIDGenerator creates a new DIDGenerator with default values
func NewDIDGeneratorV2(chainID int64, didAddress string, method string, rpcURL string) (*DIDGeneratorV2, error) {
	g := &DIDGeneratorV2{
		chainID:    defaultChainID,
		didAddress: defaultDIDAddress,
		method:     defaultMethod,
	}

	slog.Info("NewDIDGeneratorV2", "chainID", chainID, "didAddress", didAddress, "method", method, "rpcURL", rpcURL)

	if chainID != 0 {
		g.chainID = chainID
	}
	if didAddress != "" {
		g.didAddress = didAddress
	}
	if method != "" {
		g.method = method
	}

	registry, err := blockchain.NewEthereumDIDRegistryV2(g.didAddress, g.chainID, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create registry: %w", err)
	}
	g.registry = registry

	return g, nil
}

// GenerateDID generates a new DID with a newly created key pair
func (d *DIDGeneratorV2) GenerateDID(
	ctx context.Context,
	sigSigner signer.Signer, // signs the cap payload (signer in SMC)
	signerAddress string, // address param "signer" in createDID(...)
	didType blockchain.DIDType,
	hash string,
	capId string,
	epoch uint64,
	metadata map[string]interface{},
) (*DID, error) {

	// 1. Generate a new key pair (this DID will be msg.sender on-chain)
	keyPair, err := d.generateECDSADID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// 2. Generate DID document
	doc := d.generateDIDDocument(keyPair, didType, hash, metadata)

	// 3. Calculate document hash
	docHash, err := doc.Hash()
	if err != nil {
		return nil, fmt.Errorf("failed to hash DID document: %w", err)
	}

	// 4. Create payload to sign for _requireValidCapCreate(...)
	payload, err := d.registry.IssueDIDPayload(
		ctx,
		signerAddress,
		keyPair.Address, // did (msg.sender)
		didType,
		capId,
		epoch,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create payload: %w", err)
	}

	hashPayload := crypto.Keccak256(payload)

	slog.Info("hashPayload", "hashPayload", hex.EncodeToString(hashPayload))
	slog.Info("hashPayload", "hashPayload", hashPayload)
	slog.Info("payload", "payload", hex.EncodeToString(payload))

	// 5. Sign the payload using sigSigner (this becomes v,r,s)
	signatureBytes, err := sigSigner.Sign(hashPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	// verify signature again by build payload using BuildCapHash
	capIdBytes, err := ParseBytes32Hex(capId)
	if err != nil {
		return nil, fmt.Errorf("failed to parse capId: %w", err)
	}
	capHash := BuildCapHash(common.HexToAddress(d.didAddress), common.HexToAddress(signerAddress), common.HexToAddress(keyPair.Address), uint8(didType), big.NewInt(int64(epoch)), capIdBytes)
	recovered, ok, err := VerifyCapabilitySignature(common.HexToAddress(signerAddress), capHash, signatureBytes[64], [32]byte(signatureBytes[0:32]), [32]byte(signatureBytes[32:64]))
	if err != nil {
		return nil, fmt.Errorf("failed to verify signature: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("signature verification failed")
	}
	slog.Info("signature verified", "recovered", recovered.Hex())

	signature, err := blockchain.BytesToSignature(signatureBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert signature: %w", err)
	}

	// 6. Create transaction signer for msg.sender (the DID keypair)
	txSigner, err := signer.NewDefaultSigner(keyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create tx signer: %w", err)
	}

	// 7. Create DID transaction (matches new createDID signature)
	txResult, err := d.registry.CreateDIDTx(
		ctx,
		signature,
		signerAddress,   // signer param
		keyPair.Address, // msg.sender (did)
		docHash,
		capId,
		txSigner,
		didType,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create DID transaction: %w", err)
	}

	return &DID{
		DID: keyPair.Identifier,
		Secret: Secret{
			PrivateKeyHex: keyPair.PrivateKey,
		},
		Document: *doc,
		Transaction: blockchain.SubmitDIDTX{
			TxHex:  txResult.TxHex,
			TxHash: txResult.TxHash,
		},
	}, nil
}

// BuildCapHash builds the exact hash Solidity computes:
// keccak256(abi.encodePacked(0x19,0x00, contract, "CAP_CREATE", signer, did, didType(uint8), epoch(uint256), capId(bytes32)))
//
// NOTE: In your Solidity, _signerEpoch[signer] type is very likely uint256.
// Even if you store epoch as uint64 in Go, pack it as uint256 to match abi.encodePacked(uint256).
func BuildCapHash(
	contractAddr common.Address,
	signer common.Address,
	did common.Address,
	didType uint8,
	epoch *big.Int,
	capId [32]byte,
) common.Hash {
	// abi.encodePacked is just byte concatenation with fixed-size encoding:
	// - address: 20 bytes
	// - uint8: 1 byte
	// - uint256: 32 bytes (big-endian left padded)
	// - bytes32: 32 bytes
	// - string literal: raw UTF-8 bytes

	var b []byte
	b = append(b, 0x19, 0x00)
	b = append(b, contractAddr.Bytes()...)
	b = append(b, []byte("CAP_CREATE")...)
	b = append(b, signer.Bytes()...)
	b = append(b, did.Bytes()...)
	b = append(b, didType)

	epoch32 := common.LeftPadBytes(epoch.Bytes(), 32)
	b = append(b, epoch32...)

	b = append(b, capId[:]...)

	return crypto.Keccak256Hash(b)
}

// VerifyCapabilitySignature recovers address from (v,r,s) on capHash and compares to signer.
//
// Accepts v in {0,1,27,28}. Returns recovered address + ok.
func VerifyCapabilitySignature(
	signer common.Address,
	capHash common.Hash,
	v uint8,
	r [32]byte,
	s [32]byte,
) (common.Address, bool, error) {
	// go-ethereum SigToPub expects recovery id 0/1
	var recID byte
	switch v {
	case 27, 28:
		recID = v - 27
	case 0, 1:
		recID = v
	default:
		return common.Address{}, false, fmt.Errorf("invalid recovery id v=%d (expected 0/1 or 27/28)", v)
	}

	// Build 65-byte signature: r(32) || s(32) || recID(1)
	sig := make([]byte, 65)
	copy(sig[0:32], r[:])
	copy(sig[32:64], s[:])
	sig[64] = recID

	pub, err := crypto.SigToPub(capHash.Bytes(), sig)
	if err != nil {
		return common.Address{}, false, fmt.Errorf("SigToPub failed: %w", err)
	}
	recovered := crypto.PubkeyToAddress(*pub)

	return recovered, strings.EqualFold(recovered.Hex(), signer.Hex()), nil
}

// SenderFromTx returns msg.sender (from address) of the tx for a given chainId.
// This is the DID address in your createDID() (since did = msg.sender).
func SenderFromTx(tx *types.Transaction, chainID *big.Int) (common.Address, error) {
	signer := types.LatestSignerForChainID(chainID)
	from, err := types.Sender(signer, tx)
	if err != nil {
		return common.Address{}, err
	}
	return from, nil
}

// Convenience: verify directly from tx + inputs (signer param, didType, epoch, capId, v,r,s).
func VerifyCapFromTx(
	tx *types.Transaction,
	chainID *big.Int,
	contractAddr common.Address,
	signerParam common.Address, // address signer in createDID(...)
	didType uint8,
	epoch *big.Int,
	capId [32]byte,
	v uint8,
	r [32]byte,
	s [32]byte,
) (capHash common.Hash, did common.Address, recovered common.Address, ok bool, err error) {
	did, err = SenderFromTx(tx, chainID)
	if err != nil {
		return common.Hash{}, common.Address{}, common.Address{}, false, fmt.Errorf("cannot recover tx sender: %w", err)
	}

	capHash = BuildCapHash(contractAddr, signerParam, did, didType, epoch, capId)

	recovered, ok, err = VerifyCapabilitySignature(signerParam, capHash, v, r, s)
	if err != nil {
		return capHash, did, common.Address{}, false, err
	}
	return capHash, did, recovered, ok, nil
}

// Optional: verify a raw signatureBytes (65 bytes) produced by crypto.Sign(hash)
// NOTE: crypto.Sign returns v=0/1 already.
func VerifyFromSignatureBytes(
	signer common.Address,
	capHash common.Hash,
	sig65 []byte,
) (common.Address, bool, error) {
	if len(sig65) != 65 {
		return common.Address{}, false, fmt.Errorf("signature must be 65 bytes, got %d", len(sig65))
	}
	pub, err := crypto.SigToPub(capHash.Bytes(), sig65)
	if err != nil {
		return common.Address{}, false, err
	}
	recovered := crypto.PubkeyToAddress(*pub)
	return recovered, strings.EqualFold(recovered.Hex(), signer.Hex()), nil
}

// Helper to convert big.Int r/s to [32]byte
func BigToBytes32(x *big.Int) ([32]byte, error) {
	var out [32]byte
	if x.Sign() < 0 {
		return out, fmt.Errorf("negative big.Int")
	}
	b := x.Bytes()
	if len(b) > 32 {
		return out, fmt.Errorf("too large for bytes32: %d bytes", len(b))
	}
	copy(out[32-len(b):], b)
	return out, nil
}

// Helper to parse capId hex string to [32]byte
func ParseBytes32Hex(hexStr string) ([32]byte, error) {
	var out [32]byte
	s := strings.TrimPrefix(strings.TrimSpace(hexStr), "0x")
	if len(s) != 64 {
		return out, fmt.Errorf("capId must be 32 bytes hex (64 chars), got %d", len(s))
	}
	b := common.FromHex("0x" + s)
	if len(b) != 32 {
		return out, fmt.Errorf("decoded capId len=%d", len(b))
	}
	copy(out[:], b)
	return out, nil
}

// Optional sanity: ensure capHash you computed equals the "EIP-191 payload" approach you used earlier.
func BuildCapHashViaEIP191Payload(contractAddr common.Address, packedPayload []byte) common.Hash {
	// This matches: keccak256(0x19 0x00 contractAddr packedPayload...)
	buf := new(bytes.Buffer)
	buf.WriteByte(0x19)
	buf.WriteByte(0x00)
	buf.Write(contractAddr.Bytes())
	buf.Write(packedPayload)
	return crypto.Keccak256Hash(buf.Bytes())
}

// GetSignerEpoch gets the capability epoch of a signer
func (d *DIDGeneratorV2) GetCapabilityEpoch(ctx context.Context, signerAddress string) (uint64, error) {
	return d.registry.GetCapabilityEpoch(ctx, signerAddress)
}

// generateECDSADID generates a new ECDSA key pair and creates a KeyPair
func (d *DIDGeneratorV2) generateECDSADID() (*KeyPair, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	return d.createKeyPairFromECDSA(privateKey)
}

// deriveKeyPairFromPrivateKey derives a KeyPair from an existing private key hex string
func (d *DIDGeneratorV2) deriveKeyPairFromPrivateKey(privateKeyHex string) (*KeyPair, error) {
	privateKey, err := blockchain.ParsePrivateKey(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return d.createKeyPairFromECDSA(privateKey)
}

// createKeyPairFromECDSA creates a KeyPair from an ECDSA private key
func (d *DIDGeneratorV2) createKeyPairFromECDSA(privateKey *ecdsa.PrivateKey) (*KeyPair, error) {
	publicKeyECDSA, ok := privateKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to cast public key to ECDSA")
	}

	address := strings.ToLower(crypto.PubkeyToAddress(*publicKeyECDSA).Hex())
	privateKeyHex := strings.ToLower("0x" + fmt.Sprintf("%x", crypto.FromECDSA(privateKey)))
	publicKeyHex := strings.ToLower("0x" + fmt.Sprintf("%x", crypto.CompressPubkey(publicKeyECDSA)))
	identifier := strings.ToLower(fmt.Sprintf("%s:%s", d.method, address))

	return &KeyPair{
		Address:    address,
		PublicKey:  publicKeyHex,
		PrivateKey: privateKeyHex,
		Identifier: identifier,
	}, nil
}

// didTypeToString converts blockchain.DIDType to string representation
func (d *DIDGeneratorV2) didTypeToString(didType blockchain.DIDType) string {
	switch didType {
	case blockchain.DIDTypePeople:
		return "people"
	case blockchain.DIDTypeItem:
		return "item"
	case blockchain.DIDTypeActivity:
		return "activity"
	case blockchain.DIDTypeLocation:
		return "location"
	default:
		return "default"
	}
}

// generateDIDDocument creates a DID document from a key pair and request metadata
func (d *DIDGeneratorV2) generateDIDDocument(keyPair *KeyPair, didType blockchain.DIDType, hash string, metadata map[string]interface{}) *DIDDocument {
	docMetadata := make(map[string]interface{})

	// Copy existing metadata if present
	for k, v := range metadata {
		docMetadata[k] = v
	}

	// Always set type and hash
	docMetadata["type"] = d.didTypeToString(didType)
	docMetadata["hash"] = hash

	document := &DIDDocument{
		Context: []string{
			"https://w3id.org/security/v1",
			"https://www.w3.org/ns/did/v1",
		},
		Id:         keyPair.Identifier,
		Controller: keyPair.Identifier,
		VerificationMethod: []VerificationMethod{{
			Id:           keyPair.Identifier + "#key-1",
			Type:         "EcdsaSecp256k1VerificationKey2019",
			Controller:   keyPair.Identifier,
			PublicKeyHex: keyPair.PublicKey,
		}},
		Authentication:   []string{keyPair.Identifier + "#key-1"},
		AssertionMethod:  []string{keyPair.Identifier + "#key-1"},
		DocumentMetadata: docMetadata,
	}

	return document
}
