package didv2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-credential-sdk/didv2/blockchain"
)

// GenerateECDSAKeyPair generates a new ECDSA key pair and creates a KeyPair struct.
func GenerateECDSAKeyPair(method string) (*KeyPair, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	publicKeyECDSA, ok := privateKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("error casting public key to ECDSA")
	}
	address := strings.ToLower(crypto.PubkeyToAddress(*publicKeyECDSA).Hex())
	privateKeyHex := strings.ToLower("0x" + fmt.Sprintf("%x", crypto.FromECDSA(privateKey)))
	publicKeyHex := strings.ToLower("0x" + fmt.Sprintf("%x", crypto.CompressPubkey(publicKeyECDSA)))

	// Create DID identifier: ${method}:${address}
	identifier := strings.ToLower(fmt.Sprintf("%s:%s", method, address))

	return &KeyPair{
		Address:    address,
		PublicKey:  publicKeyHex,
		PrivateKey: privateKeyHex,
		Identifier: identifier,
	}, nil
}

// GenerateDIDDocument creates a DID document from a key pair and request metadata.
func GenerateDIDDocument(keyPair *KeyPair, didType blockchain.DIDType, hash string, metadata map[string]interface{}, signerDID string) *DIDDocument {
	docMetadata := make(map[string]interface{})
	for k, v := range metadata {
		docMetadata[k] = v
	}

	if didType.String() != "" {
		docMetadata["type"] = didType.String()
	}
	if hash != "" {
		docMetadata["hash"] = hash
	}

	return &DIDDocument{
		Context: []string{
			"https://w3id.org/security/v1",
			"https://www.w3.org/ns/did/v1",
		},
		Id:         keyPair.Identifier,
		Controller: signerDID,
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
}

// RandomHex returns random bytes as a 0x-prefixed hex string.
func RandomHex(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rand.Read failed: %w", err)
	}
	return "0x" + hex.EncodeToString(b), nil
}

// computeDSOPayload mimics the Solidity packing:
// keccak256(abi.encodePacked("CAP_CREATE", signer, did, type, epoch, capId))
func computeDSOPayload(signerAddr, didAddr string, didType blockchain.DIDType, capID string, epoch uint64) ([]byte, error) {
	const action = "CAP_CREATE"

	signerAddress := common.HexToAddress(signerAddr)
	didAddress := common.HexToAddress(didAddr)

	capID = strings.TrimPrefix(capID, "0x")
	capIDBytes, err := hex.DecodeString(capID)
	if err != nil || len(capIDBytes) != 32 {
		return nil, fmt.Errorf("invalid capID (must be 32 bytes hex): %v", err)
	}

	// Buffer estimation: Action(10) + Addr(20)*2 + Type(1) + Epoch(8) + CapID(32) = ~91 bytes
	buf := make([]byte, 0, 100)

	buf = append(buf, []byte(action)...)
	buf = append(buf, signerAddress.Bytes()...)
	buf = append(buf, didAddress.Bytes()...)
	buf = append(buf, byte(didType))

	// Epoch (Uint64 Big Endian)
	epochBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(epochBytes, epoch)
	buf = append(buf, epochBytes...)

	buf = append(buf, capIDBytes...)

	// Hash and apply EIP-191 prefix
	packedHash := crypto.Keccak256(buf)
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(packedHash))
	return crypto.Keccak256(append([]byte(prefix), packedHash...)), nil
}

// signatureFromBytes splits a raw 65-byte signature into R, S, V components.
func signatureFromBytes(sig []byte) (*blockchain.Signature, error) {
	if len(sig) != 65 {
		return nil, fmt.Errorf("signature must be 65 bytes, got %d", len(sig))
	}

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	v := new(big.Int).SetBytes(sig[64:])

	// Standardize V (Ethereum usually expects 27 or 28, but some libs produce 0 or 1)
	if v.Cmp(big.NewInt(1)) <= 0 {
		v.Add(v, big.NewInt(27))
	}

	return &blockchain.Signature{V: v, R: r, S: s}, nil
}
