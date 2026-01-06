package didv2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
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
func computeDSOPayload(contractAddr common.Address, signerAddr, didAddr string, didType blockchain.DIDType, capID string, epoch uint64) ([]byte, error) {
	// Normalize bytes32 hex inputs
	capID = strings.TrimSpace(capID)
	if !strings.HasPrefix(capID, "0x") {
		capID = "0x" + capID
	}
	// Basic sanity: bytes32 is 32 bytes = 64 hex chars + "0x" => len 66
	if len(capID) != 66 {
		return nil, fmt.Errorf("invalid capId length: expected bytes32 hex (66 chars with 0x), got %d", len(capID))
	}

	// IMPORTANT: this action string must match the contract verifier exactly.
	const Action = "CAP_CREATE"

	payload, err := blockchain.SolidityPacked(
		[]string{"string", "address", "address", "uint8", "uint64", "bytes32"},
		[]string{Action, signerAddr, didAddr, strconv.Itoa(int(didType)), strconv.FormatUint(epoch, 10), capID},
	)

	if err != nil {
		return nil, fmt.Errorf("failed to pack solidity values: %w", err)
	}

	// Same EIP-191 wrapper you used previously
	dataToSign, err := blockchain.CreateEIP191Payload(contractAddr, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to create EIP-191 payload: %w", err)
	}

	return crypto.Keccak256(dataToSign), nil
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
