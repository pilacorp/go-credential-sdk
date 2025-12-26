package blockchain

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// MaxAttributeNameLength defines the maximum length for attribute names (32 bytes).
const (
	MaxAttributeNameLength   = 32
	AttributeValiditySeconds = 86400
)

// SubmitTxResult represents a pre-built Ethereum transaction for DID operations.
// It is intentionally decoupled from any broadcasting logic so that callers can
// decide how and when to submit the transaction on-chain.
type SubmitTxResult struct {
	TxHex  string // Hex-encoded RLP transaction
	TxHash string // Transaction hash
}

func ParsePrivateKey(key string) (*ecdsa.PrivateKey, error) {
	key = strings.TrimPrefix(key, "0x")
	if len(key) == 0 || len(key)%2 != 0 {
		return nil, fmt.Errorf("invalid private key: empty or odd length")
	}
	privKey, err := crypto.HexToECDSA(key)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return privKey, nil
}

// prepareAttributeInputs validates and converts inputs for the SetAttribute call.
// It now accepts a *big.Int for validity.
func PrepareAttributeInputs(address, name, value string) (common.Address, [32]byte, []byte, *big.Int, error) {
	// Validate inputs
	if address == "" {
		return common.Address{}, [32]byte{}, nil, nil, fmt.Errorf("identity is empty")
	}
	if name == "" {
		return common.Address{}, [32]byte{}, nil, nil, fmt.Errorf("name is empty")
	}
	if len(name) > MaxAttributeNameLength {
		return common.Address{}, [32]byte{}, nil, nil, fmt.Errorf("name exceeds %d bytes", MaxAttributeNameLength)
	}

	// Convert identity to address
	didAddress := common.HexToAddress(strings.TrimPrefix(address, "0x"))

	// Convert name to fixed-size byte array
	var nameBytes [32]byte
	copy(nameBytes[:], name)

	// Convert value to bytes
	valueBytes := []byte(value)
	// Set validity
	validity := big.NewInt(AttributeValiditySeconds)

	// Validity is passed in, so we just return
	return didAddress, nameBytes, valueBytes, validity, nil
}

func TxFromHex(rawTxHex string) (*types.Transaction, error) {
	b, err := hex.DecodeString(rawTxHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %w", err)
	}
	var tx types.Transaction
	if err := rlp.DecodeBytes(b, &tx); err != nil {
		return nil, fmt.Errorf("failed to decode RLP: %w", err)
	}
	return &tx, nil
}

// SolidityPacked implements Solidity's abi.encodePacked function using go-ethereum's abi package.
// It tightly packs values according to their types without padding.
// Uses abi.Arguments and abi types for proper type handling.
func SolidityPacked(types []string, values []string) ([]byte, error) {
	if len(types) != len(values) {
		return nil, fmt.Errorf("types and values length mismatch")
	}

	// Create abi.Arguments from type strings
	arguments := make(abi.Arguments, len(types))
	for i, typeStr := range types {
		typ, err := abi.NewType(typeStr, "", nil)
		if err != nil {
			return nil, fmt.Errorf("invalid type %s: %w", typeStr, err)
		}
		arguments[i] = abi.Argument{Type: typ}
	}

	var result []byte

	for i, arg := range arguments {
		value := values[i]
		var encoded []byte

		switch arg.Type.T {
		case abi.StringTy:
			// String is encoded as UTF-8 bytes
			encoded = []byte(value)

		case abi.AddressTy:
			// Address is 20 bytes, use common.HexToAddress from go-ethereum
			addr := common.HexToAddress(value)
			encoded = addr.Bytes()

		case abi.UintTy:
			// Handle uint types according to Solidity's abi.encodePacked
			// uint8: 1 byte, uint16: 2 bytes, uint32: 4 bytes, uint64: 8 bytes, uint256: 32 bytes
			size := arg.Type.Size
			val, ok := new(big.Int).SetString(value, 10)
			if !ok {
				return nil, fmt.Errorf("invalid uint value: %s", value)
			}

			switch size {
			case 8: // uint8
				if val.Uint64() > 0xff {
					return nil, fmt.Errorf("value %s exceeds uint8 max value", value)
				}
				encoded = []byte{byte(val.Uint64())}
			case 16: // uint16
				if val.Uint64() > 0xffff {
					return nil, fmt.Errorf("value %s exceeds uint16 max value", value)
				}
				encoded = make([]byte, 2)
				valBytes := val.Bytes()
				copy(encoded[2-len(valBytes):], valBytes)
			case 32: // uint32
				if val.Uint64() > 0xffffffff {
					return nil, fmt.Errorf("value %s exceeds uint32 max value", value)
				}
				encoded = make([]byte, 4)
				valBytes := val.Bytes()
				copy(encoded[4-len(valBytes):], valBytes)
			case 64: // uint64
				if val.BitLen() > 64 {
					return nil, fmt.Errorf("value %s exceeds uint64 max value", value)
				}
				encoded = make([]byte, 8)
				valBytes := val.Bytes()
				copy(encoded[8-len(valBytes):], valBytes)
			case 256: // uint256
				encoded = make([]byte, 32)
				val.FillBytes(encoded)
			default:
				return nil, fmt.Errorf("unsupported uint size: %d", size)
			}

		case abi.FixedBytesTy:
			// bytes32 or other fixed bytes
			hexStr := strings.TrimPrefix(value, "0x")
			bytes32, err := hex.DecodeString(hexStr)
			if err != nil {
				return nil, fmt.Errorf("invalid bytes32 %s: %w", value, err)
			}
			if len(bytes32) != int(arg.Type.Size) {
				return nil, fmt.Errorf("bytes%d must be %d bytes, got %d", arg.Type.Size, arg.Type.Size, len(bytes32))
			}
			encoded = bytes32

		default:
			return nil, fmt.Errorf("unsupported type: %s", arg.Type.String())
		}

		result = append(result, encoded...)
	}

	return result, nil
}

// CreateEIP191Payload signs the payload using custom endorsement format.
// Format: concat(['0x1900', contractAddress, data])
func CreateEIP191Payload(smcAddress common.Address, payload []byte) ([]byte, error) {
	// Create dataToSign: concat(['0x1900', contractAddress, data])
	// 0x1900 prefix
	prefix := []byte{0x19, 0x00}

	// Contract address (20 bytes)
	addressBytes := smcAddress.Bytes()

	// Concatenate: 0x1900 + address + payload
	dataToSign := append(prefix, addressBytes...)
	dataToSign = append(dataToSign, payload...)

	return dataToSign, nil
}

// SignPayload signs the payload using EIP-191 standard.
// Returns signature in format: r (32 bytes) + s (32 bytes) + v (1 byte, recovery ID normalized to 27 or 28)
func SignPayload(privateKey *ecdsa.PrivateKey, payload []byte) ([]byte, error) {
	hash := crypto.Keccak256Hash(payload)

	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	// crypto.Sign returns signature with recovery ID (v) as 0 or 1
	// Normalize it to Ethereum format: 27 or 28
	// Signature format: r (32 bytes) + s (32 bytes) + v (1 byte)
	if len(signature) != 65 {
		return nil, fmt.Errorf("invalid signature length: expected 65 bytes, got %d", len(signature))
	}

	// Normalize recovery ID: 0 -> 27, 1 -> 28
	// so we need to normalize it to 27 or 28.
	v := signature[64]
	if v < 27 {
		v += 27
	}
	signature[64] = v

	return signature, nil
}

func ExtractSignature(signature []byte) (string, string, *big.Int, error) {
	if len(signature) != 65 {
		return "", "", nil, fmt.Errorf("invalid signature length: expected 65 bytes, got %d", len(signature))
	}

	r := hex.EncodeToString(signature[:32])
	s := hex.EncodeToString(signature[32:64])
	v := big.NewInt(int64(signature[64]))

	return r, s, v, nil
}

func BytesToSignature(signature []byte) (*Signature, error) {
	if len(signature) != 65 {
		return nil, fmt.Errorf("invalid signature length: expected 65 bytes, got %d", len(signature))
	}

	r := hex.EncodeToString(signature[:32])
	s := hex.EncodeToString(signature[32:64])
	v := big.NewInt(int64(signature[64]))

	rInt, ok := new(big.Int).SetString(r, 16)
	if !ok {
		return nil, fmt.Errorf("failed to convert r to big.Int")
	}

	sInt, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return nil, fmt.Errorf("failed to convert s to big.Int")
	}

	// normalize recovery id
	recoveryID := v.Uint64()
	if recoveryID == 0 || recoveryID == 1 {
		v = big.NewInt(int64(recoveryID + 27))
	}

	return &Signature{
		V: v,
		R: rInt,
		S: sInt,
	}, nil
}
