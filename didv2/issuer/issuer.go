package issuer

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-credential-sdk/didv2/signer"
)

// GenerateIssueDIDSignature generates an issue DID signature.
func GenerateIssueDIDSignature(input *IssueDIDPayload, issuerSigner signer.SignerProvider) (*Signature, error) {
	if issuerSigner == nil {
		return nil, fmt.Errorf("issuer signer is required")
	}

	// 1. Build issue DID payload.
	payload, err := BuildIssueDIDPayload(input)
	if err != nil {
		return nil, err
	}

	// 2. Hash payload.
	hashPayload := crypto.Keccak256Hash(payload)

	// 3. Sign payload.
	return SignPayload(hashPayload.Bytes(), issuerSigner)
}

// BuildIssueDIDPayload builds the issue DID payload.
func BuildIssueDIDPayload(input *IssueDIDPayload) ([]byte, error) {
	// 1. Validate input
	if err := input.Validate(); err != nil {
		return nil, err
	}

	// 2. Build issue DID payload
	payload, err := abiEncodePacked(
		[]string{"string", "address", "address", "uint8", "uint64", "bytes32"},
		[]string{CapCreateAction, input.IssuerAddress, input.DidAddress, strconv.Itoa(int(input.DidType)), strconv.Itoa(int(input.Epoch)), input.CapID},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encode payload to issue DID payload: %w", err)
	}

	// 3. Create EIP-191 payload
	prefix := []byte{0x19, 0x00}
	addressBytes := common.HexToAddress(input.ContractAddress).Bytes()
	dataToSign := append(prefix, addressBytes...)
	dataToSign = append(dataToSign, payload...)

	return dataToSign, nil
}

// SignPayload signs the issue DID payload.
func SignPayload(
	payload []byte,
	issuerSigner signer.SignerProvider,
) (*Signature, error) {
	sigBytes, err := issuerSigner.Sign(payload)
	if err != nil {
		return nil, err
	}

	issuerSig, err := signatureFromBytes(sigBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid signature format: %w", err)
	}

	return issuerSig, nil
}

// GenerateCapID generates a random cap ID.
//
// CapID is a 32 bytes hex string.
func GenerateCapID() (string, error) {
	b := make([]byte, CapIDLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rand.Read failed: %w", err)
	}

	return "0x" + hex.EncodeToString(b), nil
}

// abiEncodePacked encodes values according to their types using abi.encodePacked.
//
// types is a list of type strings.
// values is a list of value strings.
// Returns the encoded bytes or an error if the types and values length mismatch or the type is invalid.
func abiEncodePacked(types []string, values []string) ([]byte, error) {
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
