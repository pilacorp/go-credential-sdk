// Package issuer provides functionality for creating issuer signatures that authorize DID issuance.
//
// This package is used exclusively by Backend Issuer services to:
//   - Build EIP-191 compliant payloads for signing
//   - Generate issuer signatures using the Issuer's private key
//   - Create capability IDs for DID issuance
//
// The issuer signature proves that the Issuer authorizes the creation of a specific DID.
// This is a core component of the Issuer-centric DID model.
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

// GenerateIssueDIDSignature generates an issuer signature for authorizing DID issuance.
//
// This is the core function for creating issuer signatures. It:
//   - Validates the IssueDIDPayload
//   - Builds an EIP-191 compliant payload
//   - Hashes the payload using Keccak256
//   - Signs the hash using the issuer signer
//
// The issuer signature proves that the Issuer authorizes the creation of a specific DID.
// This signature is required for all DID creation transactions.
//
// The input parameter contains all the information needed to build the signature payload.
// The issuerSigner parameter must be a valid SignerProvider with the Issuer's private key.
//
// Returns a Signature containing R, S, V components, or an error if signing fails.
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

// BuildIssueDIDPayload builds an EIP-191 compliant payload for issuer signature.
//
// The payload is constructed as:
//   - EIP-191 prefix: 0x19 0x00
//   - Contract address (20 bytes)
//   - ABI-encoded packed data: action, issuerAddr, didAddr, didType, epoch, capID
//
// This format ensures the signature is bound to the specific contract and cannot
// be reused across different contracts or contexts.
//
// The input parameter is validated before building the payload.
// Returns the payload bytes ready for hashing and signing, or an error if validation fails.
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

// SignPayload signs the provided payload using the issuer signer.
//
// The payload should be the hash of the EIP-191 payload (from BuildIssueDIDPayload).
// The signature is normalized to Ethereum format (V = 27 or 28).
//
// Returns a Signature with R, S, V components, or an error if signing fails.
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

// GenerateCapID generates a random capability ID for DID issuance.
//
// The CapID is a 32-byte random value used to uniquely identify a specific
// DID issuance authorization. Issuers can revoke specific capabilities by
// revoking the CapID on-chain.
//
// Returns the CapID as a hex string (66 characters: "0x" + 64 hex digits),
// or an error if random generation fails.
func GenerateCapID() (string, error) {
	b := make([]byte, CapIDLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rand.Read failed: %w", err)
	}

	return "0x" + hex.EncodeToString(b), nil
}

// abiEncodePacked encodes values using Solidity's abi.encodePacked format (tight packing, no padding).
//
// This implements the same logic as Solidity's abi.encodePacked, which tightly packs
// values without padding. This is used for building the issuer signature payload.
//
// Supported types: string, address, uint8, uint16, uint32, uint64, uint256, bytes32.
//
// The types parameter is a list of Solidity type strings.
// The values parameter is a list of value strings (decimal for uint, hex for address/bytes32).
//
// Returns the tightly packed bytes, or an error if types/values mismatch or type is unsupported.
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
