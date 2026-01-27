package issuer

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pilacorp/go-credential-sdk/didv2/did"
)

// CapCreateAction is the action string used in issuer signature payloads.
const CapCreateAction = "CAP_CREATE"

// CapIDLength is the byte length of a capability ID (32 bytes = 64 hex characters + "0x" prefix = 66 total).
const CapIDLength = 32

// DefaultEpoch is the default capability epoch value (0).
const DefaultEpoch = 0

// IssueDIDPayload contains all the information needed to create an issuer signature.
//
// The payload is used to build an EIP-191 compliant message that is signed by the Issuer.
// This signature proves the Issuer's authorization to create a specific DID.
//
// Capability-based revocation:
//   - CapID: Unique identifier for this specific issuance. Can be revoked individually.
//   - Epoch: Global epoch for all signatures from this Issuer. Changing epoch revokes all previous signatures.
type IssueDIDPayload struct {
	// ContractAddress is the address of the DID Registry smart contract.
	ContractAddress string `json:"contract_address"`
	// IssuerAddress is the Ethereum address of the Issuer.
	IssuerAddress string `json:"issuer_address"`
	// DidAddress is the Ethereum address of the DID being issued.
	DidAddress string `json:"did_address"`
	// DidType specifies the type of DID (People, Item, Location, Activity).
	DidType did.DIDType `json:"did_type"`
	// CapID is a 32-byte capability ID for this specific issuance (hex string with "0x" prefix).
	// If empty, a random CapID is automatically generated.
	CapID string `json:"cap_id"`
	// Epoch is the capability epoch for issuer signature validation.
	// Defaults to 0 if not set. Can be synced from blockchain.
	Epoch uint64 `json:"epoch"`
}

// Signature represents an ECDSA signature with R, S, V components.
//
// This is the format used for issuer signatures in DID creation transactions.
// The signature is created by signing an EIP-191 payload with the Issuer's private key.
type Signature struct {
	// V is the recovery ID (27 or 28 for Ethereum).
	V *big.Int
	// R is the first 32 bytes of the signature.
	R *big.Int
	// S is the second 32 bytes of the signature.
	S *big.Int
}

// Validate validates the IssueDIDPayload to ensure all required fields are present and valid.
//
// Checks:
//   - ContractAddress is a valid hex address
//   - IssuerAddress is a valid hex address
//   - DidAddress is a valid hex address
//   - CapID is exactly 66 characters (32 bytes in hex with "0x" prefix)
//
// Returns an error if any validation fails.
func (p *IssueDIDPayload) Validate() error {
	if !common.IsHexAddress(p.ContractAddress) {
		return fmt.Errorf("invalid contract address: %s", p.ContractAddress)
	}

	if !common.IsHexAddress(p.IssuerAddress) {
		return fmt.Errorf("invalid issuer address: %s", p.IssuerAddress)
	}

	if !common.IsHexAddress(p.DidAddress) {
		return fmt.Errorf("invalid did address: %s", p.DidAddress)
	}

	// +2 for "0x" prefix.
	if len(p.CapID) != CapIDLength*2+2 {
		return fmt.Errorf("invalid cap id length: expected %d, got %d", CapIDLength, len(p.CapID))
	}

	return nil
}

// signatureFromBytes parses a raw 65-byte signature into R, S, V components.
//
// The signature format is: [R (32 bytes)][S (32 bytes)][V (1 byte)].
// The V component is normalized to 27 or 28 for Ethereum compatibility.
// Returns a Signature struct or an error if the signature format is invalid.
func signatureFromBytes(sig []byte) (*Signature, error) {
	if len(sig) != 65 {
		return nil, fmt.Errorf("signature must be 65 bytes, got %d", len(sig))
	}

	// Normalize recovery ID to 27 or 28.
	// Because crypto.Sign returns signature with recovery ID (v) as 0 or 1 but Ethereum expects 27 or 28.
	v := sig[64]
	if v < 27 {
		v += 27
	}

	sig[64] = v

	rInt := new(big.Int).SetBytes(sig[:32])
	sInt := new(big.Int).SetBytes(sig[32:64])
	vInt := new(big.Int).SetBytes(sig[64:])

	return &Signature{V: vInt, R: rInt, S: sInt}, nil
}
