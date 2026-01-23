package issuer

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pilacorp/go-credential-sdk/didv2/did"
)

// CapCreateAction is the action for the issue DID.
const CapCreateAction = "CAP_CREATE"

// CapIDLength is the length of the cap ID.
// CapID is a 32 bytes hex string.
const CapIDLength = 32

// DefaultEpoch is the default epoch for the issue DID.
const DefaultEpoch = 0

// IssueDIDPayload is the payload for the issue DID.
//
// CapID presents the capability ID for this IssuerSignature created by IssueDIDPyload.
// issuer can revoke this capability by revoking the CapID.
// CapEpoch presents for all IssuerSignature created by this Issuer.
// issuer can revoke all IssuerSignature created by this Issuer by changing the CapEpoch onchain..
type IssueDIDPayload struct {
	ContractAddress string      `json:"contract_address"`
	IssuerAddress   string      `json:"issuer_address"`
	DidAddress      string      `json:"did_address"`
	DidType         did.DIDType `json:"did_type"`
	CapID           string      `json:"cap_id"`
	Epoch           uint64      `json:"epoch"`
}

// Signature is the signature created by issuer signer to sign the payload.
type Signature struct {
	V *big.Int
	R *big.Int
	S *big.Int
}

// Validate validates the issue DID payload.
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

// signatureFromBytes splits a raw 65-byte signature into R, S, V components.
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
