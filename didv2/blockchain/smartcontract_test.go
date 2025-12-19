package blockchain

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateDIDSignature(t *testing.T) {
	contractAddr := common.HexToAddress("0x59bE1932048F76f9B0e8e5f6AcCf5Fd8D53136DD")
	registry := &EthereumDIDRegistry{
		contractAddr: contractAddr,
	}

	tests := []struct {
		name              string
		issuer            string
		issuerPrv         string
		did               string
		docHash           string
		didType           DIDType
		deadline          uint
		wantErr           bool
		validatePayload   func(t *testing.T, payload []byte, err error)
		validateSignature func(t *testing.T, signature []byte, err error)
	}{
		{
			name:      "Create DID signature",
			issuer:    "0x36e4418dafb9d1e5fff7408f5a57981e240c8f8e",
			issuerPrv: "0x8f49e4492f97ca6334e15117fc6c4c06f4652cac7fb27ed4ecc5ef9ea6ad5820",
			did:       "0xAC4885A9d09229DD2eA233Cd385a3171E0907906",
			docHash:   "0x1111111111111111111111111111111111111111111111111111111111111111",
			didType:   DIDTypePeople,
			deadline:  1765790363,
			wantErr:   false,
			validatePayload: func(t *testing.T, payload []byte, err error) {
				require.NoError(t, err)
				require.NotNil(t, payload)
				assert.Equal(t, "190059be1932048f76f9b0e8e5f6accf5fd8d53136dd4352454154455f44494436e4418dafb9d1e5fff7408f5a57981e240c8f8eac4885a9d09229dd2ea233cd385a3171e090790600111111111111111111111111111111111111111111111111111111111111111100000000000000000000000000000000000000000000000000000000693fd29b", hex.EncodeToString(payload))
			},
			validateSignature: func(t *testing.T, signature []byte, err error) {
				require.NoError(t, err)
				require.NotNil(t, signature)
				assert.Equal(t, "3e094f865d21875ed2e72cee73d3524059b5685bd1583ec203acee97bcc69c251d8a5a841787cae95ec40f9a99ab19551ff5bf61220850b56064f8dae2ddf6261b", hex.EncodeToString(signature))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := registry.IssueDIDPayload(tt.issuer, tt.did, tt.docHash, tt.didType, tt.deadline)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, payload)
			} else {
				if tt.validatePayload != nil {
					tt.validatePayload(t, payload, err)
				} else {
					require.NoError(t, err)
					require.NotNil(t, payload)
				}
			}

			privateKey, err := ParsePrivateKey(tt.issuerPrv)
			if err != nil {
				t.Fatalf("failed to parse private key: %v", err)
			}

			signature, err := SignPayload(privateKey, payload)
			if err != nil {
				t.Fatalf("failed to sign payload: %v", err)
			} else {
				if tt.validateSignature != nil {
					tt.validateSignature(t, signature, err)
				} else {
					require.NoError(t, err)
					require.NotNil(t, signature)
				}
			}

			r, s, v, err := ExtractSignature(signature)
			if err != nil {
				t.Fatalf("failed to extract r, s, v from signature: %v", err)
			} else {
				assert.Equal(t, "3e094f865d21875ed2e72cee73d3524059b5685bd1583ec203acee97bcc69c25", r)
				assert.Equal(t, "1d8a5a841787cae95ec40f9a99ab19551ff5bf61220850b56064f8dae2ddf626", s)
				assert.Equal(t, big.NewInt(27), v)
			}
		})
	}
}
