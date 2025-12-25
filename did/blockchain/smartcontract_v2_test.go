package blockchain

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssueDIDPayload(t *testing.T) {
	contractAddr := "0x6aD11619F8912f800A6f5CF05BD63Bb60e7ad160"
	chainID := int64(704)
	rpcURL := "http://localhost:8545"

	registry, err := NewEthereumDIDRegistryV2(contractAddr, chainID, rpcURL)
	if err != nil {
		t.Skipf("Skipping test due to RPC connection error: %v", err)
	}

	signerAddress := "0x2036C6CD85692F0Fb2C26E6c6B2ECed9e4478Dfd"
	didAddress := "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
	didType := DIDTypePeople
	capId := "0x1111111111111111111111111111111111111111111111111111111111111111"
	epoch := uint64(0)
	privateKeyHex := "0xa285ab66393c5fdda46d6fbad9e27fafd438254ab72ad5acb681a0e9f20f5d7b"

	ctx := context.Background()
	payload, err := registry.IssueDIDPayload(ctx, signerAddress, didAddress, didType, capId, epoch)

	require.NoError(t, err)
	require.NotNil(t, payload)
	require.GreaterOrEqual(t, len(payload), 22, "Payload should have at least 22 bytes (0x1900 + contract address)")

	// Verify EIP-191 structure: 0x1900 + contract address
	assert.Equal(t, byte(0x19), payload[0], "First byte should be 0x19")
	assert.Equal(t, byte(0x00), payload[1], "Second byte should be 0x00")

	contractAddrBytes := common.HexToAddress(contractAddr).Bytes()
	assert.Equal(t, contractAddrBytes, payload[2:22], "Contract address should match")

	t.Logf("Payload (hex): %s", hex.EncodeToString(payload))

	// Sign payload với private key
	privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(privateKeyHex, "0x"))
	require.NoError(t, err)

	// Verify private key matches signer address
	pubKeyFromPriv := privateKey.Public()
	pubKeyECDSA, ok := pubKeyFromPriv.(*ecdsa.PublicKey)
	require.True(t, ok, "Failed to get public key")

	addrFromPriv := crypto.PubkeyToAddress(*pubKeyECDSA)
	expectedSignerAddr := common.HexToAddress(signerAddress)
	assert.Equal(t, strings.ToLower(expectedSignerAddr.Hex()), strings.ToLower(addrFromPriv.Hex()),
		"Address from private key should match signer address")

	// Hash payload và ký
	payloadHash := crypto.Keccak256Hash(payload)
	signatureBytes, err := crypto.Sign(payloadHash.Bytes(), privateKey)
	require.NoError(t, err)
	require.Len(t, signatureBytes, 65, "Signature should be 65 bytes")

	// Normalize signature: crypto.Sign returns v = 0/1, normalize to 27/28
	v := signatureBytes[64]
	if v < 27 {
		v += 27
		signatureBytes[64] = v
	}

	// Extract r, s, v từ signature
	r, s, vBig, err := ExtractSignature(signatureBytes)
	require.NoError(t, err)
	require.Len(t, r, 64, "r should be 64 hex chars (32 bytes)")
	require.Len(t, s, 64, "s should be 64 hex chars (32 bytes)")
	assert.True(t, vBig.Uint64() == 27 || vBig.Uint64() == 28, "v should be 27 or 28")

	// Convert to Signature struct
	sig, err := BytesToSignature(signatureBytes)
	require.NoError(t, err)
	require.NotNil(t, sig)
	assert.NotNil(t, sig.R, "Signature R should not be nil")
	assert.NotNil(t, sig.S, "Signature S should not be nil")
	assert.NotNil(t, sig.V, "Signature V should not be nil")

	// Verify signature bằng cách recover public key (sử dụng v = 0/1 cho recovery)
	recoveryID := vBig.Uint64() - 27
	sigBytesForRecovery := make([]byte, 65)
	copy(sigBytesForRecovery[0:32], signatureBytes[0:32])
	copy(sigBytesForRecovery[32:64], signatureBytes[32:64])
	sigBytesForRecovery[64] = byte(recoveryID)

	pubKey, err := crypto.SigToPub(payloadHash.Bytes(), sigBytesForRecovery)
	require.NoError(t, err)
	recoveredAddr := crypto.PubkeyToAddress(*pubKey)
	assert.Equal(t, strings.ToLower(expectedSignerAddr.Hex()), strings.ToLower(recoveredAddr.Hex()),
		"Recovered address from signature should match signer address")

	t.Logf("Signature (hex): %s", hex.EncodeToString(signatureBytes))
	t.Logf("r: 0x%s", r)
	t.Logf("s: 0x%s", s)
	t.Logf("v: %s", vBig.String())
}
