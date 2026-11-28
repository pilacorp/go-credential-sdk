package didcomm

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/pilacorp/go-credential-sdk/didcomm/jwe"
)

// GetFromKeys returns the 32-byte key two parties share for Encrypt and
// DecryptJWE. Each side passes the other's secp256k1 public key (hex,
// compressed or uncompressed) and its own 32-byte private key (hex): the
// sender the recipient's public key, the recipient the sender's. Both get
// the same key.
//
// The key is the Concat KDF of RFC 7518 §4.6.2 over the ECDH X coordinate,
// with AlgorithmID "A256GCM", empty PartyUInfo and PartyVInfo, and
// keydatalen 256. Both keys are static, so the key is the same for every
// message between the same two parties, and only they can derive it. That
// key may encrypt at most 2^32 messages (RFC 7518 §8.4); see Encrypt.
func GetFromKeys(peerPubHex, ownPrivHex string) ([]byte, error) {
	peerPubBytes, err := hex.DecodeString(peerPubHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}
	peerPubKey, err := secp256k1.ParsePubKey(peerPubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ownPrivBytes, err := hex.DecodeString(ownPrivHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}
	if len(ownPrivBytes) != 32 {
		return nil, fmt.Errorf("invalid private key: got %d bytes, want 32", len(ownPrivBytes))
	}
	var scalar secp256k1.ModNScalar
	if overflow := scalar.SetByteSlice(ownPrivBytes); overflow || scalar.IsZero() {
		return nil, errors.New("invalid private key: not in [1, n-1]")
	}

	z := secp256k1.GenerateSharedSecret(secp256k1.NewPrivateKey(&scalar), peerPubKey)

	return concatKDF(z, jwe.Encryption, nil, nil, 8*keySize), nil
}

// concatKDF is the single-step KDF of NIST SP 800-56A §5.8.1 with SHA-256,
// with OtherInfo laid out as RFC 7518 §4.6.2 specifies. keyBits must be a
// multiple of 8.
func concatKDF(z []byte, algorithmID string, apu, apv []byte, keyBits int) []byte {
	otherInfo := lengthPrefixed(nil, []byte(algorithmID))
	otherInfo = lengthPrefixed(otherInfo, apu)
	otherInfo = lengthPrefixed(otherInfo, apv)
	otherInfo = binary.BigEndian.AppendUint32(otherInfo, uint32(keyBits))

	var out []byte
	for counter := uint32(1); len(out)*8 < keyBits; counter++ {
		h := sha256.New()
		h.Write(binary.BigEndian.AppendUint32(nil, counter))
		h.Write(z)
		h.Write(otherInfo)
		out = h.Sum(out)
	}

	return out[:keyBits/8]
}

func lengthPrefixed(dst, data []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(data)))
	return append(dst, data...)
}
