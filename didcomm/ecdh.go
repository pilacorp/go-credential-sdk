package didcomm

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func GetFromKeys(senderPubHex, receiverPrivHex string) ([]byte, error) {
	senderPubBytes, err := hex.DecodeString(senderPubHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode sender public key: %v", err)
	}
	senderPubKey, err := secp256k1.ParsePubKey(senderPubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse sender public key: %v", err)
	}

	receiverPrivBytes, err := hex.DecodeString(receiverPrivHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode receiver private key: %v", err)
	}
	receiverPrivKey := secp256k1.PrivKeyFromBytes(receiverPrivBytes)

	sharedRecipient := secp256k1.GenerateSharedSecret(receiverPrivKey, senderPubKey)

	return sharedRecipient[:], nil
}
