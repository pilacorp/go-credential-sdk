package didcomm

import (
	"encoding/hex"
	"log"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func GetFromKeys(senderPubHex, receiverPrivHex string) []byte {
	senderPubBytes, err := hex.DecodeString(senderPubHex)
	if err != nil {
		log.Fatalf("failed to decode sender public key: %v", err)
	}
	senderPubKey, err := secp256k1.ParsePubKey(senderPubBytes)
	if err != nil {
		log.Fatalf("failed to parse sender public key: %v", err)
	}

	receiverPrivBytes, err := hex.DecodeString(receiverPrivHex)
	if err != nil {
		log.Fatalf("failed to decode receiver private key: %v", err)
	}
	receiverPrivKey := secp256k1.PrivKeyFromBytes(receiverPrivBytes)

	sharedRecipient := secp256k1.GenerateSharedSecret(receiverPrivKey, senderPubKey)

	return sharedRecipient[:]
}
