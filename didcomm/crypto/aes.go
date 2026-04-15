package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"
)

func EncryptAESGCM(key, plaintext []byte) ([]byte, []byte, []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err)
	}

	// Seal appends the tag to the ciphertext
	ciphertextWithTag := gcm.Seal(nil, nonce, plaintext, nil)

	// Extract tag (last 16 bytes for AES-GCM)
	tagSize := 16
	tag := ciphertextWithTag[len(ciphertextWithTag)-tagSize:]
	ciphertext := ciphertextWithTag[:len(ciphertextWithTag)-tagSize]

	return nonce, ciphertext, tag
}
