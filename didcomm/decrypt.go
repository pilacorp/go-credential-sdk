package didcomm

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"log"
)

type JWE struct {
	Protected  string `json:"protected"`
	IV         string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
	Tag        string `json:"tag"`
}

func base64urlDecode(input string) []byte {
	data, err := base64.RawURLEncoding.DecodeString(input)
	if err != nil {
		log.Fatal("base64url decode error:", err)
	}
	return data
}

func DecryptJWE(jweStr string, sharedKey []byte) string {
	var jwe JWE
	err := json.Unmarshal([]byte(jweStr), &jwe)
	if err != nil {
		log.Fatal("unmarshal error:", err)
	}

	iv := base64urlDecode(jwe.IV)
	ciphertext := base64urlDecode(jwe.Ciphertext)

	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		log.Fatal(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		log.Fatal("decryption failed:", err)
	}

	return string(plaintext)
}
