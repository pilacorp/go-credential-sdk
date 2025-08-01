package didcomm

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

func DecryptJWE(jweStr string, sharedKey []byte) (string, error) {
	var jwe JWE
	err := json.Unmarshal([]byte(jweStr), &jwe)
	if err != nil {
		return "", fmt.Errorf("unmarshal error: %v", err)
	}

	iv := base64urlDecode(jwe.IV)
	ciphertext := base64urlDecode(jwe.Ciphertext)

	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return "", fmt.Errorf("aes new cipher error: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("aes new gcm error: %v", err)
	}

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %v", err)
	}

	return string(plaintext), nil
}
