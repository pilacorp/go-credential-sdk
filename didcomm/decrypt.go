package didcomm

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type JWE struct {
	Protected  string `json:"protected"`
	IV         string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
	Tag        string `json:"tag"`
}

func base64urlDecode(input string) ([]byte, error) {
	data, err := base64.RawURLEncoding.DecodeString(input)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func DecryptJWE(jweStr string, sharedKey []byte) (string, error) {
	var jwe JWE
	err := json.Unmarshal([]byte(jweStr), &jwe)
	if err != nil {
		return "", fmt.Errorf("unmarshal error: %w", err)
	}

	iv, err := base64urlDecode(jwe.IV)
	if err != nil {
		return "", fmt.Errorf("base64url decode iv: %w", err)
	}
	ciphertext, err := base64urlDecode(jwe.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("base64url decode ciphertext: %w", err)
	}
	tag, err := base64urlDecode(jwe.Tag)
	if err != nil {
		return "", fmt.Errorf("base64url decode tag: %w", err)
	}

	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return "", fmt.Errorf("aes new cipher error: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("aes new gcm error: %w", err)
	}

	if len(iv) != gcm.NonceSize() {
		return "", fmt.Errorf("invalid nonce size: got %d, want %d", len(iv), gcm.NonceSize())
	}

	// Append tag to ciphertext for GCM.Open (it verifies the tag)
	ciphertextWithTag := append(ciphertext, tag...)

	plaintext, err := gcm.Open(nil, iv, ciphertextWithTag, nil)
	if err != nil {
		// Fallback to mock tag for backward compatibility (old implementation used sharedKey[:16] as tag).
		// Safe: aes.NewCipher above only accepts 16/24/32-byte keys, so len(sharedKey) >= 16.
		mockTag := sharedKey[:16]
		ciphertextWithMockTag := append(ciphertext, mockTag...)

		plaintext, err = gcm.Open(nil, iv, ciphertextWithMockTag, nil)
		if err != nil {
			return "", fmt.Errorf("decryption failed: %w", err)
		}
	}

	return string(plaintext), nil
}
