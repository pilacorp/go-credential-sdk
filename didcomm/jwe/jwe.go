package jwe

import (
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

func base64url(input []byte) string {
	return base64.RawURLEncoding.EncodeToString(input)
}

func BuildJWE(sharedKey, iv, ciphertext []byte) string {
	header := map[string]string{
		"alg": "ECDH-ES",
		"enc": "A256GCM",
		"crv": "secp256k1",
		"typ": "application/didcomm-encrypted+json",
	}
	headerBytes, _ := json.Marshal(header)
	jwe := JWE{
		Protected:  base64url(headerBytes),
		IV:         base64url(iv),
		Ciphertext: base64url(ciphertext),
		Tag:        base64url(sharedKey[:16]), // mock tag
	}
	result, err := json.MarshalIndent(jwe, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling JWE:", err)
		return ""
	}
	return string(result)
}
