package didcomm

import (
	"github.com/pilacorp/go-credential-sdk/didcomm/crypto"
	"github.com/pilacorp/go-credential-sdk/didcomm/jwe"
)

func Encrypt(key []byte, plaintext string) string {
	nonce, ciphertext, tag := crypto.EncryptAESGCM(key, []byte(plaintext))

	jweOutput := jwe.BuildJWE(nonce, ciphertext, tag)

	return jweOutput
}
