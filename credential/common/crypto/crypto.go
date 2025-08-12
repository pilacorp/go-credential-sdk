package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/pilacorp/go-credential-sdk/credential/common/jsoncanonicalizer"
)

func HashString(input string) string {
	hash := sha256.New()
	hash.Write([]byte(input))

	return hex.EncodeToString(hash.Sum(nil))
}

// EncryptString encrypts a string using AES in CBC mode with PKCS5 padding.
func EncryptString(hexKey, plaintext string) (string, error) {
	plaintextBytes := []byte(plaintext)

	return EncryptData(hexKey, plaintextBytes)
}

// EncryptData encrypts the given data using AES in CBC mode with PKCS5 padding.
func EncryptData(hexKey string, plaintext []byte) (string, error) {
	// Decode the Hex-encoded key
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", err
	}

	// Create an AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Pad the plaintext using PKCS5 padding
	plaintext = pkcs5Padding(plaintext, block.BlockSize())

	// Create an IV (initialization vector)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// Create AES CBC encrypted
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	// Encode the result to Hex for easy transport
	return hex.EncodeToString(ciphertext), nil
}

// DecryptData decrypts the given Hex-encoded ciphertext using AES in CBC mode with PKCS5 padding.
func DecryptData(hexKey, encryptedText string) ([]byte, error) {
	// Decode the Hex-encoded key
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}

	// Decode the Hex-encoded string
	ciphertext, err := hex.DecodeString(encryptedText)
	if err != nil {
		return nil, err
	}

	// Create an AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Extract the IV and the actual ciphertext
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// Create AES CBC decrypted
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// Remove PKCS5 padding
	plaintext := pkcs5UnPadding(ciphertext)

	return plaintext, nil
}

// pkcs5Padding applies PKCS5 padding to make the plaintext a multiple of the block size.
func pkcs5Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize

	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}

	return append(data, padText...)
}

// pkcs5UnPadding removes PKCS5 padding.
func pkcs5UnPadding(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])

	return data[:(length - unpadding)]
}

// KeyToBytes converts a hex string with prefix 0x to a byte array.
func KeyToBytes(key string) ([]byte, error) {
	if !strings.HasPrefix(key, "0x") {
		return nil, errors.New("key is not in hex format")
	}

	return hex.DecodeString(key[2:])
}

// BytesToKey converts a byte array to a hex string with prefix 0x.
func BytesToKey(data []byte) string {
	return "0x" + hex.EncodeToString(data)
}

// SignJSONMessage signs a json message using the provided private key with secp256k1
// The message is first canonicalized and then signed.
func SignJSONMessage(privateKey, message []byte) (string, error) {
	message, err := jsoncanonicalizer.Transform(message)
	if err != nil {
		return "", err
	}

	return SignMessage(privateKey, message)
}

// SignMessage signs a message using the provided private key with secp256k1.
func SignMessage(privateKey, message []byte) (string, error) {
	// Create hash of the message
	hash := sha256.Sum256(message)

	// Parse private key
	privKey, err := ParsePrivateKey(privateKey)
	if err != nil {
		return "", err
	}

	signature, err := crypto.Sign(hash[:], privKey)
	if err != nil {
		return "", err
	}

	// Return the signature in hex format
	return hex.EncodeToString(signature), nil
}

// GetPublicKeyFromPrivateKey derives the public key of type secp256k1 from a private key
// The length of the public key is 33 bytes.
func GetPublicKeyFromPrivateKey(privateKey []byte) (string, error) {
	// Parse private key
	privKey, err := ParsePrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	// Get public key
	pubKey := privKey.Public().(*ecdsa.PublicKey)
	pubKeyBytes := crypto.CompressPubkey(pubKey)

	// Return the public key in hex format
	return BytesToKey(pubKeyBytes), nil
}

// ParsePrivateKey parses a private key of type secp256k1 from bytes
// The length of the private key is 32 bytes.
func ParsePrivateKey(privateKeyBytes []byte) (*ecdsa.PrivateKey, error) {
	if len(privateKeyBytes) != 32 {
		return nil, errors.New("private key must be 32 bytes")
	}

	privKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

// VerifyJSONSignature verifies the signature of type secp256k1 of a json message
// The message is first canonicalized and then verified.
func VerifyJSONSignature(publicKey, message, signature []byte) bool {
	message, err := jsoncanonicalizer.Transform(message)
	if err != nil {
		return false
	}

	return VerifySignature(publicKey, message, signature)
}

func verifySignatureWithoutV(publicKey, message, signature []byte) bool {
	if len(signature) != 64 || len(publicKey) != 33 || len(message) == 0 {
		return false
	}

	hash := sha256.Sum256(message)

	return crypto.VerifySignature(publicKey, hash[:], signature)
}

func VerifyJSONSignatureFromString(publicKeyStr, messageStr, signatureStr string) bool {
	publicKeyBytes, err := KeyToBytes(publicKeyStr)
	if err != nil {
		return false
	}

	// Convert signature from hex string to bytes
	signatureBytes, err := hex.DecodeString(signatureStr)
	if err != nil {
		return false
	}

	// convert message to bytes
	messageBytes := []byte(messageStr)

	return VerifyJSONSignature(publicKeyBytes, messageBytes, signatureBytes)
}

// VerifySignature verifies a signature of type secp256k1
// The length of the public key is 33 bytes
// The length of the message is positive
// The length of the signature should be 65 bytes (64 bytes + 1 recovery byte).
func VerifySignature(publicKey, message, signature []byte) bool {
	if len(signature) != 65 || len(publicKey) != 33 || len(message) == 0 {
		return verifySignatureWithoutV(publicKey, message, signature)
	}

	// Create hash of the message (same as in SignMessage)
	hash := sha256.Sum256(message)

	// Recover the public key from the signature
	recoveredPubKey, err := crypto.Ecrecover(hash[:], signature)
	if err != nil {
		return false
	}

	// Compress the recovered public key for comparison
	recoveredPubKeyObj, err := crypto.UnmarshalPubkey(recoveredPubKey)
	if err != nil {
		return false
	}

	compressedRecoveredPubKey := crypto.CompressPubkey(recoveredPubKeyObj)

	// Compare the compressed public keys
	return len(publicKey) == 33 && bytes.Equal(compressedRecoveredPubKey, publicKey)
}
