package signer

import (
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/crypto"
)

var (
	_ SignerProvider    = (*RSAProvider)(nil)
	_ AlgorithmProvider = (*RSAProvider)(nil)
)

// RSAProvider signs a digest with an RSA key for JsonWebSignature2020, using
// either an in-memory key or a caller-supplied callback (HSM/KMS). Its JOSE
// algorithm is PS256, the one RSA algorithm of the suite's table (§3.1); the
// SDK writes it to the JWS header and hands Sign the SHA-256 digest of the
// signing input.
type RSAProvider struct {
	sign func([]byte) ([]byte, error)
	alg  string
}

// minRSABits is the smallest RSA key RFC 7518 §3.5 and JsonWebSignature2020
// §3.1 allow.
const minRSABits = 2048

// NewRSAProvider creates a PS256 signer from an in-memory key of at least 2048
// bits. alg, when given, must be "PS256".
func NewRSAProvider(priv *rsa.PrivateKey, alg ...string) (*RSAProvider, error) {
	if priv == nil {
		return nil, fmt.Errorf("rsa private key is nil")
	}
	if priv.N == nil {
		return nil, fmt.Errorf("rsa private key has no modulus")
	}
	if bits := priv.N.BitLen(); bits < minRSABits {
		return nil, fmt.Errorf("rsa key is %d bits; at least %d are required", bits, minRSABits)
	}
	a, err := jwsAlg(alg...)
	if err != nil {
		return nil, err
	}
	return &RSAProvider{
		sign: func(digest []byte) ([]byte, error) {
			return rsa.SignPSS(rand.Reader, priv, stdcrypto.SHA256, digest, crypto.PSSOptions())
		},
		alg: a,
	}, nil
}

// NewRSAFunc creates a signer that delegates to signFn, which receives the
// SHA-256 digest of the signing input and returns the PS256 signature (salt
// length 32, RFC 7518 §3.5). alg, when not empty, must be "PS256".
func NewRSAFunc(signFn func([]byte) ([]byte, error), alg string) (*RSAProvider, error) {
	if signFn == nil {
		return nil, fmt.Errorf("sign function is nil")
	}
	a, err := jwsAlg(alg)
	if err != nil {
		return nil, err
	}
	return &RSAProvider{sign: signFn, alg: a}, nil
}

func (p *RSAProvider) Algorithm() string { return p.alg }

func (p *RSAProvider) Sign(digest []byte) ([]byte, error) {
	return p.sign(digest)
}

// jwsAlg returns PS256, refusing any other algorithm: JsonWebSignature2020
// lists no other RSA algorithm.
func jwsAlg(alg ...string) (string, error) {
	if len(alg) == 0 || alg[0] == "" || alg[0] == "PS256" {
		return "PS256", nil
	}
	return "", fmt.Errorf("rsa signer algorithm %q is not supported: JsonWebSignature2020 lists PS256 only for RSA", alg[0])
}
