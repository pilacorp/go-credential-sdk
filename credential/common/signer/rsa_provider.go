package signer

import (
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

var (
	_ JWSSignerProvider = (*RSAProvider)(nil)
	_ JWSSignerProvider = (*RSAFuncProvider)(nil)
)

// RSAProvider signs the JWS signing input with an in-memory RSA private key
// (suitable for local/dev; the key lives in this process).
type RSAProvider struct {
	priv *rsa.PrivateKey
	alg  string
}

// NewRSAProvider creates an RSA JWS signer from an in-memory key. alg defaults
// to "RS256" when omitted.
func NewRSAProvider(priv *rsa.PrivateKey, alg ...string) (*RSAProvider, error) {
	if priv == nil {
		return nil, fmt.Errorf("rsa private key is nil")
	}
	a := "RS256"
	if len(alg) > 0 && alg[0] != "" {
		a = alg[0]
	}
	return &RSAProvider{priv: priv, alg: a}, nil
}

func (p *RSAProvider) Algorithm() string { return p.alg }

func (p *RSAProvider) SignJWS(signingInput []byte) ([]byte, error) {
	return rsaSign(p.alg, p.priv, signingInput)
}

// RSAFuncProvider delegates signing to a caller-supplied callback (e.g. HSM,
// KMS, remote RPC), so the private key never enters the SDK.
type RSAFuncProvider struct {
	sign func([]byte) ([]byte, error)
	alg  string
}

// NewRSAFunc creates a JWS signer that calls signFn to sign. signFn receives the
// JWS signing input and must return the raw RSA signature for alg.
func NewRSAFunc(signFn func([]byte) ([]byte, error), alg string) (*RSAFuncProvider, error) {
	if signFn == nil {
		return nil, fmt.Errorf("sign function is nil")
	}
	if alg == "" {
		alg = "RS256"
	}
	return &RSAFuncProvider{sign: signFn, alg: alg}, nil
}

func (p *RSAFuncProvider) Algorithm() string { return p.alg }

func (p *RSAFuncProvider) SignJWS(signingInput []byte) ([]byte, error) {
	return p.sign(signingInput)
}

func rsaSign(alg string, priv *rsa.PrivateKey, signingInput []byte) ([]byte, error) {
	switch alg {
	case "RS256":
		h := sha256.Sum256(signingInput)
		return rsa.SignPKCS1v15(rand.Reader, priv, stdcrypto.SHA256, h[:])
	case "PS256":
		h := sha256.Sum256(signingInput)
		return rsa.SignPSS(rand.Reader, priv, stdcrypto.SHA256, h[:], nil)
	case "RS384":
		h := sha512.Sum384(signingInput)
		return rsa.SignPKCS1v15(rand.Reader, priv, stdcrypto.SHA384, h[:])
	case "PS384":
		h := sha512.Sum384(signingInput)
		return rsa.SignPSS(rand.Reader, priv, stdcrypto.SHA384, h[:], nil)
	case "RS512":
		h := sha512.Sum512(signingInput)
		return rsa.SignPKCS1v15(rand.Reader, priv, stdcrypto.SHA512, h[:])
	case "PS512":
		h := sha512.Sum512(signingInput)
		return rsa.SignPSS(rand.Reader, priv, stdcrypto.SHA512, h[:], nil)
	default:
		return nil, fmt.Errorf("unsupported JWS alg: %s", alg)
	}
}
