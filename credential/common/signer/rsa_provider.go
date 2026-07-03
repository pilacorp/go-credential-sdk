package signer

import (
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

var (
	_ SignerProvider    = (*RSAProvider)(nil)
	_ AlgorithmProvider = (*RSAProvider)(nil)
)

// RSAProvider signs a digest with an RSA key for JsonWebSignature2020, using
// either an in-memory key or a caller-supplied callback (HSM/KMS). The JOSE
// algorithm (RS256/384/512, PS256/384/512) is declared via Algorithm so the SDK
// hashes the signing input with the matching SHA and writes the JWS header.
type RSAProvider struct {
	sign func([]byte) ([]byte, error)
	alg  string
}

// NewRSAProvider creates an RSA JWS signer from an in-memory key. alg defaults
// to "RS256"; supported: RS256/384/512, PS256/384/512.
func NewRSAProvider(priv *rsa.PrivateKey, alg ...string) (*RSAProvider, error) {
	if priv == nil {
		return nil, fmt.Errorf("rsa private key is nil")
	}
	a := jwsAlg(alg...)
	return &RSAProvider{
		sign: func(digest []byte) ([]byte, error) { return rsaSignDigest(a, priv, digest) },
		alg:  a,
	}, nil
}

// NewRSAFunc creates an RSA JWS signer that delegates to signFn. signFn receives
// the digest (already hashed by the SDK with alg's SHA) and returns the raw
// signature for alg.
func NewRSAFunc(signFn func([]byte) ([]byte, error), alg string) (*RSAProvider, error) {
	if signFn == nil {
		return nil, fmt.Errorf("sign function is nil")
	}
	return &RSAProvider{sign: signFn, alg: jwsAlg(alg)}, nil
}

func (p *RSAProvider) Algorithm() string { return p.alg }

func (p *RSAProvider) Sign(digest []byte) ([]byte, error) {
	return p.sign(digest)
}

func jwsAlg(alg ...string) string {
	if len(alg) > 0 && alg[0] != "" {
		return alg[0]
	}
	return "RS256"
}

// rsaSignDigest signs a pre-hashed digest for the given JOSE alg.
func rsaSignDigest(alg string, priv *rsa.PrivateKey, digest []byte) ([]byte, error) {
	switch alg {
	case "RS256":
		return rsa.SignPKCS1v15(rand.Reader, priv, stdcrypto.SHA256, digest)
	case "PS256":
		return rsa.SignPSS(rand.Reader, priv, stdcrypto.SHA256, digest, nil)
	case "RS384":
		return rsa.SignPKCS1v15(rand.Reader, priv, stdcrypto.SHA384, digest)
	case "PS384":
		return rsa.SignPSS(rand.Reader, priv, stdcrypto.SHA384, digest, nil)
	case "RS512":
		return rsa.SignPKCS1v15(rand.Reader, priv, stdcrypto.SHA512, digest)
	case "PS512":
		return rsa.SignPSS(rand.Reader, priv, stdcrypto.SHA512, digest, nil)
	default:
		return nil, fmt.Errorf("unsupported JWS alg: %s", alg)
	}
}
