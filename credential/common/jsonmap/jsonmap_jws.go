package jsonmap

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

const (
	JsonWebSignature2020 string = "JsonWebSignature2020"
	JsonWebKey2020       string = "JsonWebKey2020"
)

// AddJWSProof attaches a JsonWebSignature2020 (detached JWS, b64:false) proof.
// The JOSE algorithm comes from the signer (AlgorithmProvider, default RS256);
// the signer signs the digest of the JWS signing input hashed with alg's SHA.
func (m *JSONMap) AddJWSProof(signerProvider signer.SignerProvider, verificationMethod, proofPurpose string) error {
	if m == nil {
		return fmt.Errorf("jsonmap: JSONMap is nil")
	}
	if signerProvider == nil {
		return fmt.Errorf("jsonmap: signer provider cannot be nil")
	}
	if verificationMethod == "" {
		return fmt.Errorf("jsonmap: verification method is required")
	}
	if proofPurpose == "" {
		return fmt.Errorf("jsonmap: proof purpose is required")
	}

	alg := signer.AlgorithmOf(signerProvider)

	proof := dto.Proof{
		Type:               JsonWebSignature2020,
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: verificationMethod,
		ProofPurpose:       proofPurpose,
	}

	payload, err := m.Canonicalize()
	if err != nil {
		return fmt.Errorf("jsonmap: canonicalize: %w", err)
	}

	encHeader, err := encodeDetachedJWSHeader(alg)
	if err != nil {
		return err
	}
	signingInput := jwsSigningInput(encHeader, payload)
	digest, err := hashForJWSAlg(alg, signingInput)
	if err != nil {
		return fmt.Errorf("jsonmap: %w", err)
	}

	sig, err := signerProvider.Sign(digest)
	if err != nil {
		return fmt.Errorf("jsonmap: jws sign: %w", err)
	}
	// Guard against a mis-routed ECDSA signer bound to an RSA verification
	// method: an ECDSA signature is 64/65 bytes, never a valid RSA signature.
	if l := len(sig); l == 64 || l == 65 {
		return fmt.Errorf("jsonmap: JsonWebSignature2020 expects an RSA signature but the signer returned %d bytes (an ECDSA signature); the signer does not match the RSA verification method — pin the right VM with WithVerificationMethodKey", l)
	}
	proof.JWS = encHeader + ".." + base64.RawURLEncoding.EncodeToString(sig)

	m.appendProof(proof)
	return nil
}

// hashForJWSAlg hashes input with the SHA matching the JOSE algorithm.
func hashForJWSAlg(alg string, input []byte) ([]byte, error) {
	switch alg {
	case "RS256", "PS256":
		h := sha256.Sum256(input)
		return h[:], nil
	case "RS384", "PS384":
		h := sha512.Sum384(input)
		return h[:], nil
	case "RS512", "PS512":
		h := sha512.Sum512(input)
		return h[:], nil
	default:
		return nil, fmt.Errorf("unsupported JWS alg: %s", alg)
	}
}

func (m *JSONMap) verifyJWSProof(doc *verificationmethod.DIDDocument, proof *dto.Proof) (bool, error) {
	vm, err := verificationmethod.FindVerificationMethod(doc, proof.VerificationMethod)
	if err != nil {
		return false, fmt.Errorf("failed to resolve verification method: %w", err)
	}
	if vm.Type != JsonWebKey2020 {
		return false, fmt.Errorf("expected %s VM, got %s", JsonWebKey2020, vm.Type)
	}
	if vm.PublicKeyJwk == nil {
		return false, fmt.Errorf("verification method '%s' has no publicKeyJwk", vm.ID)
	}
	pub, err := verificationmethod.RSAPubKeyFromJWK(vm.PublicKeyJwk)
	if err != nil {
		return false, fmt.Errorf("parse RSA jwk: %w", err)
	}

	encHeader, encSig, ok := splitDetachedJWS(proof.JWS)
	if !ok {
		return false, fmt.Errorf("malformed detached JWS")
	}

	alg, err := detachedJWSAlg(encHeader)
	if err != nil {
		return false, err
	}

	payload, err := m.Canonicalize()
	if err != nil {
		return false, fmt.Errorf("canonicalize: %w", err)
	}
	signingInput := jwsSigningInput(encHeader, payload)

	sig, err := base64.RawURLEncoding.DecodeString(encSig)
	if err != nil {
		return false, fmt.Errorf("decode jws signature: %w", err)
	}

	if err := crypto.VerifyRSAJWS(alg, pub, signingInput, sig); err != nil {
		return false, err
	}
	if err := strictPurposeCheck(doc, vm, proof.ProofPurpose, proof.Created); err != nil {
		return false, err
	}
	return true, nil
}

func encodeDetachedJWSHeader(alg string) (string, error) {
	header := map[string]interface{}{"alg": alg, "b64": false, "crit": []string{"b64"}}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("jsonmap: marshal jws header: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(headerJSON), nil
}

// detachedJWSAlg decodes the header, enforces b64:false + crit:[b64], and
// returns the algorithm.
func detachedJWSAlg(encHeader string) (string, error) {
	headerBytes, err := base64.RawURLEncoding.DecodeString(encHeader)
	if err != nil {
		return "", fmt.Errorf("decode jws header: %w", err)
	}
	var hdr struct {
		Alg  string      `json:"alg"`
		B64  interface{} `json:"b64"`
		Crit []string    `json:"crit"`
	}
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return "", fmt.Errorf("parse jws header: %w", err)
	}
	if b, ok := hdr.B64.(bool); !ok || b {
		return "", fmt.Errorf("jws header b64 must be false")
	}
	if !containsString(hdr.Crit, "b64") {
		return "", fmt.Errorf("jws header crit must include b64")
	}
	return hdr.Alg, nil
}

func jwsSigningInput(encHeader string, payload []byte) []byte {
	out := make([]byte, 0, len(encHeader)+1+len(payload))
	out = append(out, encHeader...)
	out = append(out, '.')
	out = append(out, payload...)
	return out
}

func splitDetachedJWS(jws string) (string, string, bool) {
	idx := -1
	for i := 0; i+1 < len(jws); i++ {
		if jws[i] == '.' && jws[i+1] == '.' {
			idx = i
			break
		}
	}
	if idx <= 0 {
		return "", "", false
	}
	header, sig := jws[:idx], jws[idx+2:]
	if header == "" || sig == "" {
		return "", "", false
	}
	return header, sig, true
}

func containsString(arr []string, s string) bool {
	for _, x := range arr {
		if x == s {
			return true
		}
	}
	return false
}
