package jsonmap

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/internal/errtext"
)

const (
	JsonWebSignature2020 string = "JsonWebSignature2020"
	JsonWebKey2020       string = "JsonWebKey2020"

	// jws2020SuiteContext defines JsonWebSignature2020; no base context does.
	jws2020SuiteContext string = "https://w3id.org/security/suites/jws-2020/v1"
)

// AddJWSProof attaches a JsonWebSignature2020 proof (W3C CCG, CG-FINAL
// 2022-07-21): a detached JWS with b64:false (RFC 7797) over the Linked Data
// Proofs "create verify hash", SHA-256 of the canonical proof options followed
// by SHA-256 of the canonical document. The proof options (created,
// proofPurpose, verificationMethod, challenge, domain) are therefore signed,
// and the suite's @context is added to a document that does not define it.
//
// The JOSE algorithm comes from the signer (AlgorithmProvider) and must be one
// this SDK implements from the suite's table (§3.1): ES256 or PS256. The signer
// signs the SHA-256 digest of the JWS signing input.
func (m *JSONMap) AddJWSProof(signerProvider signer.SignerProvider, verificationMethod, proofPurpose string, opts ...ProofOpt) (err error) {
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
	if err := checkJWS2020Alg(alg); err != nil {
		return fmt.Errorf("jsonmap: %w", err)
	}

	// The document is only mutated on the way to a signature; a failure must
	// leave the caller's document exactly as it was.
	restoreContext := m.contextSnapshot()
	defer func() {
		if err != nil {
			restoreContext()
		}
	}()
	if err = m.addSuiteContextWithoutChangingMeaning(jws2020Suite); err != nil {
		return fmt.Errorf("jsonmap: %w", err)
	}

	options := newProofOptions(opts...)
	proof := &dto.Proof{
		Type:               JsonWebSignature2020,
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: verificationMethod,
		ProofPurpose:       proofPurpose,
		Challenge:          options.challenge,
		Domain:             domainValue(options.domain),
	}

	encHeader, err := encodeDetachedJWSHeader(alg)
	if err != nil {
		return err
	}
	hashData, err := m.ecdsaHashData(proof, nil)
	if err != nil {
		return fmt.Errorf("jsonmap: failed to build hash data: %w", err)
	}
	digest := sha256.Sum256(jwsSigningInput(encHeader, hashData))

	sig, err := signerProvider.Sign(digest[:])
	if err != nil {
		return fmt.Errorf("jsonmap: jws sign: %w", err)
	}
	if err = validateJWSSigShape(alg, len(sig)); err != nil {
		return fmt.Errorf("jsonmap: %w", err)
	}
	// Catch an ES256 signer bound to the wrong VM here, not at the verifier,
	// when the caller named the VM's key (WithVMPublicKey). The option holds
	// an ECDSA key, so an RSA proof is not checked here.
	if vmPub := options.vmPub; vmPub != nil && alg == "ES256" {
		if !crypto.VerifyP256(vmPub, digest[:], sig) {
			return fmt.Errorf("jsonmap: the signature does not verify against verification method %q; the signer does not hold that key", verificationMethod)
		}
	}
	proof.JWS = encHeader + ".." + base64.RawURLEncoding.EncodeToString(sig)

	m.appendProof(*proof)
	return nil
}

// checkJWS2020Alg admits the JsonWebSignature2020 algorithms this SDK
// implements. §3.3.1: alg MUST be "present in the supported algorithms table
// of this suite" (EdDSA, ES256K, ES256, ES384, PS256); EdDSA, ES256K and ES384
// are not implemented, and RS256 and the other RSA variants are not in it.
func checkJWS2020Alg(alg string) error {
	switch alg {
	case "ES256", "PS256":
		return nil
	}
	return fmt.Errorf("JsonWebSignature2020 alg %q is not supported: this SDK implements ES256 and PS256 from the suite's algorithm table", alg)
}

// validateJWSSigShape rejects a signer whose signature shape does not match the
// JOSE algorithm (an ECDSA signer bound to an RSA VM, or vice versa).
func validateJWSSigShape(alg string, n int) error {
	if alg == "ES256" {
		if n != 64 {
			return fmt.Errorf("JsonWebSignature2020 ES256 expects a 64-byte ECDSA signature, got %d; the signer does not match the verification method — pin the right VM with WithVerificationMethodKey", n)
		}
		return nil
	}
	if n == 64 || n == 65 {
		return fmt.Errorf("JsonWebSignature2020 %s expects an RSA signature but the signer returned %d bytes (an ECDSA signature); the signer does not match the RSA verification method — pin the right VM with WithVerificationMethodKey", alg, n)
	}
	return nil
}

func (m *JSONMap) verifyJWSProof(doc *verificationmethod.DIDDocument, proof *dto.Proof, cache *digestCache) (bool, error) {
	vm, err := verificationmethod.FindVerificationMethod(doc, proof.VerificationMethod)
	if err != nil {
		return false, fmt.Errorf("failed to resolve verification method: %w", err)
	}
	if err := verificationmethod.RequireController(doc, vm); err != nil {
		return false, err
	}
	if vm.Type != JsonWebKey2020 {
		return false, fmt.Errorf("expected %s VM, got %s", JsonWebKey2020, vm.Type)
	}
	if vm.PublicKeyJwk == nil {
		return false, fmt.Errorf("verification method '%s' has no publicKeyJwk", vm.ID)
	}

	encHeader, encSig, ok := splitDetachedJWS(proof.JWS)
	if !ok {
		return false, fmt.Errorf("malformed detached JWS")
	}
	alg, err := detachedJWSAlg(encHeader)
	if err != nil {
		return false, err
	}
	if err := checkJWS2020Alg(alg); err != nil {
		return false, err
	}

	// Strict(): one signature has one spelling, as for the secp256k1 suite.
	sig, err := base64.RawURLEncoding.Strict().DecodeString(encSig)
	if err != nil {
		return false, fmt.Errorf("decode jws signature: %w", err)
	}

	// RFC 7797 signs the header that travels with the proof, so the one from
	// the jws goes back into the signing input.
	hashData, err := m.ecdsaHashData(proof, cache)
	if err != nil {
		// A proof made before the SDK signed the proof options sits on a
		// document without the suite's context, so its options cannot be
		// canonicalized. Say so instead of leaving only the expansion error.
		if !m.definesSuite(jws2020Suite) {
			return false, fmt.Errorf("failed to build hash data: the document's @context does not include %q; a %s proof made by an SDK that signed the document alone lacks it and must be re-issued: %w", jws2020SuiteContext, JsonWebSignature2020, err)
		}
		return false, fmt.Errorf("failed to build hash data: %w", err)
	}
	signingInput := jwsSigningInput(encHeader, hashData)

	switch alg {
	case "ES256":
		pub, err := verificationmethod.P256PubKeyFromJWK(vm.PublicKeyJwk)
		if err != nil {
			return false, fmt.Errorf("parse P-256 jwk: %w", err)
		}
		digest := sha256.Sum256(signingInput)
		if !crypto.VerifyP256(pub, digest[:], sig) {
			return false, fmt.Errorf("JsonWebSignature2020 ES256 signature verification failed")
		}
	case "PS256":
		pub, err := verificationmethod.RSAPubKeyFromJWK(vm.PublicKeyJwk)
		if err != nil {
			return false, fmt.Errorf("parse RSA jwk: %w", err)
		}
		if err := crypto.VerifyRSAJWS(alg, pub, signingInput, sig); err != nil {
			return false, fmt.Errorf("JsonWebSignature2020 PS256 signature verification failed: %w", err)
		}
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
	// RFC 7515 §4.1.11: a crit entry the recipient does not understand makes
	// the JWS invalid; b64 is the only extension this reader understands.
	for _, c := range hdr.Crit {
		if c != "b64" {
			return "", fmt.Errorf("jws header crit names %q, which this verifier does not support", errtext.Clip(c))
		}
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
