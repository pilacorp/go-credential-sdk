package jsonmap

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// ===== EcdsaSecp256k1Signature2019 (Linked Data Signatures, VC 1.1) =====
//
// secp256k1 has no Data Integrity cryptosuite: ecdsa-rdfc-2019 is defined for
// P-256 and P-384 only. The VC 1.1 era instead defines a whole Linked Data
// Signature suite per curve, and EcdsaSecp256k1Signature2019 is the secp256k1
// one — https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/.
//
// Unlike a Data Integrity proof, the signature lives in `jws` (a detached JWS
// with b64:false, per RFC 7797) rather than in `proofValue`.

const (
	// AlgES256K is the only JOSE algorithm this suite admits: ECDSA on
	// secp256k1 with SHA-256.
	AlgES256K string = "ES256K"

	// Secp256k1SuiteContext defines EcdsaSecp256k1Signature2019 and the proof
	// terms it uses (jws, proofPurpose, challenge, domain). Added only to a
	// document whose own @context defines none of them; without a definition
	// the canonicalizer cannot expand the proof and SafeMode rejects it.
	Secp256k1SuiteContext string = "https://w3id.org/security/v2"

	// credentialsV1Context is the VC 1.1 base context. It already defines
	// EcdsaSecp256k1Signature2019 with a type-scoped context covering jws,
	// created, challenge, domain, proofPurpose and verificationMethod — and its
	// terms are @protected, so layering another security context on top is a
	// protected-term redefinition, not a no-op.
	credentialsV1Context string = "https://www.w3.org/2018/credentials/v1"

	// secp256k1SuiteContextAlt is the narrower context Digital Bazaar
	// publishes for the same suite. Accepted when a caller already put it on
	// the document, never added by this SDK.
	secp256k1SuiteContextAlt string = "https://w3id.org/security/suites/secp256k1-2019/v1"
)

// SigningSuiteForKey resolves the proof suite to issue from the key the
// verification method holds. The key is what decides, because it is what
// decides which suites are applicable at all:
//
//	P-256      → DataIntegrityProof / ecdsa-rdfc-2019
//	secp256k1  → EcdsaSecp256k1Signature2019, but only when the document's
//	             @context defines it — a VC 1.1 document. Otherwise there is no
//	             applicable suite and the caller is told what to build instead.
//
// The data model cannot decide this on its own: a VC 1.1 document signs with
// either suite, depending on the key.
func (m *JSONMap) SigningSuiteForKey(kind verificationmethod.KeyKind, vmURL string) (string, error) {
	switch kind {
	case verificationmethod.KeyP256:
		return DataIntegrityProof, nil

	case verificationmethod.KeySecp256k1:
		if m.definesSecp256k1Suite() {
			return EcdsaSecp256k1Signature2019, nil
		}
		return "", fmt.Errorf(
			"verification method %q holds a secp256k1 key, which ecdsa-rdfc-2019 does not cover; %s does, but the document's @context does not define it — build the credential as VC Data Model 1.1 (vc.WithDataModel11())",
			vmURL, EcdsaSecp256k1Signature2019)

	default:
		return "", fmt.Errorf("unsupported key kind %v for JSON-LD signing", kind)
	}
}

// AddEcdsaSecp256k1Proof attaches an EcdsaSecp256k1Signature2019 proof.
// verificationMethod must be a full DID URL (the caller resolves/normalizes it).
//
// The signer must hold a secp256k1 key. go-ethereum's signer returns 65 bytes
// (r||s||v); JOSE wants the bare 64-byte r||s, so the recovery byte is dropped.
func (m *JSONMap) AddEcdsaSecp256k1Proof(signerProvider signer.SignerProvider, verificationMethod, proofPurpose string, opts ...ProofOpt) error {
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

	// The proof configuration is canonicalized against the document's
	// @context, which must define the suite's terms.
	if err := m.requireSecp256k1SuiteContext(); err != nil {
		return fmt.Errorf("jsonmap: %w", err)
	}

	options := newProofOptions(opts...)
	proof := &dto.Proof{
		Type:               EcdsaSecp256k1Signature2019,
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: verificationMethod,
		ProofPurpose:       proofPurpose,
		Challenge:          options.challenge,
		Domain:             domainValue(options.domain),
	}

	signingInput, err := m.secp256k1SigningInput(proof)
	if err != nil {
		return fmt.Errorf("jsonmap: %w", err)
	}
	signDigest := sha256.Sum256(signingInput)

	signature, err := signerProvider.Sign(signDigest[:])
	if err != nil {
		return fmt.Errorf("jsonmap: failed to sign digest: %w", err)
	}
	signature, err = joseSecp256k1Signature(signature)
	if err != nil {
		return fmt.Errorf("jsonmap: %w", err)
	}

	// Catch a signer bound to the wrong VM here, not at the verifier.
	if vmPub := options.vmPub; vmPub != nil {
		if !crypto.VerifyECDSA(vmPub, signDigest[:], signature) {
			return fmt.Errorf("jsonmap: the signature does not verify against verification method %q; the signer does not hold that key", verificationMethod)
		}
	}

	encHeader, err := encodeDetachedJWSHeader(AlgES256K)
	if err != nil {
		return err
	}
	proof.JWS = encHeader + ".." + base64.RawURLEncoding.EncodeToString(signature)
	m.appendProof(*proof)

	return nil
}

// verifyEcdsaSecp256k1Proof verifies an EcdsaSecp256k1Signature2019 proof,
// rebuilding the signing input exactly as the signer did.
func (m *JSONMap) verifyEcdsaSecp256k1Proof(doc *verificationmethod.DIDDocument, proof *dto.Proof) (bool, error) {
	vm, err := verificationmethod.FindVerificationMethod(doc, proof.VerificationMethod)
	if err != nil {
		return false, fmt.Errorf("failed to resolve verification method: %w", err)
	}
	// The suite binds the signature to a secp256k1 key; a P-256 VM under this
	// proof type means the issuer mixed suites, which is what this type exists
	// to prevent.
	if !verificationmethod.VMIsSecp256k1(vm) {
		return false, fmt.Errorf(
			"%s: verification method %q does not hold a secp256k1 key",
			EcdsaSecp256k1Signature2019, proof.VerificationMethod)
	}
	pub, err := verificationmethod.ECPubFromVM(vm)
	if err != nil {
		return false, fmt.Errorf("invalid public key: %w", err)
	}

	encHeader, encSig, ok := splitDetachedJWS(proof.JWS)
	if !ok {
		return false, fmt.Errorf("%s: malformed detached JWS", EcdsaSecp256k1Signature2019)
	}
	alg, err := detachedJWSAlg(encHeader)
	if err != nil {
		return false, err
	}
	if alg != AlgES256K {
		return false, fmt.Errorf(
			"%s: jws alg must be %s, got %q",
			EcdsaSecp256k1Signature2019, AlgES256K, alg)
	}

	signature, err := base64.RawURLEncoding.DecodeString(encSig)
	if err != nil {
		return false, fmt.Errorf("decode jws signature: %w", err)
	}
	if signature, err = joseSecp256k1Signature(signature); err != nil {
		return false, err
	}

	// The signature cannot cover itself: the proof configuration is the proof
	// with jws removed.
	cfg := *proof
	cfg.JWS = ""
	signingInput, err := m.secp256k1SigningInput(&cfg)
	if err != nil {
		return false, err
	}
	digest := sha256.Sum256(signingInput)

	if !crypto.VerifyECDSA(pub, digest[:], signature) {
		return false, fmt.Errorf("%s signature verification failed", EcdsaSecp256k1Signature2019)
	}

	if err := strictPurposeCheck(doc, vm, proof.ProofPurpose, proof.Created); err != nil {
		return false, err
	}
	return true, nil
}

// secp256k1SigningInput builds the bytes the detached JWS signs:
// base64url(header) || "." || (proofConfigHash || documentHash).
//
// The payload is the Linked Data Signatures "create verify hash" — the same
// two-digest construction ecdsa-rdfc-2019 uses — so every proof option
// (created, challenge, domain, proofPurpose) is covered by the signature. The
// alternative, hashing the document alone, would leave those options free to
// be rewritten after issuance.
func (m *JSONMap) secp256k1SigningInput(proof *dto.Proof) ([]byte, error) {
	if proof.JWS != "" {
		return nil, fmt.Errorf("proof configuration must not carry jws")
	}
	hashData, err := m.ecdsaHashData(proof)
	if err != nil {
		return nil, fmt.Errorf("failed to build hash data: %w", err)
	}
	encHeader, err := encodeDetachedJWSHeader(AlgES256K)
	if err != nil {
		return nil, err
	}
	return jwsSigningInput(encHeader, hashData), nil
}

// joseSecp256k1Signature normalizes a secp256k1 signature to the 64-byte r||s
// JOSE expects, dropping go-ethereum's trailing recovery byte.
func joseSecp256k1Signature(sig []byte) ([]byte, error) {
	switch len(sig) {
	case 65:
		return sig[:64], nil
	case 64:
		return sig, nil
	default:
		return nil, fmt.Errorf(
			"%s expects a 64-byte secp256k1 signature (r||s), got %d; the signer does not match the verification method — pin the right VM with WithVerificationMethodKey",
			EcdsaSecp256k1Signature2019, len(sig))
	}
}

// requireSecp256k1SuiteContext reports whether the document's @context defines
// EcdsaSecp256k1Signature2019, and refuses to sign when it does not.
//
// The SDK deliberately does NOT append the suite context to a document that
// lacks it. EcdsaSecp256k1Signature2019 belongs to VC Data Model 1.1, whose
// base context defines it; the 2.0 Data Integrity cryptosuites cover P-256 and
// P-384 only, and vc-di-ecdsa says of secp256k1 that it "is not used by this
// specification". Quietly bolting a security context onto a 2.0 document would
// manufacture a combination no specification covers and make it look valid —
// exactly the class of mistake this suite exists to correct. The caller is
// told to build on the right data model instead.
func (m *JSONMap) requireSecp256k1SuiteContext() error {
	if m.definesSecp256k1Suite() {
		return nil
	}
	return fmt.Errorf(
		"%s is a VC Data Model 1.1 suite, but the document's @context does not define it; build the credential on %q (issuanceDate / expirationDate) — with vc.WithDataModel11() — or add %q to @context explicitly",
		EcdsaSecp256k1Signature2019, credentialsV1Context, Secp256k1SuiteContext)
}

// definesSecp256k1Suite reports whether the document's @context defines
// EcdsaSecp256k1Signature2019 — either through the VC 1.1 base context, which
// carries the suite's own scoped context, or through a security context the
// caller added.
func (m *JSONMap) definesSecp256k1Suite() bool {
	defines := func(s string) bool {
		return s == credentialsV1Context ||
			s == Secp256k1SuiteContext ||
			s == secp256k1SuiteContextAlt
	}

	switch c := (*m)["@context"].(type) {
	case string:
		return defines(c)
	case []interface{}:
		for _, e := range c {
			if s, ok := e.(string); ok && defines(s) {
				return true
			}
		}
	case []string:
		for _, s := range c {
			if defines(s) {
				return true
			}
		}
	}
	return false
}
