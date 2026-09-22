package jsonmap

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// ===== EcdsaSecp256k1Signature2019 (Linked Data Signatures) =====
//
// secp256k1 has no Data Integrity cryptosuite: ecdsa-rdfc-2019 is defined for
// P-256 and P-384 only. The generation of suites before Data Integrity named
// one suite per curve, and EcdsaSecp256k1Signature2019 is the secp256k1 one —
// https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/. It binds to no data
// model; what it needs is an @context that defines its terms.
//
// Unlike a Data Integrity proof, the signature lives in `jws` (a detached JWS
// with b64:false, per RFC 7797) rather than in `proofValue`.

const (
	// AlgES256K is the only JOSE algorithm this suite admits: ECDSA on
	// secp256k1 with SHA-256.
	AlgES256K string = "ES256K"

	// Secp256k1SuiteContext is the broad security context, which defines this
	// suite among many other terms. The SDK never adds it — it adds the narrow
	// one below — but a caller may have put it on the document already, and
	// then it is what defines the suite and no second context is needed.
	Secp256k1SuiteContext string = "https://w3id.org/security/v2"

	// credentialsV1Context is the VC 1.1 base context. This SDK issues VC 2.0
	// documents only, but a document built elsewhere can arrive on 1.1, and
	// that context already defines the suite with its own @protected terms.
	// Recognising it is what stops the SDK from adding a second definition and
	// turning a signable document into a redefinition error.
	credentialsV1Context string = "https://www.w3.org/2018/credentials/v1"

	// Secp256k1SuiteContextNarrow defines this suite and nothing else. It is
	// what the SDK adds to a document that does not already define the suite —
	// a VC 2.0 document, whose base context covers Data Integrity only. The
	// narrow context is preferred over security/v2 because it brings in far
	// fewer terms — though not none: it defines proof at the document root,
	// which is why signing checks the document still says the same thing
	// after the context is added.
	Secp256k1SuiteContextNarrow string = "https://w3id.org/security/suites/secp256k1-2019/v1"
)

// SigningSuiteForKey resolves the proof suite to issue from the key the
// verification method holds. The key is what decides, because it is what
// decides which suites are applicable at all:
//
//	P-256      → DataIntegrityProof / ecdsa-rdfc-2019
//	secp256k1  → EcdsaSecp256k1Signature2019
//
// The data model does not decide this: either data model signs with either
// suite, depending on the key. What the data model decides is whether the
// suite's @context has to be added — see ensureSecp256k1SuiteContext.
func SigningSuiteForKey(kind verificationmethod.KeyKind) (string, error) {
	switch kind {
	case verificationmethod.KeyP256:
		return DataIntegrityProof, nil

	case verificationmethod.KeySecp256k1:
		return EcdsaSecp256k1Signature2019, nil

	default:
		return "", fmt.Errorf("unsupported key kind %v for JSON-LD signing", kind)
	}
}

// AddEcdsaSecp256k1Proof attaches an EcdsaSecp256k1Signature2019 proof.
// verificationMethod must be a full DID URL (the caller resolves/normalizes it).
//
// The signer must hold a secp256k1 key. go-ethereum's signer returns 65 bytes
// (r||s||v); JOSE wants the bare 64-byte r||s, so the recovery byte is dropped.
func (m *JSONMap) AddEcdsaSecp256k1Proof(signerProvider signer.SignerProvider, verificationMethod, proofPurpose string, opts ...ProofOpt) (err error) {
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

	// The document is only mutated on the way to a signature; a failure must
	// leave the caller's document exactly as it was.
	restoreContext := m.contextSnapshot()
	defer func() {
		if err != nil {
			restoreContext()
		}
	}()

	// The proof configuration is canonicalized against the document's
	// @context, which must define the suite's terms.
	if err = m.addSuiteContextWithoutChangingMeaning(); err != nil {
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

	encHeader, err := encodeDetachedJWSHeader(AlgES256K)
	if err != nil {
		return fmt.Errorf("jsonmap: %w", err)
	}
	signingInput, err := m.secp256k1SigningInput(proof, encHeader)
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
	// RFC 7518 § 3.4: an ES256K signature in a JWS is exactly 64 bytes. The
	// signing side trims go-ethereum's recovery byte; here a 65th byte is a
	// byte nobody signed, and accepting it would give one credential many
	// byte forms that all verify — and many different hashes.
	if l := len(signature); l != 64 {
		return false, fmt.Errorf(
			"%s: jws signature is %d bytes, want 64 (r||s)",
			EcdsaSecp256k1Signature2019, l)
	}

	// RFC 7797 signs the header that travels with the proof, so the one from
	// the jws is what goes back into the signing input — not a freshly built
	// one, which would leave every other header field uncovered.
	signingInput, err := m.secp256k1SigningInput(proof, encHeader)
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
func (m *JSONMap) secp256k1SigningInput(proof *dto.Proof, encHeader string) ([]byte, error) {
	hashData, err := m.ecdsaHashData(proof)
	if err != nil {
		return nil, fmt.Errorf("failed to build hash data: %w", err)
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

// contextSnapshot returns a function that puts @context back the way it is
// now. Signing adds the suite context before it knows whether it will succeed.
func (m *JSONMap) contextSnapshot() func() {
	previous, had := (*m)["@context"]

	return func() {
		if had {
			(*m)["@context"] = previous

			return
		}
		delete(*m, "@context")
	}
}

// addSuiteContextWithoutChangingMeaning adds the suite context and refuses if
// doing so changed what the document says.
//
// The suite context defines proof at the document root, while credentials/v2
// scopes that term to the credential itself. So a document using its own term
// named proof — under an @vocab, say — has that term redefined underneath it:
// the value either lands on a different property or stops expanding at all.
// Either way the issuer would sign something other than what it built, so the
// signature is refused instead.
func (m *JSONMap) addSuiteContextWithoutChangingMeaning() error {
	before, err := m.DocumentDigest()
	if err != nil {
		return fmt.Errorf("failed to canonicalize the document: %w", err)
	}
	if err := m.ensureSecp256k1SuiteContext(); err != nil {
		return err
	}
	after, err := m.DocumentDigest()
	if err != nil {
		return fmt.Errorf(
			"adding %q, which %s needs, stopped the document from canonicalizing; a term it defines collides with one this document uses — rename that term, or define the suite in @context yourself: %w",
			Secp256k1SuiteContextNarrow, EcdsaSecp256k1Signature2019, err)
	}
	if !bytes.Equal(before, after) {
		return fmt.Errorf(
			"adding %q, which %s needs, changed what the document says; it defines proof at the root, so a term of that name used elsewhere in this document is redefined — rename that term, or define the suite in @context yourself",
			Secp256k1SuiteContextNarrow, EcdsaSecp256k1Signature2019)
	}

	return nil
}

// ensureSecp256k1SuiteContext makes the document's @context define the suite,
// adding the narrow suite context when it does not.
//
// The canonicalizer runs in SafeMode: a proof whose terms no context defines
// does not expand, and signing fails. The two data models arrive here in
// different shapes. VC 1.1 already defines the suite in its base context, and
// those terms are @protected, so layering another security context on top is a
// protected-term redefinition — nothing is added. VC 2.0 defines Data
// Integrity only, so the suite context is appended; that combination
// canonicalizes cleanly and keeps every 2.0 property, credentialStatus
// included.
func (m *JSONMap) ensureSecp256k1SuiteContext() error {
	if m == nil {
		return fmt.Errorf("JSONMap is nil")
	}
	if m.definesSecp256k1Suite() {
		return nil
	}

	switch c := (*m)["@context"].(type) {
	case nil:
		return fmt.Errorf(
			"document has no @context, so %s cannot be expanded; build the credential through vc.NewJSONCredential or add %q yourself",
			EcdsaSecp256k1Signature2019, Secp256k1SuiteContextNarrow)
	case string:
		(*m)["@context"] = []interface{}{c, Secp256k1SuiteContextNarrow}
	case []interface{}:
		(*m)["@context"] = append(append([]interface{}{}, c...), Secp256k1SuiteContextNarrow)
	case []string:
		out := make([]interface{}, 0, len(c)+1)
		for _, s := range c {
			out = append(out, s)
		}
		(*m)["@context"] = append(out, Secp256k1SuiteContextNarrow)
	default:
		return fmt.Errorf("document @context has unexpected type %T", c)
	}

	return nil
}

// definesSecp256k1Suite reports whether the document's @context defines
// EcdsaSecp256k1Signature2019 — either through the VC 1.1 base context, which
// carries the suite's own scoped context, or through a security context the
// caller added.
func (m *JSONMap) definesSecp256k1Suite() bool {
	defines := func(s string) bool {
		return s == credentialsV1Context ||
			s == Secp256k1SuiteContext ||
			s == Secp256k1SuiteContextNarrow
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
