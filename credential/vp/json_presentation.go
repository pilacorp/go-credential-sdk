package vp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

type JSONPresentation struct {
	presentationData PresentationData
}

var _ Presentation = (*JSONPresentation)(nil)

func NewJSONPresentation(vpc PresentationContents, opts ...PresentationOpt) (*JSONPresentation, error) {
	m, err := serializePresentationContents(&vpc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize presentation contents: %w", err)
	}

	e := &JSONPresentation{presentationData: m}

	return e, e.executeOptions(opts...)
}

func ParseJSONPresentation(rawJSON []byte, opts ...PresentationOpt) (*JSONPresentation, error) {
	if len(rawJSON) == 0 {
		return nil, fmt.Errorf("JSON string is empty")
	}

	if !isJSONPresentation(rawJSON) {
		return nil, fmt.Errorf("invalid JSON format")
	}

	var m PresentationData
	if err := json.Unmarshal(rawJSON, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal presentation: %w", err)
	}

	e := &JSONPresentation{presentationData: m}

	return e, e.executeOptions(opts...)
}

// Deprecated: prefer AddProofByProvider with a signer provider; this legacy signing helper may be removed in a future release.
func (e *JSONPresentation) AddProof(priv string, opts ...PresentationOpt) error {
	p256Signer, err := signer.NewP256ProviderFromHex(priv)
	if err != nil {
		return fmt.Errorf("failed to create P-256 signer: %w", err)
	}
	return e.AddProofByProvider(p256Signer, opts...)
}

// AddProofByProvider signs the presentation, bound to the VM
// WithVerificationMethodKey pins, or by default the holder's only VM / latest
// active authentication VM.
//
// The proof suite follows the verification method's key: a P-256 key produces
// an ecdsa-rdfc-2019 proof, a secp256k1 key an EcdsaSecp256k1Signature2019 one.
// The second suite needs its terms defined, so its @context is added to the
// presentation unless it already defines them.
//
// Verification stays permissive: secp256k1, hex proofValues and
// JsonWebSignature2020 presentations issued by earlier versions still verify.
//
// A resolver is REQUIRED at signing time: the SDK reads the VM's key type from
// the resolved DID document.
func (e *JSONPresentation) AddProofByProvider(provider signer.SignerProvider, opts ...PresentationOpt) error {
	if provider == nil {
		return fmt.Errorf("signer provider cannot be nil")
	}

	if err := e.executeOptions(signingOptions(opts)...); err != nil {
		return err
	}

	vm, vmURL, err := e.resolveSigningVMEntry(opts...)
	if err != nil {
		return err
	}

	kind, ok := verificationmethod.VMKeyKind(vm)
	if !ok {
		return fmt.Errorf("verification method %q has an unrecognized key type", vmURL)
	}

	options := getOptions(opts...)
	m := (*jsonmap.JSONMap)(&e.presentationData)
	suite, err := jsonmap.SigningSuiteForKey(kind)
	if err != nil {
		return err
	}

	vmPub, err := verificationmethod.ECPubFromVM(vm)
	if err != nil {
		return fmt.Errorf("verification method %q: %w", vmURL, err)
	}

	proofOpts := []jsonmap.ProofOpt{
		jsonmap.WithVMPublicKey(vmPub),
		jsonmap.WithChallenge(options.challenge),
		jsonmap.WithDomain(options.domain),
	}

	if suite == jsonmap.EcdsaSecp256k1Signature2019 {
		return m.AddEcdsaSecp256k1Proof(provider, vmURL, "authentication", proofOpts...)
	}
	return m.AddECDSAProof(provider, vmURL, "authentication", proofOpts...)
}

// resolveSigningVMEntry resolves the verification method to sign with (pinned
// kid > latest active authentication VM) and returns the entry so the caller
// can read its key type and choose the cryptosuite.
func (e *JSONPresentation) resolveSigningVMEntry(opts ...PresentationOpt) (*verificationmethod.VerificationMethodEntry, string, error) {
	holder, ok := jsonmap.DIDFromField(e.presentationData["holder"])
	if !ok {
		return nil, "", fmt.Errorf("holder is missing or invalid")
	}

	options := getOptions(opts...)

	return verificationmethod.ResolveSigningVM(context.Background(), holder, "authentication", options.verificationMethodKey, options.resolver)
}

// GetSigningInput returns the SHA-256 digest of the canonicalized document
// body. For an ecdsa-rdfc-2019 proof, pass it to CreateProofSigning to obtain
// the digest the external signer signs.
func (e *JSONPresentation) GetSigningInput() ([]byte, error) {
	return (*jsonmap.JSONMap)(&e.presentationData).DocumentDigest()
}

// CreateProofSigning returns the 32-byte digest the external signer signs:
// SHA-256 of the section 3.2.4 hashData built from docHash and the proof options.
func (e *JSONPresentation) CreateProofSigning(docHash []byte, proof *dto.Proof) ([]byte, error) {
	hashData, err := (*jsonmap.JSONMap)(&e.presentationData).ProofHashData(docHash, proof)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(hashData)
	return digest[:], nil
}

// AddCustomProof attaches a proof signed outside the SDK, the last step of
// GetSigningInput → CreateProofSigning → sign → AddCustomProof.
//
// The proof is attached as given, apart from the proofValue encoding: this
// release issues base58btc ("z") values only, and the legacy hex form is
// refused.
//
// TODO(next PR): verify the signature against the verification method before
// attaching, so a proof signed over the wrong digest or by the wrong key fails
// here instead of at the verifier.
func (e *JSONPresentation) AddCustomProof(proof *dto.Proof, opts ...PresentationOpt) error {
	if proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}

	if proof.Type == jsonmap.DataIntegrityProof && proof.Cryptosuite == jsonmap.ECDSARDFC2019 &&
		!strings.HasPrefix(proof.ProofValue, jsonmap.MultibaseBase58BTCPrefix) {
		return fmt.Errorf("proofValue must be multibase base58btc (%q prefix); hex proofs are no longer issued", jsonmap.MultibaseBase58BTCPrefix)
	}
	// The proof arrives signed: challenge, domain and verificationMethod are
	// part of the proof configuration the signature covers, so an option
	// cannot change them here.
	if o := getOptions(opts...); o.challenge != "" || o.domain != "" || o.verificationMethodKey != "" {
		return fmt.Errorf("WithChallenge / WithDomain / WithVerificationMethodKey cannot be applied by AddCustomProof: set proof.Challenge, proof.Domain and proof.VerificationMethod on the proof you sign")
	}

	if err := e.executeOptions(signingOptions(opts)...); err != nil {
		return err
	}

	return (*jsonmap.JSONMap)(&e.presentationData).AddCustomProof(proof)
}

func (e *JSONPresentation) Verify(opts ...PresentationOpt) error {
	opts = append(opts, WithVerifyProof())

	return e.executeOptions(opts...)
}

func (e *JSONPresentation) Serialize() (interface{}, error) {
	// Check if presentation has proof
	if e.presentationData["proof"] == nil {
		return nil, fmt.Errorf("presentation must have proof before serialization")
	}

	// Return the JSON presentation object directly
	return map[string]interface{}(e.presentationData), nil
}

func (e *JSONPresentation) GetContents() ([]byte, error) {
	return (*jsonmap.JSONMap)(&e.presentationData).ToJSON()
}

func (e *JSONPresentation) GetType() string {
	return "JSON"
}

func (e *JSONPresentation) ExtractField(path string) interface{} {
	return extractFieldFromMap(e.presentationData, path)
}

func (e *JSONPresentation) executeOptions(opts ...PresentationOpt) error {
	options := getOptions(opts...)

	if options.isValidateVC {
		if err := verifyCredentials(PresentationData(e.presentationData), options); err != nil {
			return fmt.Errorf("failed to verify presentation: %w", err)
		}
	}

	if options.isCheckExpiration {
		if err := checkExpiration(PresentationData(e.presentationData)); err != nil {
			return fmt.Errorf("failed to check expiration: %w", err)
		}
	}

	if options.isVerifyProof {
		isValid, err := (*jsonmap.JSONMap)(&e.presentationData).VerifyProof(
			options.resolver,
			options.proofVerificationMethod,
		)
		if err != nil {
			return fmt.Errorf("failed to verify presentation: %w", err)
		}
		if !isValid {
			return fmt.Errorf("invalid proof")
		}
		if err := e.checkChallengeAndDomain(options); err != nil {
			return fmt.Errorf("failed to verify presentation: %w", err)
		}
	}

	return nil
}

// checkChallengeAndDomain enforces WithExpectedChallenge / WithExpectedDomain
// on the proofs VerifyProof just validated: every checked proof (or only the
// WithProofVerificationMethod one) must carry the expected values.
//
// It runs after signature verification, but only an ecdsa-rdfc-2019 proof signs
// its challenge and domain. A legacy hex or JsonWebSignature2020 signature
// covers the document alone, so on those proofs these values are not bound to
// the signer and prove nothing about who the presentation was made for.
func (e *JSONPresentation) checkChallengeAndDomain(options *presentationOptions) error {
	if options.expectedChallenge == "" && options.expectedDomain == "" {
		return nil
	}
	proofs, err := (*jsonmap.JSONMap)(&e.presentationData).Proofs()
	if err != nil {
		return err
	}
	for _, p := range proofs {
		if options.proofVerificationMethod != "" && p.VerificationMethod != options.proofVerificationMethod {
			continue
		}
		if options.expectedChallenge != "" && p.Challenge != options.expectedChallenge {
			return fmt.Errorf("proof (%s): challenge %q does not match expected %q", p.VerificationMethod, p.Challenge, options.expectedChallenge)
		}
		if options.expectedDomain != "" && !domainContains(p.Domain, options.expectedDomain) {
			return fmt.Errorf("proof (%s): domain %v does not match expected %q", p.VerificationMethod, p.Domain, options.expectedDomain)
		}
	}
	return nil
}

// domainContains reports whether the proof's domain covers expected. Data
// Integrity § 2.1 allows domain to be a single string or a set, so a
// presentation bound to several relying parties satisfies any one of them.
func domainContains(domain dto.StringOrStrings, expected string) bool {
	for _, d := range domain {
		if d == expected {
			return true
		}
	}
	return false
}
