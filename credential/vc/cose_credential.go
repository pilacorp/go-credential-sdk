package vc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	coseinternal "github.com/pilacorp/go-credential-sdk/credential/internal/cose"
	"github.com/pilacorp/go-credential-sdk/credential/internal/jwtutil"
	"github.com/pilacorp/go-credential-sdk/credential/internal/vcdm"
	"golang.org/x/sync/errgroup"
)

// COSECredential implements W3C VC 2.0 Securing Verifiable Credentials using
// COSE (vc-jose-cose). The unsecured Verifiable Credential is the unencoded
// COSE_Sign1 payload (JSON bytes), and the protected header carries
// typ: "application/vc+cose".
type COSECredential struct {
	raw         []byte         // Full COSE_Sign1 bytes (nil until signed)
	payloadData CredentialData // Unsecured VC as CredentialData
	payloadJSON []byte         // JSON encoding of the payload
	signed      bool           // Whether a signature is attached
	signingKey  jwt.SigningKey // Verification method; zero for a parsed credential
}

var _ Credential = (*COSECredential)(nil)

// Media types for COSE-secured credentials per vc-jose-cose.
const (
	TypeVCCOSE = "vc+cose"
	// TypeCOSE is what GetType reports for a credential secured with COSE.
	TypeCOSE = "COSE"
)

// NewCOSECredential creates a new Verifiable Credential secured with COSE per
// W3C vc-jose-cose §3.3.1. The credential is not signed until AddProofByProvider
// is called.
func NewCOSECredential(vcc CredentialContents, opts ...CredentialOpt) (*COSECredential, error) {
	if len(vcc.Context) == 0 {
		vcc.Context = []interface{}{credentialsV2Context}
	} else if err := requireV2Context(vcc.Context); err != nil {
		return nil, err
	}

	m, err := serializeCredentialContents(&vcc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize credential contents: %w", err)
	}

	vcMap := normalizeCredentialData(m)
	if err := requireJOSECredential(CredentialData(vcMap)); err != nil {
		return nil, err
	}

	// Per vc-jose-cose: vc and vp claims MUST NOT be present.
	delete(vcMap, "vc")
	delete(vcMap, "vp")

	jwtutil.SetIssuedAt(vcMap, time.Now())

	payloadData := CredentialData(vcMap)

	options := getOptions(opts...)

	signingKey, err := jwt.ResolveSigningKey(context.Background(), vcc.Issuer,
		"assertionMethod", options.verificationMethodKey, options.resolver)
	if err != nil {
		return nil, err
	}

	payloadJSON, err := json.Marshal(vcMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	return &COSECredential{
		payloadData: payloadData,
		payloadJSON: payloadJSON,
		signingKey:  signingKey,
	}, nil
}

// ParseCOSECredential parses a COSE_Sign1 credential. The input is raw CBOR
// bytes (CBOR tag 18).
func ParseCOSECredential(data []byte, opts ...CredentialOpt) (*COSECredential, error) {
	if !coseinternal.IsCOSESign1(data) {
		return nil, fmt.Errorf("input is not a COSE_Sign1 message")
	}

	prot, payload, _, err := coseinternal.Parse1(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse COSE_Sign1: %w", err)
	}

	// Check the typ header names a vc+cose credential.
	if !isCOSECredentialTyp(prot.Typ) {
		return nil, fmt.Errorf("invalid COSE typ for credential: got %q, want %q",
			prot.Typ, "application/"+TypeVCCOSE)
	}

	var payloadMap map[string]interface{}
	if err := json.Unmarshal(payload, &payloadMap); err != nil {
		return nil, fmt.Errorf("COSE payload is not valid JSON: %w", err)
	}

	// Same validation as JOSE: no vc/vp claims, must be a VC 2.0 document.
	if _, hasVC := payloadMap["vc"]; hasVC {
		return nil, fmt.Errorf("invalid vc-jose-cose: 'vc' claim MUST NOT be present in payload")
	}
	if _, hasVP := payloadMap["vp"]; hasVP {
		return nil, fmt.Errorf("invalid vc-jose-cose: 'vp' claim MUST NOT be present in payload")
	}

	if err := requireJOSECredential(CredentialData(payloadMap)); err != nil {
		return nil, err
	}

	c := &COSECredential{
		raw:         append([]byte(nil), data...),
		payloadData: CredentialData(payloadMap),
		payloadJSON: payload,
		signed:      true,
	}

	return c, c.executeOptions(opts...)
}

// isCOSECredentialTyp reports whether typ names a COSE-secured credential.
func isCOSECredentialTyp(typ string) bool {
	return typ == "application/"+TypeVCCOSE || typ == TypeVCCOSE
}

// AddProof signs the credential with a private key hex string.
// Deprecated: prefer AddProofByProvider.
func (c *COSECredential) AddProof(priv string, opts ...CredentialOpt) error {
	defaultSigner, err := signer.NewDefaultProvider(priv)
	if err != nil {
		return fmt.Errorf("failed to create default signer: %w", err)
	}
	return c.AddProofByProvider(defaultSigner, opts...)
}

// AddProofByProvider signs the credential using COSE_Sign1 with the given
// signer provider. The signer receives a SHA-256 digest (of the COSE
// Sig_structure) and returns 64- or 65-byte r||s.
func (c *COSECredential) AddProofByProvider(signerProvider signer.SignerProvider, opts ...CredentialOpt) error {
	if signerProvider == nil {
		return fmt.Errorf("signer provider cannot be nil")
	}

	o := getOptions(opts...)
	if err := rejectBuildTimeOptions(o); err != nil {
		return err
	}
	if c.signingKey.PublicKey == nil {
		return fmt.Errorf(
			"no verification method is bound: the credential was parsed, not built — use NewCOSECredential to sign it")
	}
	if c.signed && !o.replaceProof {
		return fmt.Errorf(
			"credential is already signed; signing again would replace that signature — pass WithReplaceProof to do so deliberately")
	}

	coseAlg, err := coseinternal.COSEAlgForJOSE(c.signingKey.Alg)
	if err != nil {
		return err
	}

	prot := coseinternal.Protected{
		Alg:         coseAlg,
		ContentType: "application/vc",
		Kid:         c.signingKey.ID,
		Typ:         "application/" + TypeVCCOSE,
	}

	signFn := func(digest []byte) ([]byte, error) {
		raw, err := signerProvider.Sign(digest)
		if err != nil {
			return nil, err
		}
		sig := jwtutil.TrimRecoveryByte(raw)
		return jwtutil.NormalizeLowS(c.signingKey.Alg, sig), nil
	}

	coseBytes, err := coseinternal.Sign1(prot, c.payloadJSON, signFn)
	if err != nil {
		return fmt.Errorf("COSE_Sign1 signing failed: %w", err)
	}

	// Verify the signature against the signing key's public key to catch
	// signer/key mismatches early, same as the JOSE path does.
	if c.signingKey.PublicKey != nil {
		allowedAlgs := []int{coseAlg}
		if _, _, verr := coseinternal.Verify1(coseBytes, c.signingKey.PublicKey, allowedAlgs); verr != nil {
			return fmt.Errorf("the signature does not verify against verification method %q: %w",
				c.signingKey.ID, verr)
		}
	}

	c.raw = coseBytes
	c.signed = true

	return nil
}

// AddCustomProof attaches a pre-built COSE_Sign1 message. The raw bytes must
// be a valid COSE_Sign1 whose payload matches this credential.
func (c *COSECredential) AddCustomProof(proof *dto.Proof, opts ...CredentialOpt) error {
	return fmt.Errorf("AddCustomProof is not supported for COSE credentials; use AddProofByProvider")
}

// GetSigningInput returns the payload JSON that the COSE_Sign1 signature
// covers (via the Sig_structure). For COSE the caller cannot build a
// Sig_structure without the protected header, so external signing uses
// AddProofByProvider with a SignerProvider that delegates to an HSM.
func (c *COSECredential) GetSigningInput() ([]byte, error) {
	return c.payloadJSON, nil
}

func (c *COSECredential) Verify(opts ...CredentialOpt) error {
	opts = append(opts, WithVerifyProof())
	return c.executeOptions(opts...)
}

// Serialize returns the full COSE_Sign1 bytes.
func (c *COSECredential) Serialize() (any, error) {
	if !c.signed {
		return nil, fmt.Errorf("credential must be signed before serializing")
	}
	return c.raw, nil
}

// Hash returns SHA-256 of the full COSE_Sign1 bytes, hex-encoded.
func (c *COSECredential) Hash() (string, error) {
	if !c.signed {
		return "", fmt.Errorf("credential must be signed before hashing")
	}
	h := sha256.Sum256(c.raw)
	return hex.EncodeToString(h[:]), nil
}

func (c *COSECredential) GetContents() ([]byte, error) {
	return json.Marshal(c.payloadData)
}

func (c *COSECredential) GetType() string {
	return TypeCOSE
}

func (c *COSECredential) ExtractField(path string) any {
	return extractFieldFromMap(map[string]interface{}(c.payloadData), path)
}

func (c *COSECredential) executeOptions(opts ...CredentialOpt) error {
	options := getOptions(opts...)

	g := &errgroup.Group{}

	if options.isValidateSchema {
		g.Go(func() error {
			if err := validateCredential(c.payloadData, options); err != nil {
				return fmt.Errorf("validate credential: %w", err)
			}
			return nil
		})
	}

	if options.isCheckRevocation {
		g.Go(func() error {
			if err := checkRevocation(c.payloadData); err != nil {
				return fmt.Errorf("check revocation: %w", err)
			}
			return nil
		})
	}

	if options.isVerifyProof {
		g.Go(func() error {
			if err := c.verifyCOSEProof(options); err != nil {
				return fmt.Errorf("verify proof: %w", err)
			}
			// exp and nbf bound the signature, not the credential, so they
			// belong to this check and not to the optional expiry check on
			// validFrom/validUntil.
			if err := jwtutil.CheckTimeClaims(map[string]interface{}(c.payloadData), options.leeway); err != nil {
				return fmt.Errorf("verify proof: %w", err)
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("credential verification failed: %w", err)
	}

	if options.isCheckExpiration {
		if err := checkExpiration(c.payloadData, options.leeway); err != nil {
			return fmt.Errorf("failed to check expiration: %w", err)
		}
	}

	return nil
}

func (c *COSECredential) verifyCOSEProof(options *credentialOptions) error {
	if !c.signed || len(c.raw) == 0 {
		return fmt.Errorf("credential is not signed")
	}

	prot, _, _, err := coseinternal.Parse1(c.raw)
	if err != nil {
		return fmt.Errorf("parse COSE_Sign1: %w", err)
	}

	kid := prot.Kid
	if kid == "" {
		return fmt.Errorf("COSE protected header has no kid")
	}

	// Determine purpose and signer from the payload, same as the JOSE path.
	var body map[string]interface{}
	if err := json.Unmarshal(c.payloadJSON, &body); err != nil {
		return fmt.Errorf("invalid payload JSON: %w", err)
	}

	issuer := vcdm.DidFromPayload(body, "issuer")
	if issuer == "" {
		return fmt.Errorf("COSE credential has no issuer")
	}

	// VC-JOSE-COSE §4.1.2: resolve a relative kid (#fragment) only when iss
	// is present and identifies the same entity as issuer. When iss is absent,
	// the kid MUST be an absolute URL.
	if len(kid) > 0 && kid[0] == '#' {
		iss, _ := body["iss"].(string)
		if iss == "" {
			return fmt.Errorf("relative kid %q requires an iss claim", kid)
		}
		if iss != issuer {
			return fmt.Errorf("iss %q does not match issuer %q", iss, issuer)
		}
		kid = iss + kid
	}

	if options.resolver == nil {
		return fmt.Errorf("document resolver is not configured")
	}

	doc, err := options.resolver.ResolveDocument(context.Background(), issuer)
	if err != nil {
		return fmt.Errorf("failed to resolve DID document for issuer %q: %w", issuer, err)
	}

	vm, err := verificationmethod.FindVerificationMethod(doc, kid)
	if err != nil {
		return fmt.Errorf("failed to resolve verification method: %w", err)
	}

	joseAlg, err := coseinternal.JOSEAlgForCOSE(prot.Alg)
	if err != nil {
		return err
	}
	kind, ok := verificationmethod.VMKeyKind(vm)
	if !ok {
		return fmt.Errorf("verification method %q has an unrecognized key type", vm.ID)
	}
	wantAlg, err := jwt.AlgForKeyKind(kind)
	if err != nil {
		return fmt.Errorf("verification method %q: %w", vm.ID, err)
	}
	if joseAlg != wantAlg {
		return fmt.Errorf("COSE alg %d (JOSE %s) does not match verification method key kind (wants %s)",
			prot.Alg, joseAlg, wantAlg)
	}

	publicKey, err := verificationmethod.ECPubFromVM(vm)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	if _, _, verr := coseinternal.Verify1(c.raw, publicKey, []int{prot.Alg}); verr != nil {
		return fmt.Errorf("COSE signature verification failed: %w", verr)
	}

	// Same post-crypto checks as the JOSE path: purpose and revocation.
	issuedAt, ierr := jwt.IssuedAtFromPayload(body)
	if ierr != nil {
		return ierr
	}
	if err := jwt.StrictPurposeCheck(doc, vm, "assertionMethod", issuedAt); err != nil {
		return err
	}

	return nil
}
