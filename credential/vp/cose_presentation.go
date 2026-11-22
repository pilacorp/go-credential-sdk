package vp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/internal/cose"
	"github.com/pilacorp/go-credential-sdk/credential/internal/jwtutil"
	"github.com/pilacorp/go-credential-sdk/credential/internal/vcdm"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// COSEPresentation implements W3C VC 2.0 Securing Verifiable Presentations
// using COSE (vc-jose-cose §3.3.2). The unsecured Verifiable Presentation is
// the unencoded COSE_Sign1 payload (JSON bytes), and the protected header
// carries typ: "application/vp+cose".
type COSEPresentation struct {
	raw         []byte           // Full COSE_Sign1 bytes (nil until signed)
	payloadData PresentationData // Unsecured VP as PresentationData
	payloadJSON []byte           // JSON encoding of the payload
	signed      bool             // Whether a signature is attached
	signingKey  jwt.SigningKey   // Verification method; zero for a parsed presentation
}

var _ Presentation = (*COSEPresentation)(nil)

// Media types for COSE-secured presentations per vc-jose-cose.
const (
	TypeVPCOSE = "vp+cose"
	// TypeCOSE is what GetType reports for a presentation secured with COSE.
	TypeCOSE = "COSE"
)

// NewCOSEPresentation creates a new Verifiable Presentation secured with COSE
// per W3C vc-jose-cose §3.3.2.
func NewCOSEPresentation(vpc PresentationContents, opts ...PresentationOpt) (*COSEPresentation, error) {
	if len(vpc.Context) == 0 {
		vpc.Context = []interface{}{"https://www.w3.org/ns/credentials/v2"}
	}

	m, err := serializePresentationContents(&vpc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize presentation contents: %w", err)
	}

	payloadData := PresentationData(m)
	options := getOptions(opts...)

	if err := requireJOSEPresentation(payloadData); err != nil {
		return nil, err
	}

	// Envelope credentials. COSE-secured VCs use data:application/vc+cose;base64,<b64>.
	// JOSE-secured VCs still use data:application/vc+jwt,<token> (or vc+sd-jwt).
	if len(vpc.VerifiableCredentials) > 0 {
		envelopedList := make([]interface{}, len(vpc.VerifiableCredentials))
		for i, cred := range vpc.VerifiableCredentials {
			serialized, err := cred.Serialize()
			if err != nil {
				return nil, fmt.Errorf("failed to serialize credential at index %d: %w", i, err)
			}

			var envelope map[string]interface{}
			switch s := serialized.(type) {
			case string:
				// JOSE credential: data:application/vc+jwt,<token> or vc+sd-jwt
				mediaType, merr := envelopeMediaType(s)
				if merr != nil {
					return nil, fmt.Errorf("credential at index %d: %w", i, merr)
				}
				envelope = map[string]interface{}{
					"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
					"type":     []interface{}{vc.TypeEnvelopedVC},
					"id":       fmt.Sprintf("data:application/%s,%s", mediaType, s),
				}
			case []byte:
				// COSE credential: data:application/vc+cose;base64,<b64>
				b64 := base64.StdEncoding.EncodeToString(s)
				envelope = map[string]interface{}{
					"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
					"type":     []interface{}{vc.TypeEnvelopedVC},
					"id":       fmt.Sprintf("data:application/%s;base64,%s", vc.TypeVCCOSE, b64),
				}
			default:
				return nil, fmt.Errorf("credential at index %d serialized to %T, want string or []byte", i, serialized)
			}
			envelopedList[i] = envelope
		}
		payloadData["verifiableCredential"] = envelopedList
	}

	// Challenge/domain → nonce and aud.
	if options.challenge != "" {
		payloadData["nonce"] = options.challenge
	}
	if options.domain != "" {
		payloadData["aud"] = options.domain
	}

	delete(payloadData, "vc")
	delete(payloadData, "vp")

	jwtutil.SetIssuedAt(payloadData, time.Now())

	signingKey, err := jwt.ResolveSigningKey(context.Background(), vpc.Holder,
		"authentication", options.verificationMethodKey, options.resolver)
	if err != nil {
		return nil, err
	}

	payloadJSON, err := json.Marshal(payloadData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	return &COSEPresentation{
		payloadData: payloadData,
		payloadJSON: payloadJSON,
		signingKey:  signingKey,
	}, nil
}

// ParseCOSEPresentation parses a COSE_Sign1 presentation. The input is raw
// CBOR bytes (CBOR tag 18).
func ParseCOSEPresentation(data []byte, opts ...PresentationOpt) (*COSEPresentation, error) {
	if !cose.IsCOSESign1(data) {
		return nil, fmt.Errorf("input is not a COSE_Sign1 message")
	}

	prot, payload, _, err := cose.Parse1(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse COSE_Sign1: %w", err)
	}

	if !isCOSEPresentationTyp(prot.Typ) {
		return nil, fmt.Errorf("invalid COSE typ for presentation: got %q, want %q",
			prot.Typ, "application/"+TypeVPCOSE)
	}

	var payloadMap map[string]interface{}
	if err := json.Unmarshal(payload, &payloadMap); err != nil {
		return nil, fmt.Errorf("COSE payload is not valid JSON: %w", err)
	}

	if _, hasVC := payloadMap["vc"]; hasVC {
		return nil, fmt.Errorf("invalid vc-jose-cose: 'vc' claim MUST NOT be present in payload")
	}
	if _, hasVP := payloadMap["vp"]; hasVP {
		return nil, fmt.Errorf("invalid vc-jose-cose: 'vp' claim MUST NOT be present in payload")
	}

	if err := requireCOSEPresentation(PresentationData(payloadMap)); err != nil {
		return nil, err
	}
	if err := requireEnvelopedCredentialsCOSE(PresentationData(payloadMap)); err != nil {
		return nil, err
	}

	p := &COSEPresentation{
		raw:         append([]byte(nil), data...),
		payloadData: PresentationData(payloadMap),
		payloadJSON: payload,
		signed:      true,
	}

	return p, p.executeOptions(opts...)
}

func isCOSEPresentationTyp(typ string) bool {
	return typ == "application/"+TypeVPCOSE || typ == TypeVPCOSE
}

// requireCOSEPresentation checks the payload is a VC 2.0 presentation.
func requireCOSEPresentation(m PresentationData) error {
	if first := vcdm.FirstContext(m["@context"]); first != vcdm.ContextV2 {
		return fmt.Errorf("%s payload must name %q first in @context, got %q",
			TypeVPCOSE, vcdm.ContextV2, first)
	}
	if !vcdm.HasType(m["type"], typeVerifiablePresentation) {
		return fmt.Errorf("%s payload must have type %s", TypeVPCOSE, typeVerifiablePresentation)
	}
	return nil
}

// requireEnvelopedCredentialsCOSE checks credentials in a vp+cose are
// enveloped, allowing both JOSE and COSE envelope formats.
func requireEnvelopedCredentialsCOSE(m PresentationData) error {
	var items []interface{}
	switch v := m["verifiableCredential"].(type) {
	case nil:
		return nil
	case []interface{}:
		items = v
	default:
		items = []interface{}{v}
	}

	for i, item := range items {
		entry, ok := item.(map[string]interface{})
		if !ok || !vcdm.HasType(entry["type"], vc.TypeEnvelopedVC) {
			return fmt.Errorf(
				"credential at index %d must be an %s; a %s carries credentials enveloped, not bare",
				i, vc.TypeEnvelopedVC, TypeVPCOSE)
		}

		if first := vcdm.FirstContext(entry["@context"]); first != vcdm.ContextV2 {
			return fmt.Errorf(
				"credential at index %d: enveloped credential @context must start with %s, got %q",
				i, vcdm.ContextV2, first)
		}

		id, _ := entry["id"].(string)
		if !isEnvelopedDataURL(id) {
			return fmt.Errorf(
				"credential at index %d: enveloped credential id must be a data: URL "+
					"with media type application/vc+jwt, application/vc+sd-jwt, or application/vc+cose, got %q", i, id)
		}
	}

	return nil
}

// Deprecated: prefer AddProofByProvider.
func (p *COSEPresentation) AddProof(priv string, opts ...PresentationOpt) error {
	defaultSigner, err := signer.NewDefaultProvider(priv)
	if err != nil {
		return fmt.Errorf("failed to create default signer: %w", err)
	}
	return p.AddProofByProvider(defaultSigner, opts...)
}

func (p *COSEPresentation) AddProofByProvider(signerProvider signer.SignerProvider, opts ...PresentationOpt) error {
	if signerProvider == nil {
		return fmt.Errorf("signer provider cannot be nil")
	}

	options := getOptions(opts...)
	if p.signed && !options.replaceProof {
		return fmt.Errorf(
			"presentation is already signed; pass WithReplaceProof to do so deliberately")
	}

	coseAlg, err := cose.COSEAlgForJOSE(p.signingKey.Alg)
	if err != nil {
		return err
	}

	prot := cose.Protected{
		Alg:         coseAlg,
		ContentType: "application/vp",
		Kid:         p.signingKey.ID,
		Typ:         "application/" + TypeVPCOSE,
	}

	signFn := func(digest []byte) ([]byte, error) {
		raw, err := signerProvider.Sign(digest)
		if err != nil {
			return nil, err
		}
		sig := jwtutil.TrimRecoveryByte(raw)
		return jwtutil.NormalizeLowS(p.signingKey.Alg, sig), nil
	}

	coseBytes, err := cose.Sign1(prot, p.payloadJSON, signFn)
	if err != nil {
		return fmt.Errorf("COSE_Sign1 signing failed: %w", err)
	}

	if p.signingKey.PublicKey != nil {
		if _, _, verr := cose.Verify1(coseBytes, p.signingKey.PublicKey, []int{coseAlg}); verr != nil {
			return fmt.Errorf("the signature does not verify against verification method %q: %w",
				p.signingKey.ID, verr)
		}
	}

	p.raw = coseBytes
	p.signed = true

	return nil
}

// AddCustomProof is not supported for COSE presentations.
func (p *COSEPresentation) AddCustomProof(proof *dto.Proof, opts ...PresentationOpt) error {
	return fmt.Errorf("AddCustomProof is not supported for COSE presentations; use AddProofByProvider")
}

func (p *COSEPresentation) GetSigningInput() ([]byte, error) {
	return p.payloadJSON, nil
}

func (p *COSEPresentation) Verify(opts ...PresentationOpt) error {
	opts = append(opts, WithVerifyProof())
	return p.executeOptions(opts...)
}

func (p *COSEPresentation) Serialize() (any, error) {
	if !p.signed {
		return nil, fmt.Errorf("presentation must be signed before serializing")
	}
	return p.raw, nil
}

func (p *COSEPresentation) Hash() (string, error) {
	if !p.signed {
		return "", fmt.Errorf("presentation must be signed before hashing")
	}
	h := sha256.Sum256(p.raw)
	return hex.EncodeToString(h[:]), nil
}

func (p *COSEPresentation) GetContents() ([]byte, error) {
	return json.Marshal(p.payloadData)
}

func (p *COSEPresentation) GetType() string {
	return TypeCOSE
}

func (p *COSEPresentation) ExtractField(path string) any {
	return extractFieldFromMap(map[string]interface{}(p.payloadData), path)
}

func (p *COSEPresentation) executeOptions(opts ...PresentationOpt) error {
	options := getOptions(opts...)

	if options.isValidateVC {
		if err := verifyCredentials(p.payloadData, options); err != nil {
			return fmt.Errorf("verify credentials: %w", err)
		}
	}

	if options.isVerifyProof {
		if err := p.verifyCOSEProof(options); err != nil {
			return err
		}
	}

	if options.isCheckExpiration {
		if err := jwtutil.CheckTimeClaims(map[string]interface{}(p.payloadData), options.leeway); err != nil {
			return err
		}
	}

	return nil
}

func (p *COSEPresentation) verifyCOSEProof(options *presentationOptions) error {
	if !p.signed || len(p.raw) == 0 {
		return fmt.Errorf("presentation is not signed")
	}

	prot, _, _, err := cose.Parse1(p.raw)
	if err != nil {
		return fmt.Errorf("parse COSE_Sign1: %w", err)
	}

	kid := prot.Kid
	if kid == "" {
		return fmt.Errorf("COSE protected header has no kid")
	}

	var body map[string]interface{}
	if err := json.Unmarshal(p.payloadJSON, &body); err != nil {
		return fmt.Errorf("invalid payload JSON: %w", err)
	}

	holder := vcdm.DidFromPayload(body, "holder")
	if holder == "" {
		return fmt.Errorf("COSE presentation has no holder")
	}

	// VC-JOSE-COSE §4.1.2: resolve a relative kid (#fragment) only when iss
	// is present and identifies the same entity as holder. When iss is absent,
	// the kid MUST be an absolute URL.
	if len(kid) > 0 && kid[0] == '#' {
		iss, _ := body["iss"].(string)
		if iss == "" {
			return fmt.Errorf("relative kid %q requires an iss claim", kid)
		}
		kid = iss + kid
	}

	if options.resolver == nil {
		return fmt.Errorf("document resolver is not configured")
	}

	doc, err := options.resolver.ResolveDocument(context.Background(), holder)
	if err != nil {
		return fmt.Errorf("failed to resolve DID document for holder %q: %w", holder, err)
	}

	vm, err := verificationmethod.FindVerificationMethod(doc, kid)
	if err != nil {
		return fmt.Errorf("failed to resolve verification method: %w", err)
	}

	joseAlg, err := cose.JOSEAlgForCOSE(prot.Alg)
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

	if _, _, verr := cose.Verify1(p.raw, publicKey, []int{prot.Alg}); verr != nil {
		return fmt.Errorf("COSE signature verification failed: %w", verr)
	}

	// Same post-crypto checks as the JOSE path: purpose and revocation.
	issuedAt, ierr := jwt.IssuedAtFromPayload(body)
	if ierr != nil {
		return ierr
	}
	if err := jwt.StrictPurposeCheck(doc, vm, "authentication", issuedAt); err != nil {
		return err
	}

	// Challenge / domain (nonce / aud) — same check as the JOSE VP.
	if err := p.checkChallengeAndDomain(options); err != nil {
		return err
	}

	return nil
}

// checkChallengeAndDomain enforces the nonce/aud values in the payload against
// the expected challenge/domain the verifier supplied. Same logic as the JOSE
// presentation's checkChallengeAndDomain.
func (p *COSEPresentation) checkChallengeAndDomain(options *presentationOptions) error {
	if options.expectedChallenge != "" {
		nonce, _ := p.payloadData["nonce"].(string)
		if nonce != options.expectedChallenge {
			return fmt.Errorf("nonce %q does not match expected challenge %q", nonce, options.expectedChallenge)
		}
	}
	return checkAudience(p.payloadData["aud"], options)
}
