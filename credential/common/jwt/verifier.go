package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// JWTVerifier handles JWT verification operations. It always enforces the
// strict-purpose check after crypto verification.
type JWTVerifier struct {
	docResolver verificationmethod.ResolverProvider
}

// VerifierOption mutates JWTVerifier construction.
type VerifierOption func(*JWTVerifier)

func NewJWTVerifier(
	docResolver verificationmethod.ResolverProvider,
	opts ...VerifierOption,
) *JWTVerifier {
	v := &JWTVerifier{
		docResolver: docResolver,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// VerifyJWT verifies a JWT token
func (v *JWTVerifier) VerifyJWT(tokenString string) error {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}

	// Decode header to get kid
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("invalid header: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("invalid header: %w", err)
	}

	alg, ok := header["alg"].(string)
	if !ok || (alg != AlgES256K && alg != AlgES256) {
		return fmt.Errorf("unsupported algorithm: %v", header["alg"])
	}

	kid, ok := header["kid"].(string)
	if !ok {
		return fmt.Errorf("kid not found in header")
	}

	if v.docResolver == nil {
		return fmt.Errorf("document resolver is not configured")
	}

	// Which purpose the token claims decides which property names its signer:
	// a credential is signed by its issuer, a presentation by its holder. So
	// the purpose has to be known before the signer can be read, and both are
	// read before any key is resolved.
	purpose, perr := jwtProofPurpose(header, parts[1])
	if perr != nil {
		return perr
	}

	// Resolve the document by the signer DID the JWT body names, not by the
	// DID prefix of `kid`. The body is the authoritative identifier;
	// FindVerificationMethod will reject if the kid does not actually belong
	// to that signer's document.
	issuer, derr := jwtSigner(parts[1], purpose)
	if derr != nil {
		return derr
	}
	doc, derr := v.docResolver.ResolveDocument(context.Background(), issuer)
	if derr != nil {
		return fmt.Errorf("failed to resolve DID document for issuer '%s': %w", issuer, derr)
	}
	vm, verr := verificationmethod.FindVerificationMethod(doc, kid)
	if verr != nil {
		return fmt.Errorf("failed to resolve verification method: %w", verr)
	}

	// The header must not claim an algorithm the verification method's key
	// cannot produce, otherwise alg and key could be mixed.
	kind, kok := verificationmethod.VMKeyKind(vm)
	if !kok {
		return fmt.Errorf("verification method '%s' has an unrecognized key type", vm.ID)
	}
	wantAlg, aerr := AlgForKeyKind(kind)
	if aerr != nil {
		return fmt.Errorf("verification method '%s': %w", vm.ID, aerr)
	}
	if alg != wantAlg {
		return fmt.Errorf("JWT alg %q does not match verification method '%s', which holds a %s key", alg, vm.ID, kind)
	}

	publicKey, err := verificationmethod.ECPubFromVM(vm)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	signingString := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	// alg was matched to the VM's key above, so publicKey is already on the
	// curve alg names; ES256K and ES256 share the same ECDSA check.
	if err := VerifyECDSA(signingString, signature, publicKey); err != nil {
		return err
	}

	// Strict-purpose check (always on): JWT VCs use proofPurpose =
	// assertionMethod, JWT VPs use authentication. purpose was resolved
	// before the signer, above.
	issuedAt, ierr := jwtIssuedAt(parts[1])
	if ierr != nil {
		return ierr
	}
	if err := strictPurposeCheck(doc, vm, purpose, issuedAt); err != nil {
		return err
	}
	return nil
}

// jwtProofPurpose returns the proofPurpose to enforce for the JWT —
// assertionMethod for credentials and authentication for presentations.
//
// The payload decides, not the header. `typ` is written by whoever signs the
// token, while the parsers that later consume it route on the payload's own
// vc/vp claim; letting `typ` win would let a key granted only authentication
// sign a document every consumer then reads as a credential. `typ` is still
// read — a `typ` that contradicts the payload is refused rather than ignored,
// since a token that misrepresents its own kind should not be honoured either
// way. When only one of the two speaks, that one answers: VC 1.1 signs with
// typ "JWT", and a payload can carry its type inside an SD-JWT disclosure.
func jwtProofPurpose(header map[string]interface{}, payloadB64 string) (string, error) {
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return "", fmt.Errorf("invalid payload encoding: %w", err)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &body); err != nil {
		return "", fmt.Errorf("invalid payload JSON: %w", err)
	}

	carried, cerr := purposeFromBody(body)
	if cerr != nil {
		return "", cerr
	}
	declared := purposeFromTyp(header)

	switch {
	case carried != "" && declared != "" && carried != declared:
		return "", fmt.Errorf("JWT typ %q implies proofPurpose %q but its payload is a %s",
			header["typ"], declared, documentKind(carried))
	case carried != "":
		return carried, nil
	case declared != "":
		return declared, nil
	}
	return "", fmt.Errorf("JWT has neither vc/vp claims nor vc+jwt/vp+jwt typ; cannot determine proofPurpose")
}

// purposeFromTyp reads the media types vc-jose-cose gives the two document
// kinds. Anything else — including VC 1.1's "JWT" — says nothing and yields "".
func purposeFromTyp(header map[string]interface{}) string {
	typ, _ := header["typ"].(string)
	switch typ {
	case "vc+jwt", "application/vc+jwt":
		return "assertionMethod"
	case "vp+jwt", "application/vp+jwt":
		return "authentication"
	}
	return ""
}

// purposeFromBody reads the kind out of the payload: the vc/vp claim of VC 1.1,
// or the type property of a vc-jose-cose payload, which carries the unsecured
// document flat. Carrying both claims is refused — the credential and the
// presentation parsers would each accept such a token as its own kind, so no
// single proofPurpose can be enforced for it.
func purposeFromBody(body map[string]interface{}) (string, error) {
	_, hasVC := body["vc"]
	_, hasVP := body["vp"]
	switch {
	case hasVC && hasVP:
		return "", fmt.Errorf("JWT carries both vc and vp claims; its kind is ambiguous")
	case hasVC:
		return "assertionMethod", nil
	case hasVP:
		return "authentication", nil
	}

	switch t := body["type"].(type) {
	case []interface{}:
		for _, v := range t {
			if str, ok := v.(string); ok {
				if p := purposeFromType(str); p != "" {
					return p, nil
				}
			}
		}
	case string:
		return purposeFromType(t), nil
	}
	return "", nil
}

func purposeFromType(t string) string {
	switch t {
	case "VerifiableCredential":
		return "assertionMethod"
	case "VerifiablePresentation":
		return "authentication"
	}
	return ""
}

// documentKind names a purpose the way the data model does, for error text.
func documentKind(purpose string) string {
	if purpose == "assertionMethod" {
		return "credential"
	}
	return "presentation"
}

// jwtSigner returns the DID whose key signed the JWT, and refuses a token
// whose `iss` claim disagrees with the property that names the signer.
//
// Which property that is depends on what the token carries: a credential is
// signed by its issuer, a presentation by its holder. Reading `issuer` off a
// presentation would let anyone name a signer the presentation never had, so
// the two are never crossed — hence the purpose argument.
//
// vc-jose-cose puts the unsecured VC/VP in the payload itself, so `iss` may be
// absent and the property alone names the signer. When both are present they
// MUST agree: "When issuer value is a string, iss value, if present, MUST
// match issuer value" — and likewise against issuer.id when issuer is an
// object. VC 1.1 nests the document under a vc/vp claim; the same rule applies
// to the nested property.
func jwtSigner(payloadB64, purpose string) (string, error) {
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return "", fmt.Errorf("invalid payload encoding: %w", err)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &body); err != nil {
		return "", fmt.Errorf("invalid payload JSON: %w", err)
	}

	// A credential names its signer in issuer, a presentation in holder.
	field := "holder"
	if purpose == "assertionMethod" {
		field = "issuer"
	}

	// VC 1.1 keeps the document under a vc/vp claim; read the property there
	// when it exists, so a nested issuer cannot disagree with iss unnoticed.
	claimed := didFromClaim(body[field])
	if inner, ok := body["vc"].(map[string]interface{}); ok {
		claimed = didFromClaim(inner["issuer"])
	} else if inner, ok := body["vp"].(map[string]interface{}); ok {
		claimed = didFromClaim(inner["holder"])
	}

	iss, _ := body["iss"].(string)
	switch {
	case iss != "" && claimed != "" && iss != claimed:
		return "", fmt.Errorf("JWT iss %q does not match %s %q", iss, field, claimed)
	case iss != "":
		return iss, nil
	case claimed != "":
		return claimed, nil
	}
	return "", fmt.Errorf("JWT names no signer: both iss and %s are absent", field)
}

// didFromClaim reads a DID out of a property the data model allows in two
// shapes: a bare string, or an object carrying it under id.
func didFromClaim(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]interface{}:
		if id, ok := t["id"].(string); ok {
			return id
		}
	}
	return ""
}

// jwtIssuedAt extracts iat (issued at) as UTC time when present, and returns
// (nil, nil) when it is absent.
//
// There is deliberately no fallback to validFrom. iat is when the token was
// signed; validFrom is when the document starts being true. The only caller is
// the soft-revocation check — "was this signed before the key was revoked" —
// and a credential may state a validFrom long after it was signed, or long
// before. Substituting one for the other answers a different question and
// answers it silently.
func jwtIssuedAt(payloadB64 string) (*time.Time, error) {
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding: %w", err)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &body); err != nil {
		return nil, fmt.Errorf("invalid payload JSON: %w", err)
	}

	sec, ok, err := numericClaim(body, "iat")
	if err != nil || !ok {
		return nil, err
	}
	tm := time.Unix(sec, 0).UTC()
	return &tm, nil
}

// strictPurposeCheck mirrors the post-crypto checks used by jsonmap.VerifyProof
// for embedded ECDSA proofs. JWTs do not carry a proof.created field, so the
// timestamp check is omitted here — verifiers that need it should encode the
// signing time as `iat` and add their own enforcement.
func strictPurposeCheck(doc *verificationmethod.DIDDocument, vm *verificationmethod.VerificationMethodEntry, proofPurpose string, issuedAt *time.Time) error {
	if verificationmethod.IsHardRevocationReason(vm.RevocationReason) {
		return fmt.Errorf("verification method '%s' revoked with hard reason '%s'", vm.ID, vm.RevocationReason)
	}
	if vm.Revoked != nil {
		if issuedAt == nil {
			return fmt.Errorf("verification method '%s' was revoked at %s (missing iat for time-based revocation check)",
				vm.ID, vm.Revoked.UTC().Format(time.RFC3339))
		}
		if !issuedAt.Before(*vm.Revoked) {
			return fmt.Errorf("verification method '%s' was revoked at %s; iat %s is not earlier",
				vm.ID, vm.Revoked.UTC().Format(time.RFC3339), issuedAt.UTC().Format(time.RFC3339))
		}
	}

	var arr []string
	switch proofPurpose {
	case "authentication":
		arr = doc.Authentication
	case "assertionMethod":
		arr = doc.AssertionMethod
	default:
		return fmt.Errorf("unsupported proofPurpose '%s'", proofPurpose)
	}
	frag := vm.ID
	if i := len(doc.ID); len(vm.ID) > i && vm.ID[:i] == doc.ID && vm.ID[i] == '#' {
		frag = vm.ID[i:]
	}
	for _, ref := range arr {
		if ref == vm.ID || ref == frag {
			return nil
		}
	}
	return fmt.Errorf("verification method '%s' is not granted purpose '%s' on DID '%s'", vm.ID, proofPurpose, doc.ID)
}
