package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// signJWT builds a compact JWT (header.payload.signature) signed with the
// secp256k1 private key. The result is what a JwtProof2020 proof carries.
func signJWT(t *testing.T, privHex string, header, payload map[string]interface{}) string {
	t.Helper()
	priv, err := ethcrypto.HexToECDSA(privHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	hdr, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(body)

	hash := sha256.Sum256([]byte(signingInput))
	sig, err := ethcrypto.Sign(hash[:], priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

const testSecp256k1PrivHex = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

// credentialBody returns a minimal VC 1.1 JSON-LD body, the shape a legacy
// JwtProof2020 credential carries.
func credentialBody() map[string]interface{} {
	return map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
		"issuanceDate": "2024-01-01T00:00:00Z",
	}
}

// attachJwtProof2020 builds a JwtProof2020 proof around the JWT and attaches
// it to the credential body.
func attachJwtProof2020(body map[string]interface{}, jwt string) {
	body["proof"] = map[string]interface{}{
		"type":               "JwtProof2020",
		"jwt":                jwt,
		"verificationMethod": "did:example:issuer#key-1",
	}
}

// jwtHeader returns the standard JWT header for ES256K.
func jwtHeader() map[string]interface{} {
	return map[string]interface{}{"typ": "JWT", "alg": "ES256K"}
}

// sdkPayload builds an SDK-shape JWT payload: vc holds the full credential body,
// and iss/sub/jti/nbf/exp repeat some fields at the top level.
func sdkPayload(body map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"vc":  body,
		"iss": "did:example:issuer",
	}
}

// --- TC-02: SDK-shape JWT, body equal to vc ---

func TestVerifyJwtProof_TC02_SDKShapeMatchingBody(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	body := credentialBody()
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), sdkPayload(body))
	attachJwtProof2020(body, token)

	ok, err := VerifyJwtProof(&body, &priv.PublicKey)
	if err != nil {
		t.Fatalf("VerifyJwtProof error: %v", err)
	}
	if !ok {
		t.Fatal("a matching body was refused")
	}
}

// --- TC-03: VC-JWT 1.1 shape with moved fields ---

func TestVerifyJwtProof_TC03_VCJWT11ShapeWithMovedFields(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	vcClaim := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"credentialSubject": map[string]interface{}{
			"name": "Alice",
		},
	}
	jwtPayload := map[string]interface{}{
		"vc":  vcClaim,
		"iss": "did:example:issuer",
		"sub": "did:example:subject",
		"jti": "urn:uuid:1234",
		"nbf": float64(1704067200), // 2024-01-01T00:00:00Z
	}
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), jwtPayload)

	body := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   "did:example:issuer",
		"id":       "urn:uuid:1234",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
		"issuanceDate": "2024-01-01T00:00:00Z",
	}
	attachJwtProof2020(body, token)

	ok, err := VerifyJwtProof(&body, &priv.PublicKey)
	if err != nil {
		t.Fatalf("VerifyJwtProof error: %v", err)
	}
	if !ok {
		t.Fatal("VC-JWT 1.1 shape with moved fields was refused")
	}
}

// --- TC-04: Body adds a member absent from the JWT ---

func TestVerifyJwtProof_TC04_BodyAddsExtraMember(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	body := credentialBody()
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), sdkPayload(body))

	body["evidence"] = []interface{}{map[string]interface{}{"type": "DocumentVerification"}}
	attachJwtProof2020(body, token)

	ok, err := VerifyJwtProof(&body, &priv.PublicKey)
	if ok {
		t.Fatal("a body with an extra unsigned member was accepted")
	}
	if err == nil {
		t.Fatal("expected an error for extra member, got (false, nil)")
	}
	if !errors.Is(err, ErrJwtProofBinding) {
		t.Fatalf("err = %v, want one wrapping ErrJwtProofBinding", err)
	}
	if !strings.Contains(err.Error(), "evidence") {
		t.Fatalf("err = %v, want one naming the failing member 'evidence'", err)
	}
}

// --- TC-05: Body drops credentialStatus that vc carries ---

func TestVerifyJwtProof_TC05_BodyDropsVCMember(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	body := credentialBody()
	body["credentialStatus"] = map[string]interface{}{
		"id":   "https://example.com/status/1",
		"type": "StatusList2021Entry",
	}
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), sdkPayload(body))

	delete(body, "credentialStatus")
	attachJwtProof2020(body, token)

	ok, err := VerifyJwtProof(&body, &priv.PublicKey)
	if ok {
		t.Fatal("a body that drops a signed credentialStatus was accepted")
	}
	if err == nil {
		t.Fatal("expected an error for dropped member, got (false, nil)")
	}
	if !errors.Is(err, ErrJwtProofBinding) {
		t.Fatalf("err = %v, want one wrapping ErrJwtProofBinding", err)
	}
	if !strings.Contains(err.Error(), "credentialStatus") {
		t.Fatalf("err = %v, want one naming the failing member 'credentialStatus'", err)
	}
}

// --- TC-06: Body issuanceDate one day off nbf ---

func TestVerifyJwtProof_TC06_IssuanceDateOffByOneDay(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	vcClaim := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
	}
	jwtPayload := map[string]interface{}{
		"vc":  vcClaim,
		"iss": "did:example:issuer",
		"nbf": float64(1704067200), // 2024-01-01T00:00:00Z
	}
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), jwtPayload)

	body := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
		"issuanceDate": "2024-01-02T00:00:00Z", // one day off
	}
	attachJwtProof2020(body, token)

	ok, err := VerifyJwtProof(&body, &priv.PublicKey)
	if ok {
		t.Fatal("a body with issuanceDate one day off was accepted")
	}
	if err == nil {
		t.Fatal("expected an error for mismatched date, got (false, nil)")
	}
	if !errors.Is(err, ErrJwtProofBinding) {
		t.Fatalf("err = %v, want one wrapping ErrJwtProofBinding", err)
	}
	if !strings.Contains(err.Error(), "issuanceDate") {
		t.Fatalf("err = %v, want one naming 'issuanceDate'", err)
	}
}

// --- TC-07: Body round-tripped through json.Marshal / json.Unmarshal ---

func TestVerifyJwtProof_TC07_BodyRoundTrippedThroughJSON(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	body := credentialBody()
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), sdkPayload(body))
	attachJwtProof2020(body, token)

	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var roundTripped map[string]interface{}
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	ok, err := VerifyJwtProof(&roundTripped, &priv.PublicKey)
	if err != nil {
		t.Fatalf("VerifyJwtProof error: %v", err)
	}
	if !ok {
		t.Fatal("a round-tripped body was refused")
	}
}

// --- TC-08: JWT payload not JSON, or no vc claim ---

func TestVerifyJwtProof_TC08_MalformedJWTPayload(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	t.Run("no_vc_claim", func(t *testing.T) {
		body := credentialBody()
		payload := map[string]interface{}{
			"iss": "did:example:issuer",
			"sub": "did:example:subject",
		}
		token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), payload)
		attachJwtProof2020(body, token)

		ok, err := VerifyJwtProof(&body, &priv.PublicKey)
		if ok {
			t.Fatal("a JWT with no vc claim was accepted")
		}
		if err == nil {
			t.Fatal("expected an error for missing vc claim")
		}
		if !errors.Is(err, ErrJwtProofBinding) {
			t.Fatalf("err = %v, want one wrapping ErrJwtProofBinding", err)
		}
	})

	t.Run("vc_not_object", func(t *testing.T) {
		body := credentialBody()
		payload := map[string]interface{}{
			"vc":  "not an object",
			"iss": "did:example:issuer",
		}
		token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), payload)
		attachJwtProof2020(body, token)

		ok, err := VerifyJwtProof(&body, &priv.PublicKey)
		if ok {
			t.Fatal("a JWT whose vc is not an object was accepted")
		}
		if !errors.Is(err, ErrJwtProofBinding) {
			t.Fatalf("err = %v, want one wrapping ErrJwtProofBinding", err)
		}
	})

	_ = priv
}

// --- TC-09: credentialSubject array, sub is first element's id ---

func TestVerifyJwtProof_TC09_SubjectArrayWithSub(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	vcClaim := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"credentialSubject": []interface{}{
			map[string]interface{}{"name": "Alice"},
			map[string]interface{}{"id": "did:example:witness", "role": "witness"},
		},
	}
	jwtPayload := map[string]interface{}{
		"vc":  vcClaim,
		"iss": "did:example:issuer",
		"sub": "did:example:subject",
	}
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), jwtPayload)

	body := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   "did:example:issuer",
		"credentialSubject": []interface{}{
			map[string]interface{}{"id": "did:example:subject", "name": "Alice"},
			map[string]interface{}{"id": "did:example:witness", "role": "witness"},
		},
	}
	attachJwtProof2020(body, token)

	ok, err := VerifyJwtProof(&body, &priv.PublicKey)
	if err != nil {
		t.Fatalf("VerifyJwtProof error: %v", err)
	}
	if !ok {
		t.Fatal("a subject array with sub moved from first element was refused")
	}
}

// --- TC-10: issuer object with extra name field ---

func TestVerifyJwtProof_TC10_IssuerObjectWithName(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	vcClaim := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
	}
	jwtPayload := map[string]interface{}{
		"vc":  vcClaim,
		"iss": "did:example:issuer",
	}
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), jwtPayload)

	body := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer": map[string]interface{}{
			"id":   "did:example:issuer",
			"name": "Evil Org",
		},
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
	}
	attachJwtProof2020(body, token)

	ok, err := VerifyJwtProof(&body, &priv.PublicKey)
	if ok {
		t.Fatal("an issuer object with an unsigned name field was accepted")
	}
	if err == nil {
		t.Fatal("expected an error for issuer with extra name")
	}
	if !errors.Is(err, ErrJwtProofBinding) {
		t.Fatalf("err = %v, want one wrapping ErrJwtProofBinding", err)
	}
	if !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("err = %v, want one naming 'issuer'", err)
	}
}

// --- Forged body (direct call) ---

func TestVerifyJwtProof_ForgedBodyRefused(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	bodyA := credentialBody()
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), sdkPayload(bodyA))

	bodyB := credentialBody()
	bodyB["credentialSubject"] = map[string]interface{}{
		"id":   "did:example:attacker",
		"name": "Attacker",
		"degree": map[string]interface{}{
			"type": "PhD",
		},
	}
	attachJwtProof2020(bodyB, token)

	ok, err := VerifyJwtProof(&bodyB, &priv.PublicKey)
	if ok {
		t.Fatal("a forged body was accepted")
	}
	if err == nil {
		t.Fatal("expected an error for a forged body, got (false, nil)")
	}
	if !errors.Is(err, ErrJwtProofBinding) {
		t.Fatalf("err = %v, want one wrapping ErrJwtProofBinding", err)
	}
	if !strings.Contains(err.Error(), "credentialSubject") {
		t.Fatalf("err = %v, want one naming 'credentialSubject'", err)
	}
}

// --- Fractional nbf ---

// RFC 7519 §2 lets a NumericDate carry a fraction. The body's date is read at
// the second, the precision the JWT path reads nbf with (jwtutil.NumericDate).
func TestVerifyJwtProof_FractionalNbfReadToTheSecond(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), map[string]interface{}{
		"vc": map[string]interface{}{
			"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":              []interface{}{"VerifiableCredential"},
			"credentialSubject": map[string]interface{}{"id": "did:example:subject", "name": "Alice"},
		},
		"iss": "did:example:issuer",
		"nbf": float64(1704067200.5),
	})
	for _, c := range []struct {
		issuanceDate string
		accept       bool
	}{
		{"2024-01-01T00:00:00Z", true},
		{"2024-01-01T00:00:01Z", false},
	} {
		body := map[string]interface{}{
			"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":              []interface{}{"VerifiableCredential"},
			"issuer":            "did:example:issuer",
			"credentialSubject": map[string]interface{}{"id": "did:example:subject", "name": "Alice"},
			"issuanceDate":      c.issuanceDate,
		}
		attachJwtProof2020(body, token)
		ok, err := VerifyJwtProof(&body, &priv.PublicKey)
		if c.accept && !ok {
			t.Fatalf("issuanceDate %s refused: %v", c.issuanceDate, err)
		}
		if !c.accept && !errors.Is(err, ErrJwtProofBinding) {
			t.Fatalf("issuanceDate %s: err = %v, want one wrapping ErrJwtProofBinding", c.issuanceDate, err)
		}
	}
}

// --- Finding 1: no panic on non-object proof ---

func TestVerifyJwtProof_NoPanicOnNonObjectProof(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	body := credentialBody()
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), sdkPayload(body))

	// proof is a one-element array
	body["proof"] = []interface{}{
		map[string]interface{}{
			"type":               "JwtProof2020",
			"jwt":                token,
			"verificationMethod": "did:example:issuer#key-1",
		},
	}

	ok, err := VerifyJwtProof(&body, &priv.PublicKey)
	if ok {
		t.Fatal("expected rejection for array proof via old entry point")
	}
	if err == nil {
		t.Fatal("expected an error for array proof, got (false, nil)")
	}
	// The important thing: no panic.

	// A completely invalid proof type.
	body["proof"] = "not even a map"
	ok, err = VerifyJwtProof(&body, &priv.PublicKey)
	if ok {
		t.Fatal("expected rejection for string proof")
	}
	if err == nil {
		t.Fatal("expected an error for string proof")
	}
}

// --- Finding 3: proof member inside vc → refused ---

func TestVerifyJwtProofToken_VCWithProofMember(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	// The vc claim includes a "proof" member.
	vcClaim := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
		"issuanceDate": "2024-01-01T00:00:00Z",
		"proof":        map[string]interface{}{"type": "FakeProof"},
	}
	jwtPayload := map[string]interface{}{
		"vc":  vcClaim,
		"iss": "did:example:issuer",
	}
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), jwtPayload)

	body := credentialBody()

	_, err = VerifyJwtProofToken(body, token, &priv.PublicKey)
	if err == nil {
		t.Fatal("a vc claim with a proof member was accepted")
	}
	if !errors.Is(err, ErrJwtProofBinding) {
		t.Fatalf("err = %v, want one wrapping ErrJwtProofBinding", err)
	}
	if !strings.Contains(err.Error(), "proof") {
		t.Fatalf("err = %v, want one naming 'proof'", err)
	}
}

// --- Finding 4: VP with matching vp claim ---

func TestVerifyJwtProofToken_VP_MatchingBody(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	vpBody := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               "did:example:holder",
		"verifiableCredential": []interface{}{"vc-jwt-token-here"},
	}
	vpClaim := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               "did:example:holder",
		"verifiableCredential": []interface{}{"vc-jwt-token-here"},
	}
	jwtPayload := map[string]interface{}{
		"vp":  vpClaim,
		"iss": "did:example:holder",
	}
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), jwtPayload)

	_, err = VerifyJwtProofToken(vpBody, token, &priv.PublicKey)
	if err != nil {
		t.Fatalf("VP with matching vp claim was refused: %v", err)
	}
}

func TestVerifyJwtProofToken_VP_MovedFields(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	// VP with holder and id moved to iss and jti.
	vpClaim := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"verifiableCredential": []interface{}{"vc-jwt-token-here"},
	}
	jwtPayload := map[string]interface{}{
		"vp":  vpClaim,
		"iss": "did:example:holder",
		"jti": "urn:uuid:vp-1234",
	}
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), jwtPayload)

	vpBody := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               "did:example:holder",
		"id":                   "urn:uuid:vp-1234",
		"verifiableCredential": []interface{}{"vc-jwt-token-here"},
	}

	_, err = VerifyJwtProofToken(vpBody, token, &priv.PublicKey)
	if err != nil {
		t.Fatalf("VP with moved fields was refused: %v", err)
	}
}

func TestVerifyJwtProofToken_VP_DifferentHolder(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	vpClaim := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"verifiableCredential": []interface{}{"vc-jwt-token-here"},
	}
	jwtPayload := map[string]interface{}{
		"vp":  vpClaim,
		"iss": "did:example:holder",
	}
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), jwtPayload)

	vpBody := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               "did:example:attacker", // different from iss
		"verifiableCredential": []interface{}{"vc-jwt-token-here"},
	}

	_, err = VerifyJwtProofToken(vpBody, token, &priv.PublicKey)
	if err == nil {
		t.Fatal("a VP with a forged holder was accepted")
	}
	if !errors.Is(err, ErrJwtProofBinding) {
		t.Fatalf("err = %v, want one wrapping ErrJwtProofBinding", err)
	}
	if !strings.Contains(err.Error(), "holder") {
		t.Fatalf("err = %v, want one naming 'holder'", err)
	}
}

func TestVerifyJwtProofToken_VP_ExtraMember(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	vpClaim := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               "did:example:holder",
		"verifiableCredential": []interface{}{"vc-jwt-token-here"},
	}
	jwtPayload := map[string]interface{}{
		"vp":  vpClaim,
		"iss": "did:example:holder",
	}
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), jwtPayload)

	vpBody := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               "did:example:holder",
		"verifiableCredential": []interface{}{"vc-jwt-token-here"},
		"extra":                "unsigned",
	}

	_, err = VerifyJwtProofToken(vpBody, token, &priv.PublicKey)
	if err == nil {
		t.Fatal("a VP with an extra unsigned member was accepted")
	}
	if !errors.Is(err, ErrJwtProofBinding) {
		t.Fatalf("err = %v, want one wrapping ErrJwtProofBinding", err)
	}
	if !strings.Contains(err.Error(), "extra") {
		t.Fatalf("err = %v, want one naming 'extra'", err)
	}
}

// --- Reverse-direction check: signed moved claims must appear in the body ---
// VC-JWT 1.1 §6.3.1 moves exp, nbf, jti, sub out of the vc claim into
// top-level JWT claims. If the JWT signs one of these, the body must still
// carry the corresponding member; otherwise the body can silently drop it.

func TestVerifyJwtProof_BodyDropsExpirationDateWhileExpSigned(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	vcClaim := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
	}
	jwtPayload := map[string]interface{}{
		"vc":  vcClaim,
		"iss": "did:example:issuer",
		"exp": float64(1735689600), // 2025-01-01T00:00:00Z
	}
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), jwtPayload)

	// Body omits expirationDate entirely.
	body := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
	}
	attachJwtProof2020(body, token)

	ok, err := VerifyJwtProof(&body, &priv.PublicKey)
	if ok {
		t.Fatal("a body that drops expirationDate while exp is signed was accepted")
	}
	if !errors.Is(err, ErrJwtProofBinding) {
		t.Fatalf("err = %v, want one wrapping ErrJwtProofBinding", err)
	}
	if !strings.Contains(err.Error(), "expirationDate") {
		t.Fatalf("err = %v, want one naming 'expirationDate'", err)
	}
}

func TestVerifyJwtProof_BodyDropsIssuanceDateWhileNbfSigned(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	vcClaim := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
	}
	jwtPayload := map[string]interface{}{
		"vc":  vcClaim,
		"iss": "did:example:issuer",
		"nbf": float64(1704067200), // 2024-01-01T00:00:00Z
	}
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), jwtPayload)

	// Body omits issuanceDate entirely.
	body := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
	}
	attachJwtProof2020(body, token)

	ok, err := VerifyJwtProof(&body, &priv.PublicKey)
	if ok {
		t.Fatal("a body that drops issuanceDate while nbf is signed was accepted")
	}
	if !errors.Is(err, ErrJwtProofBinding) {
		t.Fatalf("err = %v, want one wrapping ErrJwtProofBinding", err)
	}
	if !strings.Contains(err.Error(), "issuanceDate") {
		t.Fatalf("err = %v, want one naming 'issuanceDate'", err)
	}
}

func TestVerifyJwtProof_BodyDropsIDWhileJtiSigned(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	vcClaim := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
	}
	jwtPayload := map[string]interface{}{
		"vc":  vcClaim,
		"iss": "did:example:issuer",
		"jti": "urn:uuid:1234",
	}
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), jwtPayload)

	// Body omits id entirely.
	body := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
	}
	attachJwtProof2020(body, token)

	ok, err := VerifyJwtProof(&body, &priv.PublicKey)
	if ok {
		t.Fatal("a body that drops id while jti is signed was accepted")
	}
	if !errors.Is(err, ErrJwtProofBinding) {
		t.Fatalf("err = %v, want one wrapping ErrJwtProofBinding", err)
	}
	if !strings.Contains(err.Error(), "id") {
		t.Fatalf("err = %v, want one naming 'id'", err)
	}
}

func TestVerifyJwtProof_BodyDropsSubjectIDWhileSubSigned(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	vcClaim := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"credentialSubject": map[string]interface{}{
			"name": "Alice",
		},
	}
	jwtPayload := map[string]interface{}{
		"vc":  vcClaim,
		"iss": "did:example:issuer",
		"sub": "did:example:subject",
	}
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), jwtPayload)

	// Body credentialSubject has no id.
	body := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"name": "Alice",
		},
	}
	attachJwtProof2020(body, token)

	ok, err := VerifyJwtProof(&body, &priv.PublicKey)
	if ok {
		t.Fatal("a body whose credentialSubject drops id while sub is signed was accepted")
	}
	if !errors.Is(err, ErrJwtProofBinding) {
		t.Fatalf("err = %v, want one wrapping ErrJwtProofBinding", err)
	}
}

func TestVerifyJwtProof_BodyDropsSubjectIDWhileSubSigned_Array(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	// credentialSubject is an array, none have id.
	vcClaim := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"credentialSubject": []interface{}{
			map[string]interface{}{"name": "Alice"},
			map[string]interface{}{"role": "witness"},
		},
	}
	jwtPayload := map[string]interface{}{
		"vc":  vcClaim,
		"iss": "did:example:issuer",
		"sub": "did:example:subject",
	}
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), jwtPayload)

	body := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   "did:example:issuer",
		"credentialSubject": []interface{}{
			map[string]interface{}{"name": "Alice"},
			map[string]interface{}{"role": "witness"},
		},
	}
	attachJwtProof2020(body, token)

	ok, err := VerifyJwtProof(&body, &priv.PublicKey)
	if ok {
		t.Fatal("a body whose credentialSubject array has no id while sub is signed was accepted")
	}
	if !errors.Is(err, ErrJwtProofBinding) {
		t.Fatalf("err = %v, want one wrapping ErrJwtProofBinding", err)
	}
}

func TestVerifyJwtProof_BodyDropsFirstSubjectIDWhileSubSigned(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	// sub stands for the first subject (VC-JWT 1.1 moves its id there). An id
	// on another subject must not stand in for it.
	vcClaim := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"credentialSubject": []interface{}{
			map[string]interface{}{"name": "Alice"},
			map[string]interface{}{"id": "did:example:witness", "role": "witness"},
		},
	}
	jwtPayload := map[string]interface{}{
		"vc":  vcClaim,
		"iss": "did:example:issuer",
		"sub": "did:example:subject",
	}
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), jwtPayload)

	body := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   "did:example:issuer",
		"credentialSubject": []interface{}{
			map[string]interface{}{"name": "Alice"},
			map[string]interface{}{"id": "did:example:witness", "role": "witness"},
		},
	}
	attachJwtProof2020(body, token)

	ok, err := VerifyJwtProof(&body, &priv.PublicKey)
	if ok {
		t.Fatal("a body whose first credentialSubject has no id while sub is signed was accepted")
	}
	if !errors.Is(err, ErrJwtProofBinding) {
		t.Fatalf("err = %v, want one wrapping ErrJwtProofBinding", err)
	}
}

func TestVerifyJwtProofToken_VP_BodyDropsIDWhileJtiSigned(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	vpClaim := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"verifiableCredential": []interface{}{"vc-jwt-token-here"},
	}
	jwtPayload := map[string]interface{}{
		"vp":  vpClaim,
		"iss": "did:example:holder",
		"jti": "urn:uuid:vp-1234",
	}
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), jwtPayload)

	// Body omits id entirely.
	vpBody := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               "did:example:holder",
		"verifiableCredential": []interface{}{"vc-jwt-token-here"},
	}

	_, err = VerifyJwtProofToken(vpBody, token, &priv.PublicKey)
	if err == nil {
		t.Fatal("a VP that drops id while jti is signed was accepted")
	}
	if !errors.Is(err, ErrJwtProofBinding) {
		t.Fatalf("err = %v, want one wrapping ErrJwtProofBinding", err)
	}
	if !strings.Contains(err.Error(), "id") {
		t.Fatalf("err = %v, want one naming 'id'", err)
	}
}

// Verify the existing round-trip tests (TC-03) still work with the reverse
// check: a body that has all the moved-claim members must still verify.
func TestVerifyJwtProof_VCJWT11_AllMovedFieldsPresent(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	vcClaim := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"credentialSubject": map[string]interface{}{
			"name": "Alice",
		},
	}
	jwtPayload := map[string]interface{}{
		"vc":  vcClaim,
		"iss": "did:example:issuer",
		"sub": "did:example:subject",
		"jti": "urn:uuid:1234",
		"nbf": float64(1704067200), // 2024-01-01T00:00:00Z
		"exp": float64(1735689600), // 2025-01-01T00:00:00Z
	}
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), jwtPayload)

	body := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   "did:example:issuer",
		"id":       "urn:uuid:1234",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
		"issuanceDate":   "2024-01-01T00:00:00Z",
		"expirationDate": "2025-01-01T00:00:00Z",
	}
	attachJwtProof2020(body, token)

	ok, err := VerifyJwtProof(&body, &priv.PublicKey)
	if err != nil {
		t.Fatalf("VerifyJwtProof error: %v", err)
	}
	if !ok {
		t.Fatal("a VC-JWT 1.1 body with all moved fields present was refused")
	}
}

// --- Sentinel error ---

func TestErrJwtProofBinding_IsSentinel(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	body := credentialBody()
	body["extra"] = "unsigned"
	token := signJWT(t, testSecp256k1PrivHex, jwtHeader(), sdkPayload(credentialBody()))
	attachJwtProof2020(body, token)

	_, err = VerifyJwtProof(&body, &priv.PublicKey)
	if !errors.Is(err, ErrJwtProofBinding) {
		t.Fatalf("errors.Is(err, ErrJwtProofBinding) = false; err = %v", err)
	}
}

func TestVerifyJwtProof_NilCredential(t *testing.T) {
	ok, err := VerifyJwtProof(nil, nil)
	if ok || err == nil {
		t.Fatalf("ok = %v, err = %v, want an error", ok, err)
	}
}
