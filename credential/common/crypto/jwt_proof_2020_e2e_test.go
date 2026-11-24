package crypto_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	pilacrpto "github.com/pilacorp/go-credential-sdk/credential/common/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jsonmap"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

const e2ePrivHex = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

// A second key for two-proof-set tests.
const e2ePrivHex2 = "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"

// signJWTE2E builds a compact JWT signed with the secp256k1 key.
func signJWTE2E(t *testing.T, privHex string, header, payload map[string]interface{}) string {
	t.Helper()
	priv, err := ethcrypto.HexToECDSA(privHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	hdr, _ := json.Marshal(header)
	body, _ := json.Marshal(payload)
	signingInput := base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(body)
	hash := sha256.Sum256([]byte(signingInput))
	sig, err := ethcrypto.Sign(hash[:], priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func e2eHeader() map[string]interface{} {
	return map[string]interface{}{"typ": "JWT", "alg": "ES256K"}
}

func e2eHeaderWithKid(kid string) map[string]interface{} {
	return map[string]interface{}{"typ": "JWT", "alg": "ES256K", "kid": kid}
}

func e2eResolverAndDoc(t *testing.T, did, fragment, privHex string) *verificationmethod.StaticResolver {
	t.Helper()
	priv, err := ethcrypto.HexToECDSA(privHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	doc := verificationmethod.NewDIDDocument(did, verificationmethod.NewSecp256k1VM(
		did, fragment, hex.EncodeToString(ethcrypto.CompressPubkey(&priv.PublicKey))))
	return verificationmethod.NewStaticResolver(doc)
}

// TC-01: the issue's forged-body scenario end-to-end through JSONMap.VerifyProof.
func TestVerifyProof_TC01_ForgedBodyRefusedEndToEnd(t *testing.T) {
	const did = "did:example:issuer"
	resolver := e2eResolverAndDoc(t, did, "key-1", e2ePrivHex)

	bodyA := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   did,
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:alice",
			"name": "Alice",
		},
		"issuanceDate": "2024-01-01T00:00:00Z",
	}
	jwtPayload := map[string]interface{}{
		"vc":  bodyA,
		"iss": did,
	}
	token := signJWTE2E(t, e2ePrivHex, e2eHeader(), jwtPayload)

	bodyB := jsonmap.JSONMap{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   did,
		"credentialSubject": map[string]interface{}{
			"id":     "did:example:attacker",
			"name":   "Attacker",
			"degree": "PhD",
		},
		"issuanceDate": "2024-01-01T00:00:00Z",
		"proof": map[string]interface{}{
			"type":               "JwtProof2020",
			"jwt":                token,
			"verificationMethod": did + "#key-1",
		},
	}

	ok, err := bodyB.VerifyProof(resolver, "")
	if ok {
		t.Fatal("a forged body was accepted through JSONMap.VerifyProof")
	}
	if err == nil {
		t.Fatal("expected an error for the forged body")
	}
	if !errors.Is(err, pilacrpto.ErrJwtProofBinding) {
		t.Fatalf("err = %v, want one wrapping ErrJwtProofBinding", err)
	}
}

// --- Finding 1: proof as one-element array verifies when bound ---

func TestVerifyProof_ProofArrayVerifiesWhenBound(t *testing.T) {
	const did = "did:example:issuer"
	resolver := e2eResolverAndDoc(t, did, "key-1", e2ePrivHex)

	body := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   did,
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
		"issuanceDate": "2024-01-01T00:00:00Z",
	}
	jwtPayload := map[string]interface{}{
		"vc":  body,
		"iss": did,
		"iat": float64(1704067200), // 2024-01-01T00:00:00Z
	}
	token := signJWTE2E(t, e2ePrivHex, e2eHeader(), jwtPayload)

	m := jsonmap.JSONMap(body)
	m["proof"] = []interface{}{
		map[string]interface{}{
			"type":               "JwtProof2020",
			"jwt":                token,
			"verificationMethod": did + "#key-1",
		},
	}

	ok, err := m.VerifyProof(resolver, "")
	if err != nil {
		t.Fatalf("VerifyProof error: %v", err)
	}
	if !ok {
		t.Fatal("a bound proof in a one-element array was refused")
	}
}

func TestVerifyProof_ProofArrayRefusedWhenForged(t *testing.T) {
	const did = "did:example:issuer"
	resolver := e2eResolverAndDoc(t, did, "key-1", e2ePrivHex)

	bodyA := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   did,
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:alice",
			"name": "Alice",
		},
		"issuanceDate": "2024-01-01T00:00:00Z",
	}
	jwtPayload := map[string]interface{}{
		"vc":  bodyA,
		"iss": did,
		"iat": float64(1704067200),
	}
	token := signJWTE2E(t, e2ePrivHex, e2eHeader(), jwtPayload)

	bodyB := jsonmap.JSONMap{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   did,
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:attacker",
			"name": "Attacker",
		},
		"issuanceDate": "2024-01-01T00:00:00Z",
		"proof": []interface{}{
			map[string]interface{}{
				"type":               "JwtProof2020",
				"jwt":                token,
				"verificationMethod": did + "#key-1",
			},
		},
	}

	ok, err := bodyB.VerifyProof(resolver, "")
	if ok {
		t.Fatal("a forged body in a proof array was accepted")
	}
	if !errors.Is(err, pilacrpto.ErrJwtProofBinding) {
		t.Fatalf("err = %v, want one wrapping ErrJwtProofBinding", err)
	}
}

// Two-proof set: each proof uses its own JWT.

func TestVerifyProof_TwoProofSetUsesEachProofsOwnJWT(t *testing.T) {
	const did1 = "did:example:issuer1"
	const did2 = "did:example:issuer2"

	priv1, _ := ethcrypto.HexToECDSA(e2ePrivHex)
	priv2, _ := ethcrypto.HexToECDSA(e2ePrivHex2)
	doc1 := verificationmethod.NewDIDDocument(did1, verificationmethod.NewSecp256k1VM(
		did1, "key-1", hex.EncodeToString(ethcrypto.CompressPubkey(&priv1.PublicKey))))
	doc2 := verificationmethod.NewDIDDocument(did2, verificationmethod.NewSecp256k1VM(
		did2, "key-1", hex.EncodeToString(ethcrypto.CompressPubkey(&priv2.PublicKey))))
	resolver := verificationmethod.NewStaticResolver(doc1, doc2)

	body := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   did1,
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
		"issuanceDate": "2024-01-01T00:00:00Z",
	}

	jwt1 := signJWTE2E(t, e2ePrivHex, e2eHeader(), map[string]interface{}{
		"vc": body, "iss": did1, "iat": float64(1704067200),
	})
	jwt2 := signJWTE2E(t, e2ePrivHex2, e2eHeader(), map[string]interface{}{
		"vc": body, "iss": did2, "iat": float64(1704067200),
	})

	m := jsonmap.JSONMap(body)
	m["proof"] = []interface{}{
		map[string]interface{}{
			"type":               "JwtProof2020",
			"jwt":                jwt1,
			"verificationMethod": did1 + "#key-1",
		},
		map[string]interface{}{
			"type":               "JwtProof2020",
			"jwt":                jwt2,
			"verificationMethod": did2 + "#key-1",
		},
	}

	ok, err := m.VerifyProof(resolver, "")
	if err != nil {
		t.Fatalf("VerifyProof error: %v", err)
	}
	if !ok {
		t.Fatal("a two-proof set where both JWTs match was refused")
	}
}

// --- Finding 2: soft-revoked key with signed time ---

func TestVerifyProof_SoftRevokedKey_IatAfterRevocationRefused(t *testing.T) {
	const did = "did:example:issuer"
	priv, _ := ethcrypto.HexToECDSA(e2ePrivHex)
	doc := verificationmethod.NewDIDDocument(did, verificationmethod.NewSecp256k1VM(
		did, "key-1", hex.EncodeToString(ethcrypto.CompressPubkey(&priv.PublicKey))))

	// Revoke the key (soft) on 2024-06-01.
	revoked, _ := time.Parse(time.RFC3339, "2024-06-01T00:00:00Z")
	doc.VerificationMethod[0].Revoked = &revoked
	doc.VerificationMethod[0].RevocationReason = verificationmethod.ReasonSuperseded
	resolver := verificationmethod.NewStaticResolver(doc)

	body := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   did,
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
		"issuanceDate": "2024-01-01T00:00:00Z",
	}

	// JWT iat is 2024-07-01, AFTER revocation.
	jwtPayload := map[string]interface{}{
		"vc":  body,
		"iss": did,
		"iat": float64(1719792000), // 2024-07-01T00:00:00Z
	}
	token := signJWTE2E(t, e2ePrivHex, e2eHeader(), jwtPayload)

	m := jsonmap.JSONMap(body)
	m["proof"] = map[string]interface{}{
		"type":               "JwtProof2020",
		"jwt":                token,
		"verificationMethod": did + "#key-1",
		// proof.created is BEFORE revocation — an attacker forges this.
		"created": "2024-01-01T00:00:00Z",
	}

	ok, err := m.VerifyProof(resolver, "")
	if ok {
		t.Fatal("a proof with iat after revocation was accepted despite proof.created being before")
	}
	if err == nil {
		t.Fatal("expected an error for iat-after-revocation")
	}
	// The error should come from the proof.created != iat check or the
	// purpose check using the signed iat.
	if !strings.Contains(err.Error(), "differs from JWT signed time") &&
		!strings.Contains(err.Error(), "is not earlier") {
		t.Fatalf("err = %v, want one about created mismatch or revocation", err)
	}
}

func TestVerifyProof_SoftRevokedKey_CreatedAbsentUsesIat(t *testing.T) {
	const did = "did:example:issuer"
	priv, _ := ethcrypto.HexToECDSA(e2ePrivHex)
	doc := verificationmethod.NewDIDDocument(did, verificationmethod.NewSecp256k1VM(
		did, "key-1", hex.EncodeToString(ethcrypto.CompressPubkey(&priv.PublicKey))))

	// Revoke the key (soft) on 2024-06-01.
	revoked, _ := time.Parse(time.RFC3339, "2024-06-01T00:00:00Z")
	doc.VerificationMethod[0].Revoked = &revoked
	doc.VerificationMethod[0].RevocationReason = verificationmethod.ReasonSuperseded
	resolver := verificationmethod.NewStaticResolver(doc)

	body := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   did,
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
		"issuanceDate": "2024-01-01T00:00:00Z",
	}

	// JWT iat is 2024-01-01, BEFORE revocation. No proof.created.
	jwtPayload := map[string]interface{}{
		"vc":  body,
		"iss": did,
		"iat": float64(1704067200), // 2024-01-01T00:00:00Z
	}
	token := signJWTE2E(t, e2ePrivHex, e2eHeader(), jwtPayload)

	m := jsonmap.JSONMap(body)
	m["proof"] = map[string]interface{}{
		"type":               "JwtProof2020",
		"jwt":                token,
		"verificationMethod": did + "#key-1",
		// No created field — the signed iat (before revocation) is used.
	}

	ok, err := m.VerifyProof(resolver, "")
	if err != nil {
		t.Fatalf("VerifyProof error: %v", err)
	}
	if !ok {
		t.Fatal("a proof with iat before revocation and no created was refused")
	}
}

// proof.created != iat → refused

func TestVerifyProof_CreatedDiffersFromIat(t *testing.T) {
	const did = "did:example:issuer"
	resolver := e2eResolverAndDoc(t, did, "key-1", e2ePrivHex)

	body := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   did,
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
		"issuanceDate": "2024-01-01T00:00:00Z",
	}

	jwtPayload := map[string]interface{}{
		"vc":  body,
		"iss": did,
		"iat": float64(1704067200), // 2024-01-01T00:00:00Z
	}
	token := signJWTE2E(t, e2ePrivHex, e2eHeader(), jwtPayload)

	m := jsonmap.JSONMap(body)
	m["proof"] = map[string]interface{}{
		"type":               "JwtProof2020",
		"jwt":                token,
		"verificationMethod": did + "#key-1",
		"created":            "2024-06-01T00:00:00Z", // differs from iat
	}

	ok, err := m.VerifyProof(resolver, "")
	if ok {
		t.Fatal("a proof with created != iat was accepted")
	}
	if err == nil {
		t.Fatal("expected an error for created != iat")
	}
	if !strings.Contains(err.Error(), "differs from JWT signed time") {
		t.Fatalf("err = %v, want one about created mismatch", err)
	}
}

// --- Finding 4: VP end-to-end through VerifyProof ---

func TestVerifyProof_VP_MatchingVpClaimVerifies(t *testing.T) {
	const did = "did:example:holder"
	resolver := e2eResolverAndDoc(t, did, "key-1", e2ePrivHex)

	vpBody := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               did,
		"verifiableCredential": []interface{}{"vc-jwt-token-here"},
	}
	vpClaim := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               did,
		"verifiableCredential": []interface{}{"vc-jwt-token-here"},
	}
	jwtPayload := map[string]interface{}{
		"vp":  vpClaim,
		"iss": did,
		"iat": float64(1704067200),
	}
	token := signJWTE2E(t, e2ePrivHex, e2eHeader(), jwtPayload)

	m := jsonmap.JSONMap(vpBody)
	m["proof"] = map[string]interface{}{
		"type":               "JwtProof2020",
		"jwt":                token,
		"verificationMethod": did + "#key-1",
	}

	ok, err := m.VerifyProof(resolver, "")
	if err != nil {
		t.Fatalf("VerifyProof error: %v", err)
	}
	if !ok {
		t.Fatal("a VP with matching vp claim was refused")
	}
}

func TestVerifyProof_VP_ForgedHolderRefused(t *testing.T) {
	const did = "did:example:holder"
	resolver := e2eResolverAndDoc(t, did, "key-1", e2ePrivHex)

	vpClaim := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"verifiableCredential": []interface{}{"vc-jwt-token-here"},
	}
	jwtPayload := map[string]interface{}{
		"vp":  vpClaim,
		"iss": did,
		"iat": float64(1704067200),
	}
	token := signJWTE2E(t, e2ePrivHex, e2eHeader(), jwtPayload)

	m := jsonmap.JSONMap{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               "did:example:attacker", // forged
		"verifiableCredential": []interface{}{"vc-jwt-token-here"},
		"proof": map[string]interface{}{
			"type":               "JwtProof2020",
			"jwt":                token,
			"verificationMethod": did + "#key-1",
		},
	}

	ok, err := m.VerifyProof(resolver, "")
	if ok {
		t.Fatal("a VP with a forged holder was accepted")
	}
	if !errors.Is(err, pilacrpto.ErrJwtProofBinding) {
		t.Fatalf("err = %v, want one wrapping ErrJwtProofBinding", err)
	}
}

// --- kid vs verificationMethod cross-check ---

// e2eResolverTwoKeys builds a resolver with one DID document that has two
// verification methods (key-1 and key-2).
func e2eResolverTwoKeys(t *testing.T, did string) *verificationmethod.StaticResolver {
	t.Helper()
	priv1, _ := ethcrypto.HexToECDSA(e2ePrivHex)
	priv2, _ := ethcrypto.HexToECDSA(e2ePrivHex2)
	doc := verificationmethod.NewDIDDocument(did,
		verificationmethod.NewSecp256k1VM(did, "key-1",
			hex.EncodeToString(ethcrypto.CompressPubkey(&priv1.PublicKey))),
		verificationmethod.NewSecp256k1VM(did, "key-2",
			hex.EncodeToString(ethcrypto.CompressPubkey(&priv2.PublicKey))),
	)
	return verificationmethod.NewStaticResolver(doc)
}

func TestVerifyProof_KidVsVerificationMethod_MismatchRefused(t *testing.T) {
	const did = "did:example:issuer"
	resolver := e2eResolverTwoKeys(t, did)

	body := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   did,
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
		"issuanceDate": "2024-01-01T00:00:00Z",
	}

	// JWT header kid points to key-1, JWT is signed by key-1.
	jwtPayload := map[string]interface{}{
		"vc":  body,
		"iss": did,
		"iat": float64(1704067200),
	}
	token := signJWTE2E(t, e2ePrivHex,
		e2eHeaderWithKid(did+"#key-1"), jwtPayload)

	// But proof.verificationMethod points to key-2.
	m := jsonmap.JSONMap(body)
	m["proof"] = map[string]interface{}{
		"type":               "JwtProof2020",
		"jwt":                token,
		"verificationMethod": did + "#key-2",
	}

	ok, err := m.VerifyProof(resolver, "")
	if ok {
		t.Fatal("kid #key-1 + verificationMethod #key-2 was accepted")
	}
	if !errors.Is(err, pilacrpto.ErrJwtProofBinding) {
		t.Fatalf("err = %v, want one wrapping ErrJwtProofBinding", err)
	}
}

func TestVerifyProof_KidVsVerificationMethod_MatchingVerifies(t *testing.T) {
	const did = "did:example:issuer"
	resolver := e2eResolverTwoKeys(t, did)

	body := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   did,
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
		"issuanceDate": "2024-01-01T00:00:00Z",
	}

	// JWT header kid points to key-1, signed by key-1, VM also key-1.
	jwtPayload := map[string]interface{}{
		"vc":  body,
		"iss": did,
		"iat": float64(1704067200),
	}
	token := signJWTE2E(t, e2ePrivHex,
		e2eHeaderWithKid(did+"#key-1"), jwtPayload)

	m := jsonmap.JSONMap(body)
	m["proof"] = map[string]interface{}{
		"type":               "JwtProof2020",
		"jwt":                token,
		"verificationMethod": did + "#key-1",
	}

	ok, err := m.VerifyProof(resolver, "")
	if err != nil {
		t.Fatalf("VerifyProof error: %v", err)
	}
	if !ok {
		t.Fatal("kid + verificationMethod both #key-1 was refused")
	}
}

func TestVerifyProof_KidRelativeFragment_NormalisedMatch(t *testing.T) {
	const did = "did:example:issuer"
	resolver := e2eResolverTwoKeys(t, did)

	body := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   did,
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
		"issuanceDate": "2024-01-01T00:00:00Z",
	}

	// JWT kid is relative "#key-1", proof.verificationMethod is full.
	jwtPayload := map[string]interface{}{
		"vc":  body,
		"iss": did,
		"iat": float64(1704067200),
	}
	token := signJWTE2E(t, e2ePrivHex,
		e2eHeaderWithKid("#key-1"), jwtPayload)

	m := jsonmap.JSONMap(body)
	m["proof"] = map[string]interface{}{
		"type":               "JwtProof2020",
		"jwt":                token,
		"verificationMethod": did + "#key-1",
	}

	ok, err := m.VerifyProof(resolver, "")
	if err != nil {
		t.Fatalf("VerifyProof error: %v", err)
	}
	if !ok {
		t.Fatal("relative kid #key-1 vs full verificationMethod was refused")
	}
}

// --- VP purpose: authentication, not assertionMethod ---

// e2eDocWithPurpose builds a DID document where the VM is in only one purpose array.
func e2eDocWithPurpose(t *testing.T, did, fragment, privHex string, assertionMethod, authentication bool) *verificationmethod.DIDDocument {
	t.Helper()
	priv, err := ethcrypto.HexToECDSA(privHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	vm := verificationmethod.NewSecp256k1VM(did, fragment,
		hex.EncodeToString(ethcrypto.CompressPubkey(&priv.PublicKey)))
	doc := &verificationmethod.DIDDocument{
		ID:                 did,
		VerificationMethod: []verificationmethod.VerificationMethodEntry{vm},
	}
	if assertionMethod {
		doc.AssertionMethod = []string{vm.ID}
	}
	if authentication {
		doc.Authentication = []string{vm.ID}
	}
	return doc
}

func TestVerifyProof_VP_AuthenticationOnlyKeyVerifies(t *testing.T) {
	const did = "did:example:holder"
	// Key is in authentication ONLY, not assertionMethod.
	doc := e2eDocWithPurpose(t, did, "key-1", e2ePrivHex, false, true)
	resolver := verificationmethod.NewStaticResolver(doc)

	vpBody := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               did,
		"verifiableCredential": []interface{}{"vc-jwt-token-here"},
	}
	jwtPayload := map[string]interface{}{
		"vp":  vpBody,
		"iss": did,
		"iat": float64(1704067200),
	}
	token := signJWTE2E(t, e2ePrivHex, e2eHeader(), jwtPayload)

	m := jsonmap.JSONMap(vpBody)
	m["proof"] = map[string]interface{}{
		"type":               "JwtProof2020",
		"jwt":                token,
		"verificationMethod": did + "#key-1",
	}

	ok, err := m.VerifyProof(resolver, "")
	if err != nil {
		t.Fatalf("VerifyProof error: %v", err)
	}
	if !ok {
		t.Fatal("VP with authentication-only key was refused")
	}
}

func TestVerifyProof_VP_AssertionMethodOnlyKeyRefused(t *testing.T) {
	const did = "did:example:holder"
	// Key is in assertionMethod ONLY, not authentication.
	doc := e2eDocWithPurpose(t, did, "key-1", e2ePrivHex, true, false)
	resolver := verificationmethod.NewStaticResolver(doc)

	vpBody := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               did,
		"verifiableCredential": []interface{}{"vc-jwt-token-here"},
	}
	jwtPayload := map[string]interface{}{
		"vp":  vpBody,
		"iss": did,
		"iat": float64(1704067200),
	}
	token := signJWTE2E(t, e2ePrivHex, e2eHeader(), jwtPayload)

	m := jsonmap.JSONMap(vpBody)
	m["proof"] = map[string]interface{}{
		"type":               "JwtProof2020",
		"jwt":                token,
		"verificationMethod": did + "#key-1",
	}

	ok, err := m.VerifyProof(resolver, "")
	if ok {
		t.Fatal("VP with assertionMethod-only key was accepted")
	}
	if err == nil {
		t.Fatal("expected an error for VP with assertionMethod-only key")
	}
	if !strings.Contains(err.Error(), "not granted purpose") {
		t.Fatalf("err = %v, want one about purpose not granted", err)
	}
}

func TestVerifyProof_VC_AssertionMethodOnlyKeyVerifies(t *testing.T) {
	const did = "did:example:issuer"
	// Key is in assertionMethod ONLY — VC should still verify.
	doc := e2eDocWithPurpose(t, did, "key-1", e2ePrivHex, true, false)
	resolver := verificationmethod.NewStaticResolver(doc)

	body := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   did,
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
		"issuanceDate": "2024-01-01T00:00:00Z",
	}

	jwtPayload := map[string]interface{}{
		"vc":  body,
		"iss": did,
		"iat": float64(1704067200),
	}
	token := signJWTE2E(t, e2ePrivHex, e2eHeader(), jwtPayload)

	m := jsonmap.JSONMap(body)
	m["proof"] = map[string]interface{}{
		"type":               "JwtProof2020",
		"jwt":                token,
		"verificationMethod": did + "#key-1",
	}

	ok, err := m.VerifyProof(resolver, "")
	if err != nil {
		t.Fatalf("VerifyProof error: %v", err)
	}
	if !ok {
		t.Fatal("VC with assertionMethod-only key was refused")
	}
}
