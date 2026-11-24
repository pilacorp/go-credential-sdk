package crypto

import (
	"errors"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// The accepted bodies below are what did-jwt-vc 5.0.2 (normalizeCredential and
// normalizePresentation in src/converters.ts), the library that defined
// JwtProof2020, returns for the JWT next to them, written out by hand.

func didJwtVcClaim() map[string]interface{} {
	return map[string]interface{}{
		"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":              []interface{}{"VerifiableCredential"},
		"credentialSubject": map[string]interface{}{"name": "Alice"},
	}
}

func didJwtVcBody(extra map[string]interface{}) map[string]interface{} {
	body := map[string]interface{}{
		"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":              []interface{}{"VerifiableCredential"},
		"issuer":            map[string]interface{}{"id": "did:example:issuer"},
		"credentialSubject": map[string]interface{}{"name": "Alice", "id": "did:example:subject"},
	}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

func withMember(m map[string]interface{}, key string, val interface{}) map[string]interface{} {
	m[key] = val
	return m
}

func TestVerifyJwtProof_DidJwtVcCredential(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	cases := []struct {
		name    string
		payload map[string]interface{}
		body    map[string]interface{}
		accept  bool
	}{
		{
			name:    "iat and nbf: iat stays in the body",
			payload: map[string]interface{}{"iat": 1700000100.0, "nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject", "vc": didJwtVcClaim()},
			body:    didJwtVcBody(map[string]interface{}{"iat": 1700000100.0, "issuanceDate": "2023-11-14T22:13:20.000Z"}),
			accept:  true,
		},
		{
			name:    "iat only: issuanceDate comes from iat",
			payload: map[string]interface{}{"iat": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject", "vc": didJwtVcClaim()},
			body:    didJwtVcBody(map[string]interface{}{"issuanceDate": "2023-11-14T22:13:20.000Z"}),
			accept:  true,
		},
		{
			name:    "aud and nonce stay in the body",
			payload: map[string]interface{}{"nbf": 1700000000.0, "aud": "did:example:verifier", "nonce": "n-1", "iss": "did:example:issuer", "sub": "did:example:subject", "vc": didJwtVcClaim()},
			body:    didJwtVcBody(map[string]interface{}{"aud": "did:example:verifier", "nonce": "n-1", "issuanceDate": "2023-11-14T22:13:20.000Z"}),
			accept:  true,
		},
		{
			name:    "iat in the body differs from the signed iat",
			payload: map[string]interface{}{"iat": 1700000100.0, "nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject", "vc": didJwtVcClaim()},
			body:    didJwtVcBody(map[string]interface{}{"iat": 1700000999.0, "issuanceDate": "2023-11-14T22:13:20.000Z"}),
		},
		{
			name:    "nbf signed: issuanceDate taken from iat instead",
			payload: map[string]interface{}{"iat": 1700000100.0, "nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject", "vc": didJwtVcClaim()},
			body:    didJwtVcBody(map[string]interface{}{"iat": 1700000100.0, "issuanceDate": "2023-11-14T22:15:00.000Z"}),
		},
		{
			name:    "iat only: issuanceDate differs from iat",
			payload: map[string]interface{}{"iat": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject", "vc": didJwtVcClaim()},
			body:    didJwtVcBody(map[string]interface{}{"issuanceDate": "2024-01-01T00:00:00.000Z"}),
		},
		{
			name: "issuer object with a signed name",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"issuer": map[string]interface{}{"name": "Acme"}, "vc": didJwtVcClaim()},
			body: didJwtVcBody(map[string]interface{}{"issuer": map[string]interface{}{"id": "did:example:issuer", "name": "Acme"},
				"issuanceDate": "2023-11-14T22:13:20.000Z"}),
			accept: true,
		},
		{
			name: "issuer name differs from the signed one",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"issuer": map[string]interface{}{"name": "Acme"}, "vc": didJwtVcClaim()},
			body: didJwtVcBody(map[string]interface{}{"issuer": map[string]interface{}{"id": "did:example:issuer", "name": "Evil"},
				"issuanceDate": "2023-11-14T22:13:20.000Z"}),
		},
		{
			// VC-JWT 1.1 allows the registered claims "in addition to" the
			// properties; this SDK's NewJWTCredential signs that shape.
			name: "properties kept inside vc as well",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"vc": map[string]interface{}{
					"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
					"type":              []interface{}{"VerifiableCredential"},
					"issuer":            "did:example:issuer",
					"issuanceDate":      "2023-11-14T22:13:20Z",
					"credentialSubject": map[string]interface{}{"id": "did:example:subject", "name": "Alice"},
				}},
			body: didJwtVcBody(map[string]interface{}{"issuanceDate": "2023-11-14T22:13:20.000Z",
				"vc": map[string]interface{}{"issuer": "did:example:issuer", "issuanceDate": "2023-11-14T22:13:20Z"}}),
			accept: true,
		},
		{
			name: "credentialStatus moved out of vc",
			payload: map[string]interface{}{"iat": 1700000100.0, "nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"vc": withMember(didJwtVcClaim(), "credentialStatus", map[string]interface{}{"id": "https://example.com/status#1", "type": "BitstringStatusListEntry"})},
			body: didJwtVcBody(map[string]interface{}{"iat": 1700000100.0, "issuanceDate": "2023-11-14T22:13:20.000Z",
				"credentialStatus": map[string]interface{}{"id": "https://example.com/status#1", "type": "BitstringStatusListEntry"}}),
			accept: true,
		},
		{
			name:    "jti becomes id, fractional iat truncated to milliseconds",
			payload: map[string]interface{}{"iat": 1700000000.0005, "jti": "urn:uuid:1", "iss": "did:example:issuer", "sub": "did:example:subject", "vc": didJwtVcClaim()},
			body:    didJwtVcBody(map[string]interface{}{"id": "urn:uuid:1", "issuanceDate": "2023-11-14T22:13:20.000Z"}),
			accept:  true,
		},
		{
			name:    "signed exp but expirationDate dropped",
			payload: map[string]interface{}{"nbf": 1700000000.0, "exp": 1900000000.0, "iss": "did:example:issuer", "sub": "did:example:subject", "vc": didJwtVcClaim()},
			body:    didJwtVcBody(map[string]interface{}{"issuanceDate": "2023-11-14T22:13:20.000Z"}),
		},
		{
			// did-jwt-vc leaves validUntil under vc, where the expiry check
			// never looks.
			name: "validUntil only under vc",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"vc": withMember(didJwtVcClaim(), "validUntil", "2024-01-01T00:00:00Z")},
			body: didJwtVcBody(map[string]interface{}{"issuanceDate": "2023-11-14T22:13:20.000Z",
				"vc": map[string]interface{}{"validUntil": "2024-01-01T00:00:00Z"}}),
		},
		{
			name:    "JWT with no vc claim",
			payload: map[string]interface{}{"iat": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject", "aud": "did:example:verifier", "nonce": "n-1"},
			body: map[string]interface{}{"@context": []interface{}{}, "type": []interface{}{},
				"issuer": map[string]interface{}{"id": "did:example:issuer"}, "credentialSubject": map[string]interface{}{"id": "did:example:subject"},
				"aud": "did:example:verifier", "nonce": "n-1", "issuanceDate": "2023-11-14T22:13:20.000Z"},
		},
		{
			name:    "member the JWT does not carry",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject", "vc": didJwtVcClaim()},
			body:    didJwtVcBody(map[string]interface{}{"nonce": "n-1", "issuanceDate": "2023-11-14T22:13:20.000Z"}),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := VerifyJwtProofToken(c.body, signJWT(t, testSecp256k1PrivHex, jwtHeader(), c.payload), &priv.PublicKey)
			if c.accept && err != nil {
				t.Fatalf("did-jwt-vc credential refused: %v", err)
			}
			if !c.accept && !errors.Is(err, ErrJwtProofBinding) {
				t.Fatalf("err = %v, want one wrapping ErrJwtProofBinding", err)
			}
		})
	}
}

func TestVerifyJwtProof_DidJwtVcPresentation(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	vcJWT := signJWT(t, testSecp256k1PrivHex, jwtHeader(), map[string]interface{}{
		"iat": 1700000100.0, "nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject", "vc": didJwtVcClaim(),
	})
	vpJWT := signJWT(t, testSecp256k1PrivHex, jwtHeader(), map[string]interface{}{
		"iss": "did:example:holder", "aud": "did:example:verifier", "nonce": "n-1",
		"iat": 1700000100.0, "nbf": 1700000000.0, "exp": 1900000000.0,
		"vp": map[string]interface{}{
			"@context":             []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":                 []interface{}{"VerifiablePresentation"},
			"verifiableCredential": []interface{}{vcJWT},
		},
	})
	normalizedVC := func(name string) map[string]interface{} {
		vc := didJwtVcBody(map[string]interface{}{"iat": 1700000100.0, "issuanceDate": "2023-11-14T22:13:20.000Z"})
		vc["credentialSubject"] = map[string]interface{}{"name": name, "id": "did:example:subject"}
		vc["proof"] = map[string]interface{}{"type": "JwtProof2020", "jwt": vcJWT}
		return vc
	}
	vpBody := func(vc interface{}, verifier interface{}) map[string]interface{} {
		creds := []interface{}{vc}
		if vc == nil {
			creds = []interface{}{}
		}
		return map[string]interface{}{
			"@context":             []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":                 []interface{}{"VerifiablePresentation"},
			"holder":               "did:example:holder",
			"verifier":             verifier,
			"nonce":                "n-1",
			"iat":                  1700000100.0,
			"issuanceDate":         "2023-11-14T22:13:20.000Z",
			"expirationDate":       "2030-03-17T17:46:40.000Z",
			"verifiableCredential": creds,
		}
	}
	noCredsJWT := signJWT(t, testSecp256k1PrivHex, jwtHeader(), map[string]interface{}{
		"iss": "did:example:holder", "aud": "did:example:verifier", "nonce": "n-1",
		"iat": 1700000100.0, "nbf": 1700000000.0, "exp": 1900000000.0,
		"vp": map[string]interface{}{
			"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":     []interface{}{"VerifiablePresentation"},
		},
	})
	hiddenJWT := signJWT(t, testSecp256k1PrivHex, jwtHeader(), map[string]interface{}{
		"iss": "did:example:holder", "iat": 1700000000.0,
		"vp": map[string]interface{}{
			"@context":   []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":       []interface{}{"VerifiablePresentation"},
			"validUntil": "2021-01-01T00:00:00Z",
		},
	})
	hiddenBody := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               "did:example:holder",
		"issuanceDate":         "2023-11-14T22:13:20.000Z",
		"verifiableCredential": []interface{}{},
		"vp":                   map[string]interface{}{"validUntil": "2021-01-01T00:00:00Z"},
	}
	withDate := func(body map[string]interface{}, key, date string) map[string]interface{} {
		body[key] = date
		return body
	}
	verifier := []interface{}{"did:example:verifier"}
	cases := []struct {
		name   string
		jwt    string
		body   map[string]interface{}
		accept bool
	}{
		{"did-jwt-vc presentation", vpJWT, vpBody(normalizedVC("Alice"), verifier), true},
		{"presentation with no credentials", noCredsJWT, vpBody(nil, verifier), true},
		{"embedded credential edited", vpJWT, vpBody(normalizedVC("Mallory"), verifier), false},
		{"embedded credential left as its JWT", vpJWT, vpBody(vcJWT, verifier), false},
		{"verifier differs from aud", vpJWT, vpBody(normalizedVC("Alice"), []interface{}{"did:example:other"}), false},
		{"expirationDate differs from exp", vpJWT, withDate(vpBody(normalizedVC("Alice"), verifier), "expirationDate", "2031-01-01T00:00:00.000Z"), false},
		{"validUntil only under vp", hiddenJWT, hiddenBody, false},
		{"issuanceDate differs from nbf", vpJWT, withDate(vpBody(normalizedVC("Alice"), verifier), "issuanceDate", "2024-01-01T00:00:00.000Z"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := VerifyJwtProofToken(c.body, c.jwt, &priv.PublicKey)
			if c.accept && err != nil {
				t.Fatalf("did-jwt-vc presentation refused: %v", err)
			}
			if !c.accept && !errors.Is(err, ErrJwtProofBinding) {
				t.Fatalf("err = %v, want one wrapping ErrJwtProofBinding", err)
			}
		})
	}
}
