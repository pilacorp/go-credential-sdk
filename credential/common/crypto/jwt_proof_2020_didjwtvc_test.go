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

// mappedVCBody is the VCDM 1.1 §6.3.1 mapping form of a vc claim built from
// didJwtVcClaim plus members: the subject id moved to sub, the rest as is.
func mappedVCBody(members map[string]interface{}) map[string]interface{} {
	body := didJwtVcClaim()
	body["credentialSubject"] = map[string]interface{}{"name": "Alice", "id": "did:example:subject"}
	for k, v := range members {
		body[k] = v
	}
	return body
}

func vcClaimWith(members map[string]interface{}) map[string]interface{} {
	vc := didJwtVcClaim()
	for k, v := range members {
		vc[k] = v
	}
	return vc
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
			name: "date kept in vc differs from the top-level one",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"vc": withMember(didJwtVcClaim(), "issuanceDate", "2024-01-01T00:00:00Z")},
			body: didJwtVcBody(map[string]interface{}{"issuanceDate": "2023-11-14T22:13:20.000Z",
				"vc": map[string]interface{}{"issuanceDate": "2024-01-01T00:00:00Z"}}),
		},
		{
			name: "issuer kept in vc differs from iss",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"vc": withMember(didJwtVcClaim(), "issuer", "did:example:other")},
			body: didJwtVcBody(map[string]interface{}{"issuanceDate": "2023-11-14T22:13:20.000Z",
				"vc": map[string]interface{}{"issuer": "did:example:other"}}),
		},
		{
			// did-jwt-vc's verifyCredential refuses a type without
			// VerifiableCredential.
			name: "type without VerifiableCredential",
			payload: map[string]interface{}{"iat": 1700000100.0, "nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"vc": withMember(didJwtVcClaim(), "type", []interface{}{"AuthToken"})},
			body: withMember(didJwtVcBody(map[string]interface{}{"iat": 1700000100.0, "issuanceDate": "2023-11-14T22:13:20.000Z"}),
				"type", []interface{}{"AuthToken"}),
		},
		{
			name: "@context without the VCDM 1.1 context",
			payload: map[string]interface{}{"iat": 1700000100.0, "nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"vc": withMember(didJwtVcClaim(), "@context", []interface{}{"https://example.com/ctx"})},
			body: withMember(didJwtVcBody(map[string]interface{}{"iat": 1700000100.0, "issuanceDate": "2023-11-14T22:13:20.000Z"}),
				"@context", []interface{}{"https://example.com/ctx"}),
		},
		{
			// did-jwt-vc spreads a string into index keys (a FIXME there); no
			// producer emits one, and lone surrogates could not be compared.
			name: "string credentialSubject",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"vc": withMember(didJwtVcClaim(), "credentialSubject", "ab")},
			body: withMember(didJwtVcBody(map[string]interface{}{"issuanceDate": "2023-11-14T22:13:20.000Z"}),
				"credentialSubject", map[string]interface{}{"0": "a", "1": "b", "id": "did:example:subject"}),
		},
		{
			name: "string credentialSubject, body without its characters",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"vc": withMember(didJwtVcClaim(), "credentialSubject", "ab")},
			body: withMember(didJwtVcBody(map[string]interface{}{"issuanceDate": "2023-11-14T22:13:20.000Z"}),
				"credentialSubject", map[string]interface{}{"id": "did:example:subject"}),
		},
		{
			// did-jwt-vc builds issuanceDate from the milliseconds of nbf.
			name:    "fractional nbf",
			payload: map[string]interface{}{"nbf": 1700000000.25, "iss": "did:example:issuer", "sub": "did:example:subject", "vc": didJwtVcClaim()},
			body:    didJwtVcBody(map[string]interface{}{"issuanceDate": "2023-11-14T22:13:20.250Z"}),
			accept:  true,
		},
		{
			name:    "top-level validFrom with milliseconds, same second as nbf",
			payload: map[string]interface{}{"iat": 1700000100.0, "nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject", "validFrom": "2023-11-14T22:13:20.123Z", "vc": didJwtVcClaim()},
			body:    didJwtVcBody(map[string]interface{}{"iat": 1700000100.0, "issuanceDate": "2023-11-14T22:13:20.000Z", "validFrom": "2023-11-14T22:13:20.123Z"}),
			accept:  true,
		},
		{
			name:    "fractional nbf with the same validFrom",
			payload: map[string]interface{}{"nbf": 1700000000.25, "iss": "did:example:issuer", "sub": "did:example:subject", "validFrom": "2023-11-14T22:13:20.25Z", "vc": didJwtVcClaim()},
			body:    didJwtVcBody(map[string]interface{}{"issuanceDate": "2023-11-14T22:13:20.250Z", "validFrom": "2023-11-14T22:13:20.25Z"}),
			accept:  true,
		},
		{
			name: "empty issuer in vc beside a top-level issuer string",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"issuer": "did:example:issuer", "vc": withMember(didJwtVcClaim(), "issuer", "")},
			body: didJwtVcBody(map[string]interface{}{"iss": "did:example:issuer", "issuer": "did:example:issuer",
				"issuanceDate": "2023-11-14T22:13:20.000Z", "vc": map[string]interface{}{"issuer": ""}}),
		},
		{
			name: "nbf that is not a number beside epoch dates",
			payload: map[string]interface{}{"iat": 1700000100.0, "nbf": "2099-01-01", "iss": "did:example:issuer", "sub": "did:example:subject",
				"issuanceDate": "1970-01-01T00:00:00Z", "validFrom": "1970-01-01T00:00:00Z", "vc": didJwtVcClaim()},
			body: didJwtVcBody(map[string]interface{}{"iat": 1700000100.0, "nbf": "2099-01-01",
				"issuanceDate": "1970-01-01T00:00:00Z", "validFrom": "1970-01-01T00:00:00Z"}),
		},
		{
			name: "top-level issuer string differs from iss",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"issuer": "did:example:victim", "vc": didJwtVcClaim()},
			body: didJwtVcBody(map[string]interface{}{"iss": "did:example:issuer", "issuer": "did:example:victim",
				"issuanceDate": "2023-11-14T22:13:20.000Z"}),
		},
		{
			name: "empty issuer in vc and no iss",
			payload: map[string]interface{}{"nbf": 1700000000.0, "sub": "did:example:subject",
				"vc": withMember(didJwtVcClaim(), "issuer", "")},
			body: didJwtVcBody(map[string]interface{}{"issuer": map[string]interface{}{},
				"issuanceDate": "2023-11-14T22:13:20.000Z", "vc": map[string]interface{}{"issuer": ""}}),
		},
		{
			// did-jwt-vc ignores a falsy sub, but it is still a signed claim
			// that names a subject other than the one the body shows.
			name: "empty sub beside a top-level subject id",
			payload: map[string]interface{}{"iat": 1700000100.0, "nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "",
				"credentialSubject": map[string]interface{}{"id": "did:example:carol"}, "vc": didJwtVcClaim()},
			body: withMember(didJwtVcBody(map[string]interface{}{"iat": 1700000100.0, "sub": "", "issuanceDate": "2023-11-14T22:13:20.000Z"}),
				"credentialSubject", map[string]interface{}{"id": "did:example:carol", "name": "Alice"}),
		},
		{
			name:    "top-level validFrom agrees with nbf",
			payload: map[string]interface{}{"iat": 1700000100.0, "nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject", "validFrom": "2023-11-14T22:13:20Z", "vc": didJwtVcClaim()},
			body:    didJwtVcBody(map[string]interface{}{"iat": 1700000100.0, "issuanceDate": "2023-11-14T22:13:20.000Z", "validFrom": "2023-11-14T22:13:20Z"}),
			accept:  true,
		},
		{
			// The expiry check reads validFrom; the JWT path reads nbf.
			name: "top-level validFrom differs from nbf",
			payload: map[string]interface{}{"nbf": 4000000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"validFrom": "2020-01-01T00:00:00Z", "vc": didJwtVcClaim()},
			body: didJwtVcBody(map[string]interface{}{"issuanceDate": "2096-10-02T07:06:40.000Z", "validFrom": "2020-01-01T00:00:00Z"}),
		},
		{
			name:    "top-level issuanceDate kept beside a differing nbf",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject", "issuanceDate": "2020-01-01T00:00:00Z", "vc": didJwtVcClaim()},
			body:    didJwtVcBody(map[string]interface{}{"nbf": 1700000000.0, "issuanceDate": "2020-01-01T00:00:00Z"}),
		},
		{
			name:    "top-level validUntil differs from exp",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject", "exp": 1600000000.0, "validUntil": "2099-01-01T00:00:00Z", "vc": didJwtVcClaim()},
			body: didJwtVcBody(map[string]interface{}{"issuanceDate": "2023-11-14T22:13:20.000Z",
				"expirationDate": "2020-09-13T12:26:40.000Z", "validUntil": "2099-01-01T00:00:00Z"}),
		},
		{
			name:    "top-level issuer id differs from iss",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject", "issuer": map[string]interface{}{"id": "did:example:victim"}, "vc": didJwtVcClaim()},
			body: didJwtVcBody(map[string]interface{}{"iss": "did:example:issuer", "issuanceDate": "2023-11-14T22:13:20.000Z",
				"issuer": map[string]interface{}{"id": "did:example:victim"}}),
		},
		{
			name:    "top-level subject id differs from sub",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject", "credentialSubject": map[string]interface{}{"id": "did:example:carol"}, "vc": didJwtVcClaim()},
			body: withMember(didJwtVcBody(map[string]interface{}{"sub": "did:example:subject", "issuanceDate": "2023-11-14T22:13:20.000Z"}),
				"credentialSubject", map[string]interface{}{"id": "did:example:carol", "name": "Alice"}),
		},
		{
			name:    "top-level id differs from jti",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject", "jti": "urn:uuid:1", "id": "urn:uuid:2", "vc": didJwtVcClaim()},
			body:    didJwtVcBody(map[string]interface{}{"jti": "urn:uuid:1", "id": "urn:uuid:2", "issuanceDate": "2023-11-14T22:13:20.000Z"}),
		},
		{
			name: "issuer string in vc, top-level issuer with a signed name",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject", "issuer": map[string]interface{}{"name": "Acme"},
				"vc": withMember(didJwtVcClaim(), "issuer", "did:example:issuer")},
			body: didJwtVcBody(map[string]interface{}{"issuanceDate": "2023-11-14T22:13:20.000Z",
				"issuer": map[string]interface{}{"id": "did:example:issuer", "name": "Acme"},
				"vc":     map[string]interface{}{"issuer": "did:example:issuer"}}),
			accept: true,
		},
		{
			name:    "null member in vc with nothing at the top level",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject", "vc": withMember(didJwtVcClaim(), "note", nil)},
			body: didJwtVcBody(map[string]interface{}{"issuanceDate": "2023-11-14T22:13:20.000Z",
				"vc": map[string]interface{}{"note": nil}}),
		},
		{
			// did-jwt-vc keeps the top-level credentialStatus and drops the one
			// in vc, which the SDK's VC-JWT path would read instead.
			name: "credentialStatus in vc differs from the top-level claim",
			payload: map[string]interface{}{"iat": 1700000100.0, "nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"credentialStatus": map[string]interface{}{"id": "https://example.com/status#5", "type": "BitstringStatusListEntry"},
				"vc":               withMember(didJwtVcClaim(), "credentialStatus", map[string]interface{}{"id": "https://example.com/status#9", "type": "BitstringStatusListEntry"})},
			body: didJwtVcBody(map[string]interface{}{"iat": 1700000100.0, "issuanceDate": "2023-11-14T22:13:20.000Z",
				"credentialStatus": map[string]interface{}{"id": "https://example.com/status#5", "type": "BitstringStatusListEntry"}}),
		},
		{
			name: "sub differs from the subject id in vc",
			payload: map[string]interface{}{"iat": 1700000100.0, "nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"vc": withMember(didJwtVcClaim(), "credentialSubject", map[string]interface{}{"id": "did:example:alice", "name": "Alice"})},
			body: didJwtVcBody(map[string]interface{}{"iat": 1700000100.0, "issuanceDate": "2023-11-14T22:13:20.000Z"}),
		},
		{
			// The VC-JWT path reads the nested .123, the JSON path the top-level
			// .000: two instants for one member.
			name: "date in vc with milliseconds, same second as nbf",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"vc": withMember(didJwtVcClaim(), "issuanceDate", "2023-11-14T22:13:20.123Z")},
			body: didJwtVcBody(map[string]interface{}{"issuanceDate": "2023-11-14T22:13:20.000Z",
				"vc": map[string]interface{}{"issuanceDate": "2023-11-14T22:13:20.123Z"}}),
		},
		{
			// The name is signed but sits only under vc, where nothing reads it.
			name: "issuer object in vc with more members than the top level",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"vc": withMember(didJwtVcClaim(), "issuer", map[string]interface{}{"id": "did:example:issuer", "name": "Acme"})},
			body: didJwtVcBody(map[string]interface{}{"issuanceDate": "2023-11-14T22:13:20.000Z",
				"vc": map[string]interface{}{"issuer": map[string]interface{}{"id": "did:example:issuer", "name": "Acme"}}}),
		},
		{
			name: "custom member in vc with a date-like value of other text",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"note": "2023-11-14T22:13:20.000Z", "vc": withMember(didJwtVcClaim(), "note", "2023-11-14T22:13:20Z")},
			body: didJwtVcBody(map[string]interface{}{"issuanceDate": "2023-11-14T22:13:20.000Z", "note": "2023-11-14T22:13:20.000Z",
				"vc": map[string]interface{}{"note": "2023-11-14T22:13:20Z"}}),
		},
		{
			name: "custom member in vc as a string, top level as an object with that id",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"sponsor": map[string]interface{}{"id": "did:example:x"}, "vc": withMember(didJwtVcClaim(), "sponsor", "did:example:x")},
			body: didJwtVcBody(map[string]interface{}{"issuanceDate": "2023-11-14T22:13:20.000Z", "sponsor": map[string]interface{}{"id": "did:example:x"},
				"vc": map[string]interface{}{"sponsor": "did:example:x"}}),
		},
		{
			// RFC 3339 takes no comma before the fraction; Go's time.Parse does.
			name: "issuanceDate with a comma fraction",
			payload: map[string]interface{}{"iat": 1700000100.0, "nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"issuanceDate": "2023-11-14T22:13:20,5Z", "vc": didJwtVcClaim()},
			body: didJwtVcBody(map[string]interface{}{"iat": 1700000100.0, "nbf": 1700000000.0, "issuanceDate": "2023-11-14T22:13:20,5Z"}),
		},
		{
			// VCDM 1.1 issuanceDate is an XML Schema dateTime; without a time
			// zone it is read as UTC.
			name:    "mapped issuanceDate without a time zone",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject", "vc": didJwtVcClaim()},
			body:    didJwtVcBody(map[string]interface{}{"issuanceDate": "2023-11-14T22:13:20"}),
			accept:  true,
		},
		// VCDM 1.1 §6.3.1 decoding sets the member from the claim, so a member
		// kept in vc must say what the claim says.
		{
			name:    "mapping: vc.expirationDate differs from exp",
			payload: map[string]interface{}{"exp": 1577836800.0, "iss": "did:example:issuer", "sub": "did:example:subject", "vc": vcClaimWith(map[string]interface{}{"issuer": "did:example:issuer", "expirationDate": "2099-01-01T00:00:00Z"})},
			body:    mappedVCBody(map[string]interface{}{"issuer": "did:example:issuer", "expirationDate": "2099-01-01T00:00:00Z"}),
		},
		{
			name:    "mapping: vc.issuer differs from iss",
			payload: map[string]interface{}{"iss": "did:example:issuer", "sub": "did:example:subject", "vc": vcClaimWith(map[string]interface{}{"issuer": "did:example:other"})},
			body:    mappedVCBody(map[string]interface{}{"issuer": "did:example:other"}),
		},
		{
			name:    "mapping: vc.issuanceDate differs from nbf",
			payload: map[string]interface{}{"nbf": 1893456000.0, "iss": "did:example:issuer", "sub": "did:example:subject", "vc": vcClaimWith(map[string]interface{}{"issuer": "did:example:issuer", "issuanceDate": "2010-01-01T00:00:00Z"})},
			body:    mappedVCBody(map[string]interface{}{"issuer": "did:example:issuer", "issuanceDate": "2010-01-01T00:00:00Z"}),
		},
		{
			name:    "mapping: vc.id differs from jti",
			payload: map[string]interface{}{"jti": "urn:2", "iss": "did:example:issuer", "sub": "did:example:subject", "vc": vcClaimWith(map[string]interface{}{"issuer": "did:example:issuer", "id": "urn:1"})},
			body:    mappedVCBody(map[string]interface{}{"issuer": "did:example:issuer", "id": "urn:1"}),
		},
		{
			name:    "mapping: vc.credentialSubject.id differs from sub",
			payload: map[string]interface{}{"iss": "did:example:issuer", "sub": "did:example:subject", "vc": vcClaimWith(map[string]interface{}{"issuer": "did:example:issuer", "credentialSubject": map[string]interface{}{"id": "did:example:s1", "name": "Alice"}})},
			body:    mappedVCBody(map[string]interface{}{"issuer": "did:example:issuer", "credentialSubject": map[string]interface{}{"id": "did:example:s1", "name": "Alice"}}),
		},
		{
			// sub stands for the first of several subjects.
			name: "mapping: sub differs from the first subject id",
			payload: map[string]interface{}{"iss": "did:example:issuer", "sub": "did:example:bob", "vc": vcClaimWith(map[string]interface{}{"issuer": "did:example:issuer",
				"credentialSubject": []interface{}{map[string]interface{}{"id": "did:example:alice"}, map[string]interface{}{"id": "did:example:witness"}}})},
			body: mappedVCBody(map[string]interface{}{"issuer": "did:example:issuer",
				"credentialSubject": []interface{}{map[string]interface{}{"id": "did:example:alice"}, map[string]interface{}{"id": "did:example:witness"}}}),
		},
		{
			name:    "mapping: vc members equal to their claims",
			payload: map[string]interface{}{"jti": "urn:1", "nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject", "vc": vcClaimWith(map[string]interface{}{"issuer": "did:example:issuer", "id": "urn:1", "issuanceDate": "2023-11-14T22:13:20Z"})},
			body:    mappedVCBody(map[string]interface{}{"issuer": "did:example:issuer", "id": "urn:1", "issuanceDate": "2023-11-14T22:13:20Z"}),
			accept:  true,
		},
		{
			// Readers compare dates to the nanosecond: a nested .100 and a
			// top-level .900 are two instants.
			name: "validUntil in vc .100, at the top level .900",
			payload: map[string]interface{}{"iat": 1700000100.0, "nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"validUntil": "2099-01-01T00:00:00.900Z", "vc": withMember(didJwtVcClaim(), "validUntil", "2099-01-01T00:00:00.100Z")},
			body: didJwtVcBody(map[string]interface{}{"iat": 1700000100.0, "issuanceDate": "2023-11-14T22:13:20.000Z",
				"validUntil": "2099-01-01T00:00:00.900Z", "vc": map[string]interface{}{"validUntil": "2099-01-01T00:00:00.100Z"}}),
		},
		{
			// Equal values are not enough: a moved date must read as a date
			// and its claim as a NumericDate.
			name:    "moved issuanceDate a number equal to nbf",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject", "vc": didJwtVcClaim()},
			body:    didJwtVcBody(map[string]interface{}{"issuanceDate": 1700000000.0}),
		},
		{
			name:    "moved issuanceDate a date string equal to a string nbf",
			payload: map[string]interface{}{"nbf": "2023-11-14T22:13:20Z", "iss": "did:example:issuer", "sub": "did:example:subject", "vc": didJwtVcClaim()},
			body:    didJwtVcBody(map[string]interface{}{"issuanceDate": "2023-11-14T22:13:20Z"}),
		},
		{
			name: "validUntil not a date, the same in vc and at the top level",
			payload: map[string]interface{}{"iat": 1700000100.0, "nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"validUntil": "never", "vc": withMember(didJwtVcClaim(), "validUntil", "never")},
			body: didJwtVcBody(map[string]interface{}{"iat": 1700000100.0, "issuanceDate": "2023-11-14T22:13:20.000Z",
				"validUntil": "never", "vc": map[string]interface{}{"validUntil": "never"}}),
		},
		{
			name:    "moved issuanceDate a bool equal to nbf",
			payload: map[string]interface{}{"nbf": true, "iss": "did:example:issuer", "sub": "did:example:subject", "vc": didJwtVcClaim()},
			body:    didJwtVcBody(map[string]interface{}{"issuanceDate": true}),
		},
		{
			// Mapping form: the body moves issuanceDate to nbf.
			name:    "mapped issuanceDate with a comma fraction",
			payload: map[string]interface{}{"nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject", "vc": didJwtVcClaim()},
			body:    didJwtVcBody(map[string]interface{}{"issuanceDate": "2023-11-14T22:13:20,0Z"}),
		},
		{
			name: "issuanceDate that is not a date",
			payload: map[string]interface{}{"iat": 1700000100.0, "nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"issuanceDate": "soon", "vc": didJwtVcClaim()},
			body: didJwtVcBody(map[string]interface{}{"iat": 1700000100.0, "nbf": 1700000000.0, "issuanceDate": "soon"}),
		},
		{
			// validateTimestamp refuses 12 or more digits as milliseconds.
			name: "expirationDate in milliseconds",
			payload: map[string]interface{}{"iat": 1700000100.0, "nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
				"expirationDate": 1900000000000.0, "vc": didJwtVcClaim()},
			body: didJwtVcBody(map[string]interface{}{"iat": 1700000100.0, "issuanceDate": "2023-11-14T22:13:20.000Z", "expirationDate": 1900000000000.0}),
		},
		{
			name: "empty credentialSubject",
			payload: map[string]interface{}{"iat": 1700000100.0, "nbf": 1700000000.0, "iss": "did:example:issuer",
				"vc": withMember(didJwtVcClaim(), "credentialSubject", map[string]interface{}{})},
			body: withMember(didJwtVcBody(map[string]interface{}{"iat": 1700000100.0, "issuanceDate": "2023-11-14T22:13:20.000Z"}),
				"credentialSubject", map[string]interface{}{}),
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
	// signVP signs a presentation with holder, iat and the given vp claim.
	signVP := func(extra map[string]interface{}, vp map[string]interface{}) string {
		payload := map[string]interface{}{"iss": "did:example:holder", "iat": 1700000000.0, "vp": vp}
		for k, v := range extra {
			payload[k] = v
		}
		return signJWT(t, testSecp256k1PrivHex, jwtHeader(), payload)
	}
	// plainVPBody is the decoded form of a signVP presentation.
	plainVPBody := func(context []interface{}, creds []interface{}, extra map[string]interface{}) map[string]interface{} {
		body := map[string]interface{}{
			"@context":             context,
			"type":                 []interface{}{"VerifiablePresentation"},
			"holder":               "did:example:holder",
			"issuanceDate":         "2023-11-14T22:13:20.000Z",
			"verifiableCredential": creds,
		}
		for k, v := range extra {
			body[k] = v
		}
		return body
	}
	v1 := []interface{}{"https://www.w3.org/2018/credentials/v1"}
	vpClaim := func(context []interface{}, creds []interface{}) map[string]interface{} {
		return map[string]interface{}{"@context": context, "type": []interface{}{"VerifiablePresentation"}, "verifiableCredential": creds}
	}
	jtiJWT := signVP(map[string]interface{}{"jti": "urn:uuid:vp"}, vpClaim(v1, []interface{}{}))
	// A credential held as an object keeps its own proof object, extra
	// members included; did-jwt-vc rebuilds the rest from proof.jwt.
	ownProof := map[string]interface{}{"type": "JwtProof2020", "jwt": vcJWT, "note": "kept"}
	heldVC := normalizedVC("Alice")
	heldVC["proof"] = ownProof
	heldJWT := signVP(nil, vpClaim(v1, []interface{}{map[string]interface{}{"proof": ownProof}}))
	editedHeld := normalizedVC("Mallory")
	editedHeld["proof"] = ownProof
	// JavaScript's Set keeps two equal objects apart, so both stay.
	twoCtx := []interface{}{"https://www.w3.org/2018/credentials/v1", map[string]interface{}{"@vocab": "https://example.com/#"}, map[string]interface{}{"@vocab": "https://example.com/#"}}
	twoCtxJWT := signVP(nil, vpClaim(twoCtx, []interface{}{}))
	// A presentation whose embedded credential did-jwt-vc's validator refuses.
	fooVCJWT := signJWT(t, testSecp256k1PrivHex, jwtHeader(), map[string]interface{}{
		"iat": 1700000100.0, "nbf": 1700000000.0, "iss": "did:example:issuer", "sub": "did:example:subject",
		"vc": withMember(didJwtVcClaim(), "type", []interface{}{"AuthToken"}),
	})
	fooVC := withMember(didJwtVcBody(map[string]interface{}{"iat": 1700000100.0, "issuanceDate": "2023-11-14T22:13:20.000Z"}),
		"type", []interface{}{"AuthToken"})
	fooVC["proof"] = map[string]interface{}{"type": "JwtProof2020", "jwt": fooVCJWT}
	fooHeldJWT := signVP(nil, vpClaim(v1, []interface{}{fooVCJWT}))
	otherCtx := []interface{}{"https://example.com/ctx"}
	otherCtxJWT := signVP(nil, vpClaim(otherCtx, []interface{}{}))
	msExpJWT := signVP(map[string]interface{}{"expirationDate": 1900000000000.0}, vpClaim(v1, []interface{}{}))
	nullIDJWT := signVP(map[string]interface{}{"jti": "urn:uuid:vp", "id": nil}, vpClaim(v1, []interface{}{}))
	vpDateJWT := signVP(map[string]interface{}{"nbf": 1700000000.0, "issuanceDate": "2020-01-01T00:00:00Z"}, vpClaim(v1, []interface{}{}))
	vpZeroJWT := signVP(map[string]interface{}{"nbf": 0.0, "issuanceDate": "2020-01-01T00:00:00Z"}, vpClaim(v1, []interface{}{}))
	holderInVPJWT := signJWT(t, testSecp256k1PrivHex, jwtHeader(), map[string]interface{}{
		"iss": "did:example:holder",
		"vp":  map[string]interface{}{"@context": v1, "type": []interface{}{"VerifiablePresentation"}, "holder": "did:example:x"},
	})
	vpExpJWT := signVP(map[string]interface{}{"exp": 1900000000.0, "expirationDate": "2020-01-01T00:00:00Z"}, vpClaim(v1, []interface{}{}))
	vpWith := func(claims map[string]interface{}, members map[string]interface{}) string {
		vp := map[string]interface{}{"@context": v1, "type": []interface{}{"VerifiablePresentation"}, "holder": "did:example:holder"}
		for k, v := range members {
			vp[k] = v
		}
		payload := map[string]interface{}{"iss": "did:example:holder", "vp": vp}
		for k, v := range claims {
			payload[k] = v
		}
		return signJWT(t, testSecp256k1PrivHex, jwtHeader(), payload)
	}
	vpValidFromJWT := vpWith(map[string]interface{}{"nbf": 1700000000.0}, map[string]interface{}{"validFrom": "2023-11-14T22:13:20Z"})
	vpExpOnlyJWT := vpWith(map[string]interface{}{"exp": 1900000000.0}, nil)
	vpUntilJWT := vpWith(map[string]interface{}{"exp": 1577836800.0}, map[string]interface{}{"validUntil": "2099-01-01T00:00:00Z"})
	vpExpDateJWT := vpWith(map[string]interface{}{"exp": 1577836800.0}, map[string]interface{}{"expirationDate": "2099-01-01T00:00:00Z"})
	holderSameJWT := signJWT(t, testSecp256k1PrivHex, jwtHeader(), map[string]interface{}{
		"iss": "did:example:holder",
		"vp":  map[string]interface{}{"@context": v1, "type": []interface{}{"VerifiablePresentation"}, "holder": "did:example:holder"},
	})
	nbfVPJWT := signJWT(t, testSecp256k1PrivHex, jwtHeader(), map[string]interface{}{
		"iss": "did:example:holder", "nbf": 1700000000.0,
		"vp": map[string]interface{}{"@context": v1, "type": []interface{}{"VerifiablePresentation"}},
	})
	// mappedVPBody is the VCDM 1.1 §6.3.1 mapping form of nbfVPJWT.
	mappedVPBody := func(extra map[string]interface{}) map[string]interface{} {
		body := map[string]interface{}{"@context": v1, "type": []interface{}{"VerifiablePresentation"}, "holder": "did:example:holder"}
		for k, v := range extra {
			body[k] = v
		}
		return body
	}
	holderJWT := signVP(map[string]interface{}{"holder": "did:example:victim"}, vpClaim(v1, []interface{}{}))
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
		{"jti becomes id", jtiJWT, plainVPBody(v1, []interface{}{}, map[string]interface{}{"id": "urn:uuid:vp"}), true},
		{"jti dropped from the body", jtiJWT, plainVPBody(v1, []interface{}{}, map[string]interface{}{"jti": "urn:uuid:vp"}), false},
		{"credential held as an object with its own proof", heldJWT, plainVPBody(v1, []interface{}{heldVC}, nil), true},
		{"credential held as an object, edited", heldJWT, plainVPBody(v1, []interface{}{editedHeld}, nil), false},
		{"credential the did-jwt-vc validator refuses", fooHeldJWT, plainVPBody(v1, []interface{}{fooVC}, nil), false},
		{"@context without the VCDM 1.1 context", otherCtxJWT, plainVPBody(otherCtx, []interface{}{}, nil), false},
		{"expirationDate in milliseconds", msExpJWT, plainVPBody(v1, []interface{}{}, map[string]interface{}{"expirationDate": 1900000000000.0}), false},
		{"null id beside a signed jti", nullIDJWT, plainVPBody(v1, []interface{}{}, map[string]interface{}{"id": nil, "jti": "urn:uuid:vp"}), false},
		{"top-level issuanceDate differs from nbf", vpDateJWT, plainVPBody(v1, []interface{}{}, map[string]interface{}{"issuanceDate": "2020-01-01T00:00:00Z", "nbf": 1700000000.0, "iat": 1700000000.0}), false},
		{"nbf 0 beside issuanceDate", vpZeroJWT, plainVPBody(v1, []interface{}{}, map[string]interface{}{"issuanceDate": "2020-01-01T00:00:00Z", "nbf": 0.0, "iat": 1700000000.0}), false},
		{"top-level expirationDate differs from exp", vpExpJWT, plainVPBody(v1, []interface{}{}, map[string]interface{}{"expirationDate": "2020-01-01T00:00:00Z", "exp": 1900000000.0}), false},
		{"mapping: validFrom in vp equal to nbf", vpValidFromJWT, map[string]interface{}{"@context": v1, "type": []interface{}{"VerifiablePresentation"}, "holder": "did:example:holder", "validFrom": "2023-11-14T22:13:20Z"}, true},
		{"mapping: exp signed, no date in the presentation", vpExpOnlyJWT, map[string]interface{}{"@context": v1, "type": []interface{}{"VerifiablePresentation"}, "holder": "did:example:holder"}, true},
		{"mapping: validUntil in vp differs from exp", vpUntilJWT, map[string]interface{}{"@context": v1, "type": []interface{}{"VerifiablePresentation"}, "holder": "did:example:holder", "validUntil": "2099-01-01T00:00:00Z"}, false},
		{"mapping: expirationDate in vp differs from exp", vpExpDateJWT, map[string]interface{}{"@context": v1, "type": []interface{}{"VerifiablePresentation"}, "holder": "did:example:holder", "expirationDate": "2099-01-01T00:00:00Z"}, false},
		{"mapping: vp.holder differs from iss", holderInVPJWT, map[string]interface{}{"@context": v1, "type": []interface{}{"VerifiablePresentation"}, "holder": "did:example:x"}, false},
		{"mapping: vp.holder equal to iss", holderSameJWT, map[string]interface{}{"@context": v1, "type": []interface{}{"VerifiablePresentation"}, "holder": "did:example:holder"}, true},
		{"mapping: issuanceDate moved from nbf", nbfVPJWT, mappedVPBody(map[string]interface{}{"issuanceDate": "2023-11-14T22:13:20Z"}), true},
		{"mapping: nbf signed but no issuanceDate", nbfVPJWT, mappedVPBody(nil), false},
		{"top-level holder differs from iss", holderJWT, plainVPBody(v1, []interface{}{}, map[string]interface{}{"holder": "did:example:victim", "iss": "did:example:holder"}), false},
		{"equal context objects both kept", twoCtxJWT, plainVPBody(twoCtx, []interface{}{}, nil), true},
		{"equal context objects merged into one", twoCtxJWT, plainVPBody(twoCtx[:2], []interface{}{}, nil), false},
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
