package vc_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

const expiryTestDID = "did:example:issuer"

// signExpiryJWT signs payload as an ES256K JWT for expiryTestDID#key-1 and
// returns the token and a resolver that knows the key.
func signExpiryJWT(t *testing.T, payload map[string]interface{}) (string, verificationmethod.ResolverProvider) {
	t.Helper()
	priv, err := ethcrypto.HexToECDSA("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")
	if err != nil {
		t.Fatal(err)
	}
	header, _ := json.Marshal(map[string]interface{}{"typ": "JWT", "alg": "ES256K", "kid": expiryTestDID + "#key-1"})
	body, _ := json.Marshal(payload)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(input))
	sig, err := ethcrypto.Sign(digest[:], priv)
	if err != nil {
		t.Fatal(err)
	}
	vm := verificationmethod.NewSecp256k1VM(expiryTestDID, "key-1", hex.EncodeToString(ethcrypto.CompressPubkey(&priv.PublicKey)))
	resolver := verificationmethod.NewStaticResolver(verificationmethod.NewDIDDocument(expiryTestDID, vm))
	return input + "." + base64.RawURLEncoding.EncodeToString(sig[:64]), resolver
}

// A VC-JWT in JSON form with a VC Data Model 2.0 context and a 1.1
// expirationDate, moved from exp, is refused once expired.
func TestJwtProof2020_ExpiredWithV2Context(t *testing.T) {
	exp := time.Now().Add(-time.Hour).Unix()
	jwt, resolver := signExpiryJWT(t, map[string]interface{}{
		"iss": expiryTestDID, "exp": exp,
		"vc": map[string]interface{}{
			"@context":          []interface{}{"https://www.w3.org/ns/credentials/v2"},
			"type":              []interface{}{"VerifiableCredential"},
			"credentialSubject": map[string]interface{}{"name": "Alice"},
		},
	})
	raw, _ := json.Marshal(map[string]interface{}{
		"@context":          []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":              []interface{}{"VerifiableCredential"},
		"issuer":            expiryTestDID,
		"credentialSubject": map[string]interface{}{"name": "Alice"},
		"expirationDate":    time.Unix(exp, 0).UTC().Format(time.RFC3339),
		"proof":             map[string]interface{}{"type": "JwtProof2020", "jwt": jwt, "verificationMethod": expiryTestDID + "#key-1"},
	})
	c, err := vc.ParseCredential(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := c.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("proof refused, the test would prove nothing: %v", err)
	}
	err = c.Verify(vc.WithResolver(resolver), vc.WithCheckExpiration())
	if err == nil || !strings.Contains(err.Error(), "credential is expired") {
		t.Fatalf("err = %v, want the credential expired", err)
	}
}

// VC-JWT 1.1 moves no presentation date, so a VP-JWT in JSON form may show no
// date member at all: only its exp tells it expired.
func TestJwtProof2020_PresentationExpiredByExpClaim(t *testing.T) {
	// "Type" too: the proof check reads the type case-insensitively
	// (encoding/json), so the expiry check must read the same proofs.
	for _, typeKey := range []string{"type", "Type"} {
		t.Run(typeKey, func(t *testing.T) {
			exp := time.Now().Add(-time.Hour).Unix()
			jwt, resolver := signExpiryJWT(t, map[string]interface{}{
				"iss": expiryTestDID, "exp": exp,
				"vp": map[string]interface{}{
					"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
					"type":     []interface{}{"VerifiablePresentation"},
				},
			})
			raw, _ := json.Marshal(map[string]interface{}{
				"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
				"type":     []interface{}{"VerifiablePresentation"},
				"holder":   expiryTestDID,
				"proof":    map[string]interface{}{typeKey: "JwtProof2020", "jwt": jwt, "verificationMethod": expiryTestDID + "#key-1"},
			})
			p, err := vp.ParsePresentation(raw)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if err := p.Verify(vp.WithResolver(resolver)); err != nil {
				t.Fatalf("proof refused, the test would prove nothing: %v", err)
			}
			err = p.Verify(vp.WithResolver(resolver), vp.WithCheckExpiration())
			if err == nil || !strings.Contains(err.Error(), "(exp)") {
				t.Fatalf("err = %v, want the exp claim refused", err)
			}
		})
	}
}

// VCDM 1.1 issuanceDate and expirationDate are enforced whatever @context
// says: a credential that lists the 1.1 context second, or not at all, does
// not move its dates out of view.
func TestJwtProof2020_ExpirationDateWithMixedContexts(t *testing.T) {
	for _, ctx := range [][]interface{}{
		{"https://www.w3.org/2018/credentials/v1"},
		{"https://www.w3.org/ns/credentials/v2", "https://www.w3.org/2018/credentials/v1"},
	} {
		vcClaim := map[string]interface{}{
			"@context":          ctx,
			"type":              []interface{}{"VerifiableCredential"},
			"credentialSubject": map[string]interface{}{"name": "Alice"},
			"expirationDate":    "2020-01-01T00:00:00Z",
		}
		jwt, resolver := signExpiryJWT(t, map[string]interface{}{"iss": expiryTestDID, "vc": vcClaim})
		body := map[string]interface{}{"issuer": expiryTestDID,
			"proof": map[string]interface{}{"type": "JwtProof2020", "jwt": jwt, "verificationMethod": expiryTestDID + "#key-1"}}
		for k, v := range vcClaim {
			body[k] = v
		}
		raw, _ := json.Marshal(body)
		c, err := vc.ParseCredential(raw)
		if err != nil {
			t.Fatalf("%v: parse: %v", ctx, err)
		}
		if err := c.Verify(vc.WithResolver(resolver)); err != nil {
			t.Fatalf("%v: proof refused, the test would prove nothing: %v", ctx, err)
		}
		err = c.Verify(vc.WithResolver(resolver), vc.WithCheckExpiration())
		if err == nil || !strings.Contains(err.Error(), "credential is expired") {
			t.Fatalf("%v: err = %v, want the credential expired", ctx, err)
		}
	}
}

// The did-jwt-vc form keeps a falsy exp (0) as a claim and shows no date for
// it; the JWT check still refuses it, as the JWT path does.
func TestJwtProof2020_ZeroExpRefused(t *testing.T) {
	jwt, resolver := signExpiryJWT(t, map[string]interface{}{
		"iss": expiryTestDID, "exp": 0,
		"vc": map[string]interface{}{
			"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":              []interface{}{"VerifiableCredential"},
			"credentialSubject": map[string]interface{}{"name": "Alice"},
		},
	})
	raw, _ := json.Marshal(map[string]interface{}{
		"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":              []interface{}{"VerifiableCredential"},
		"issuer":            map[string]interface{}{"id": expiryTestDID},
		"credentialSubject": map[string]interface{}{"name": "Alice"},
		"exp":               0,
		"proof":             map[string]interface{}{"type": "JwtProof2020", "jwt": jwt, "verificationMethod": expiryTestDID + "#key-1"},
	})
	c, err := vc.ParseCredential(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := c.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("proof refused, the test would prove nothing: %v", err)
	}
	if err := c.Verify(vc.WithResolver(resolver), vc.WithCheckExpiration()); err == nil || !strings.Contains(err.Error(), "exp") {
		t.Fatalf("err = %v, want the exp claim refused", err)
	}
}

// expirationDate binds to exp at the second, so it may lie later in that
// second than exp itself; the token is expired from exp on, as on the JWT path.
func TestJwtProof2020_ExpiredInsideTheClaimSecond(t *testing.T) {
	exp := time.Now().Add(-time.Hour).Unix()
	jwt, resolver := signExpiryJWT(t, map[string]interface{}{
		"iss": expiryTestDID, "exp": exp,
		"vc": map[string]interface{}{
			"@context":          []interface{}{"https://www.w3.org/ns/credentials/v2"},
			"type":              []interface{}{"VerifiableCredential"},
			"credentialSubject": map[string]interface{}{"name": "Alice"},
		},
	})
	raw, _ := json.Marshal(map[string]interface{}{
		"@context":          []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":              []interface{}{"VerifiableCredential"},
		"issuer":            expiryTestDID,
		"credentialSubject": map[string]interface{}{"name": "Alice"},
		"validUntil":        time.Unix(exp, 900000000).UTC().Format(time.RFC3339Nano),
		"proof":             map[string]interface{}{"type": "JwtProof2020", "jwt": jwt, "verificationMethod": expiryTestDID + "#key-1"},
	})
	c, err := vc.ParseCredential(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Seen at exp + 0.5 s: before validUntil, after exp.
	leeway := time.Since(time.Unix(exp, 500000000))
	if err := c.Verify(vc.WithResolver(resolver), vc.WithCheckExpiration(), vc.WithLeeway(leeway)); err == nil || !strings.Contains(err.Error(), "(exp)") {
		t.Fatalf("err = %v, want the exp claim refused", err)
	}
}
