package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// signJWTWithHeader signs payload under header, with a 64-byte r||s signature
// (RFC 8812 §3.2) or the 65-byte go-ethereum form with its recovery id.
func signJWTWithHeader(t *testing.T, header interface{}, payload map[string]interface{}, recoverable bool) string {
	t.Helper()
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatal(err)
	}
	hdr, _ := json.Marshal(header)
	body, _ := json.Marshal(payload)
	input := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(input))
	sig, err := ethcrypto.Sign(digest[:], priv)
	if err != nil {
		t.Fatal(err)
	}
	if !recoverable {
		sig = sig[:64]
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// VCDM 1.1 §6.3.1: "alg MUST be set for digital signatures"; "typ, if
// present, MUST be set to JWT" (a media type, RFC 7515 §4.1.9). RFC 7515
// §4.1.11: a crit this verifier does not understand makes the JWS invalid.
// did-jwt writes typ JWT with ES256K or ES256K-R for a secp256k1 key.
func TestVerifyJwtProof_Header(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA(testSecp256k1PrivHex)
	if err != nil {
		t.Fatal(err)
	}
	body := credentialBody()
	payload := sdkPayload(body)
	cases := []struct {
		name        string
		header      interface{}
		recoverable bool
		wantErr     string
	}{
		{"ES256K, 64-byte signature", map[string]interface{}{"typ": "JWT", "alg": "ES256K"}, false, ""},
		{"ES256K, 65-byte go-ethereum signature", map[string]interface{}{"typ": "JWT", "alg": "ES256K"}, true, ""},
		{"ES256K-R, 65-byte signature", map[string]interface{}{"typ": "JWT", "alg": "ES256K-R"}, true, ""},
		{"no typ", map[string]interface{}{"alg": "ES256K"}, false, ""},
		{"typ in lowercase", map[string]interface{}{"typ": "jwt", "alg": "ES256K"}, false, ""},
		{"no alg", map[string]interface{}{"typ": "JWT"}, false, "alg"},
		{"alg none", map[string]interface{}{"typ": "JWT", "alg": "none"}, false, "alg"},
		{"alg HS256", map[string]interface{}{"typ": "JWT", "alg": "HS256"}, false, "alg"},
		{"alg ES256", map[string]interface{}{"typ": "JWT", "alg": "ES256"}, false, "alg"},
		{"typ application/jwt", map[string]interface{}{"typ": "application/jwt", "alg": "ES256K"}, false, ""},
		{"typ JOSE", map[string]interface{}{"typ": "JOSE", "alg": "ES256K"}, false, "typ"},
		{"crit lists an extension", map[string]interface{}{"typ": "JWT", "alg": "ES256K", "crit": []interface{}{"b64"}, "b64": false}, false, "crit"},
		{"crit empty", map[string]interface{}{"typ": "JWT", "alg": "ES256K", "crit": []interface{}{}}, false, "crit"},
		{"typ not a string", map[string]interface{}{"typ": 1, "alg": "ES256K"}, false, "typ"},
		{"header not an object", []interface{}{"ES256K"}, false, "JSON object"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := VerifyJwtProofToken(body, signJWTWithHeader(t, c.header, payload, c.recoverable), &priv.PublicKey)
			if c.wantErr == "" && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
				t.Fatalf("err = %v, want one naming %q", err, c.wantErr)
			}
		})
	}
}

// RFC 7515 §4: header parameter names are case-sensitive, so only "kid"
// names the key; a "KID" beside it must not replace it.
func TestJwtKid_CaseSensitive(t *testing.T) {
	enc := func(header string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(header)) + ".e30.sig"
	}
	cases := []struct {
		header string
		want   string
	}{
		{`{"kid":"did:a#1"}`, "did:a#1"},
		{`{"KID":"did:a#1"}`, ""},
		{`{"kid":"did:a#1","KID":"did:evil#2"}`, "did:a#1"},
	}
	for _, c := range cases {
		got, _ := JwtKid(enc(c.header))
		if got != c.want {
			t.Errorf("%s: kid = %q, want %q", c.header, got, c.want)
		}
	}
}
