package didcomm

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func testKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func parseMembers(t *testing.T, s string) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("parse JWE: %v", err)
	}
	return m
}

func marshal(t *testing.T, m map[string]interface{}) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// sealWith seals plaintext under key with the given protected header and AAD,
// so a header the code must refuse is otherwise a well-formed message.
func sealWith(t *testing.T, key []byte, protected, plaintext string, aad []byte) map[string]interface{} {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, gcm.NonceSize())
	sealed := gcm.Seal(nil, iv, []byte(plaintext), aad)
	split := len(sealed) - gcm.Overhead()
	return map[string]interface{}{
		"protected":  protected,
		"iv":         b64(iv),
		"ciphertext": b64(sealed[:split]),
		"tag":        b64(sealed[split:]),
	}
}

func wantErr(t *testing.T, err error, sub string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error containing %q, got nil", sub)
	}
	if !strings.Contains(err.Error(), sub) {
		t.Fatalf("error %q does not contain %q", err, sub)
	}
}

// The header names what the code does: the shared key is the content
// encryption key (RFC 7518 §4.5) and the content is A256GCM (§5.3).
func TestEncrypt_ProtectedHeaderIsDirA256GCM(t *testing.T) {
	out, err := Encrypt(testKey(), "hi")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	m := parseMembers(t, out)
	header, err := base64.RawURLEncoding.DecodeString(m["protected"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if string(header) != `{"alg":"dir","enc":"A256GCM"}` {
		t.Fatalf("protected header = %s", header)
	}
	// RFC 7516 §7.2.1: encrypted_key is absent when the encrypted key is empty.
	if _, ok := m["encrypted_key"]; ok {
		t.Fatal("encrypted_key present for alg dir")
	}
	iv, _ := base64.RawURLEncoding.DecodeString(m["iv"].(string))
	tag, _ := base64.RawURLEncoding.DecodeString(m["tag"].(string))
	if len(iv) != 12 || len(tag) != 16 {
		t.Fatalf("iv %d bytes, tag %d bytes; want 12 and 16", len(iv), len(tag))
	}
}

// RFC 7516 §5.1 step 14: the encoded protected header is the AAD, so a
// message whose header was changed no longer decrypts.
func TestDecryptJWE_ProtectedHeaderIsAuthenticated(t *testing.T) {
	out, err := Encrypt(testKey(), "hi")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	for _, h := range []string{
		`{"alg":"dir","enc":"A256GCM","kid":"x"}`,
		`{"enc":"A256GCM","alg":"dir"}`,
	} {
		m := parseMembers(t, out)
		m["protected"] = b64([]byte(h))
		_, err := DecryptJWE(marshal(t, m), testKey())
		wantErr(t, err, "decryption failed")
	}
}

// RFC 7516 §5.2 steps 2-5: the header is decoded and checked before any
// decryption. Every message here is sealed with its own header as AAD, so
// only the header check can refuse it.
func TestDecryptJWE_RefusesHeader(t *testing.T) {
	cases := []struct {
		name   string
		header string
		nilAAD bool
		errSub string
	}{
		{name: "previous format", header: `{"alg":"ECDH-ES","crv":"secp256k1","enc":"A256GCM","typ":"application/didcomm-encrypted+json"}`, nilAAD: true, errSub: `"alg"`},
		{name: "alg ECDH-ES", header: `{"alg":"ECDH-ES","enc":"A256GCM"}`, errSub: `"alg"`},
		{name: "alg none", header: `{"alg":"none","enc":"A256GCM"}`, errSub: `"alg"`},
		{name: "enc A128GCM", header: `{"alg":"dir","enc":"A128GCM"}`, errSub: `"enc"`},
		{name: "alg missing", header: `{"enc":"A256GCM"}`, errSub: `"alg"`},
		{name: "enc missing", header: `{"alg":"dir"}`, errSub: `"enc"`},
		{name: "names are case-sensitive", header: `{"ALG":"dir","enc":"A256GCM"}`, errSub: `"alg"`},
		{name: "alg not a string", header: `{"alg":["dir"],"enc":"A256GCM"}`, errSub: `"alg"`},
		{name: "crit", header: `{"alg":"dir","enc":"A256GCM","crit":["exp"],"exp":1}`, errSub: `"crit"`},
		{name: "zip", header: `{"alg":"dir","enc":"A256GCM","zip":"DEF"}`, errSub: `"zip"`},
		{name: "array", header: `[]`, errSub: "JSON object"},
		{name: "null", header: `null`, errSub: "JSON object"},
		{name: "invalid UTF-8", header: "{\"alg\":\"dir\",\"enc\":\"A256GCM\",\"x\":\"\xff\"}", errSub: "UTF-8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			protected := b64([]byte(tc.header))
			aad := []byte(protected)
			if tc.nilAAD {
				aad = nil
			}
			_, err := DecryptJWE(marshal(t, sealWith(t, testKey(), protected, "hi", aad)), testKey())
			wantErr(t, err, tc.errSub)
		})
	}
}

func TestDecryptJWE_RefusesMalformedProtected(t *testing.T) {
	valid := b64([]byte(`{"alg":"dir","enc":"A256GCM"}`))
	for name, protected := range map[string]string{
		"empty":      "",
		"padded":     valid + "=",
		"line break": valid[:4] + "\n" + valid[4:],
	} {
		t.Run(name, func(t *testing.T) {
			_, err := DecryptJWE(marshal(t, sealWith(t, testKey(), protected, "hi", []byte(protected))), testKey())
			wantErr(t, err, "protected")
		})
	}
}

// Members this package does not implement are refused rather than ignored:
// each one would change the key or the AAD (RFC 7516 §5.2 steps 8 and 14).
func TestDecryptJWE_RefusesUnsupportedMembers(t *testing.T) {
	out, err := Encrypt(testKey(), "hi")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	for name, value := range map[string]interface{}{
		"encrypted_key": "AAAA",
		"aad":           "AAAA",
		"unprotected":   map[string]interface{}{},
		"header":        map[string]interface{}{"kid": "x"},
		"recipients":    []interface{}{},
	} {
		t.Run(name, func(t *testing.T) {
			m := parseMembers(t, out)
			m[name] = value
			_, err := DecryptJWE(marshal(t, m), testKey())
			wantErr(t, err, `"`+name+`"`)
		})
	}
}

// JSON member names are case-sensitive; encoding/json is not.
func TestDecryptJWE_MemberNamesAreCaseSensitive(t *testing.T) {
	out, err := Encrypt(testKey(), "hi")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	for _, name := range []string{"protected", "iv", "ciphertext", "tag"} {
		t.Run(name, func(t *testing.T) {
			m := parseMembers(t, out)
			m[strings.ToUpper(name[:1])+name[1:]] = m[name]
			delete(m, name)
			_, err := DecryptJWE(marshal(t, m), testKey())
			wantErr(t, err, `"`+name+`"`)
		})
	}
}

// RFC 7518 §5.3: the A256GCM tag is 128 bits. Moving tag bytes into the
// ciphertext member must not be accepted.
func TestDecryptJWE_TagMustBe128Bits(t *testing.T) {
	out, err := Encrypt(testKey(), "hello")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	m := parseMembers(t, out)
	ct, _ := base64.RawURLEncoding.DecodeString(m["ciphertext"].(string))
	tag, _ := base64.RawURLEncoding.DecodeString(m["tag"].(string))
	// moved is the number of tag bytes moved into the ciphertext member.
	for name, moved := range map[string]int{"empty tag": 16, "15-byte tag": 1} {
		t.Run(name, func(t *testing.T) {
			sealed := append(append([]byte{}, ct...), tag...)
			at := len(ct) + moved
			m := parseMembers(t, out)
			m["ciphertext"] = b64(sealed[:at])
			m["tag"] = b64(sealed[at:])
			_, err := DecryptJWE(marshal(t, m), testKey())
			wantErr(t, err, "tag size")
		})
	}
}

func TestDecryptJWE_StrictBase64url(t *testing.T) {
	out, err := Encrypt(testKey(), "hello")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ct := parseMembers(t, out)["ciphertext"].(string)
	for name, v := range map[string]string{
		"line break": ct[:2] + "\n" + ct[2:],
		"padding":    ct + "=",
	} {
		t.Run(name, func(t *testing.T) {
			m := parseMembers(t, out)
			m["ciphertext"] = v
			_, err := DecryptJWE(marshal(t, m), testKey())
			wantErr(t, err, "ciphertext")
		})
	}
}

// A wrong key length is an error to the caller, never a process exit.
func TestKeyMustBe256Bits(t *testing.T) {
	for _, n := range []int{0, 16, 24, 33} {
		key := make([]byte, n)
		_, err := Encrypt(key, "hi")
		wantErr(t, err, "key size")
		_, err = DecryptJWE(marshal(t, sealWith(t, testKey(), b64([]byte(`{"alg":"dir","enc":"A256GCM"}`)), "hi", nil)), key)
		wantErr(t, err, "key size")
	}
}

// A message written by go-jose v4.1.4 (jose.DIRECT, jose.A256GCM) under the
// key a0 a1 ... bf decrypts here.
func TestDecryptJWE_GoJoseVector(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0xa0 + i)
	}
	const msg = `{"protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0","iv":"0QHYifz9uqStI3iF","ciphertext":"jnA_2N78ADGX5_2UvZMCx6-uPZ0Upo1NDaA0ni_CuJjoM2153yieCA","tag":"BR60YRyKyl8IedNWzzkRxw"}`
	got, err := DecryptJWE(msg, key)
	if err != nil {
		t.Fatalf("DecryptJWE: %v", err)
	}
	if got != `{"msg":"interop vector from go-jose v4"}` {
		t.Fatalf("plaintext = %q", got)
	}
}

// RFC 7518 Appendix C: Concat KDF for ECDH-ES with A128GCM, apu "Alice",
// apv "Bob".
func TestConcatKDF_RFC7518AppendixC(t *testing.T) {
	z := []byte{158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
		38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
		140, 254, 144, 196}
	got := concatKDF(z, "A128GCM", []byte("Alice"), []byte("Bob"), 128)
	if b64(got) != "VqqN6vgjbSBcIijNcacQGg" {
		t.Fatalf("derived key = %s, want VqqN6vgjbSBcIijNcacQGg", b64(got))
	}
}

const (
	alicePriv = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
	bobPriv   = "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
)

func pubHex(t *testing.T, privHex string) string {
	t.Helper()
	priv, err := hex.DecodeString(privHex)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(secp256k1PubFromPriv(priv))
}

// Both parties derive the same 32-byte key, and it is the KDF output, not the
// raw ECDH X coordinate.
func TestGetFromKeys_BothSidesAgree(t *testing.T) {
	aliceSide, err := GetFromKeys(pubHex(t, bobPriv), alicePriv)
	if err != nil {
		t.Fatal(err)
	}
	bobSide, err := GetFromKeys(pubHex(t, alicePriv), bobPriv)
	if err != nil {
		t.Fatal(err)
	}
	if len(aliceSide) != 32 || hex.EncodeToString(aliceSide) != hex.EncodeToString(bobSide) {
		t.Fatalf("keys differ: %x vs %x", aliceSide, bobSide)
	}
	z := rawSharedX(t, pubHex(t, bobPriv), alicePriv)
	if hex.EncodeToString(aliceSide) == hex.EncodeToString(z) {
		t.Fatal("key is the raw ECDH output")
	}
	if hex.EncodeToString(aliceSide) != hex.EncodeToString(concatKDF(z, "A256GCM", nil, nil, 256)) {
		t.Fatal("key is not Concat KDF(Z) with AlgorithmID A256GCM")
	}
	out, err := Encrypt(aliceSide, "hi bob")
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptJWE(out, bobSide)
	if err != nil || got != "hi bob" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestGetFromKeys_RefusesBadPrivateKey(t *testing.T) {
	peer := pubHex(t, bobPriv)
	for name, priv := range map[string]string{
		"31 bytes": alicePriv[2:],
		"33 bytes": alicePriv + "00",
		"zero":     strings.Repeat("00", 32),
		"order N":  "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := GetFromKeys(peer, priv)
			wantErr(t, err, "private key")
		})
	}
}

func secp256k1PubFromPriv(priv []byte) []byte {
	return secp256k1.PrivKeyFromBytes(priv).PubKey().SerializeCompressed()
}

func rawSharedX(t *testing.T, peerPubHex, ownPrivHex string) []byte {
	t.Helper()
	pubBytes, _ := hex.DecodeString(peerPubHex)
	pub, err := secp256k1.ParsePubKey(pubBytes)
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := hex.DecodeString(ownPrivHex)
	return secp256k1.GenerateSharedSecret(secp256k1.PrivKeyFromBytes(priv), pub)
}

func TestDecryptJWE_WrongKey(t *testing.T) {
	out, err := Encrypt(testKey(), "hi")
	if err != nil {
		t.Fatal(err)
	}
	other := testKey()
	other[0] ^= 1
	_, err = DecryptJWE(out, other)
	wantErr(t, err, "decryption failed")
}

func TestDecryptJWE_NotAJSONObject(t *testing.T) {
	for _, s := range []string{`[]`, `"x"`, `null`, `1`} {
		if _, err := DecryptJWE(s, testKey()); err == nil {
			t.Fatalf("%s: expected an error", s)
		}
	}
}
