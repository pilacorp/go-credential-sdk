package jws

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"math/big"
	"runtime"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/jwk"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	p256, p256Pub := newP256Signer(t)
	k1, k1Pub := newSecpSigner(t, false)
	for _, tc := range []struct {
		name string
		s    Signer
		pub  *ecdsa.PublicKey
		alg  string
	}{
		{"P-256", p256, p256Pub, AlgES256},
		{"secp256k1", k1, k1Pub, AlgES256K},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := `{"iss":"https://x", "name":"Nguyễn <a&b>"}`
			token := mustSign(t, tc.s, tc.pub, map[string]any{"typ": "dc+sd-jwt", "kid": "key-2"}, payload)
			h, got, err := Verify(token, tc.pub, nil)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if string(got) != payload {
				t.Fatalf("payload %q, want the signed bytes unchanged %q", got, payload)
			}
			if h.Alg() != tc.alg || h.Typ() != "dc+sd-jwt" || h.Kid() != "key-2" {
				t.Fatalf("header %v", h)
			}
			if sig, _ := jose.DecodeSegment(token[strings.LastIndex(token, ".")+1:]); len(sig) != 64 {
				t.Fatalf("signature is %d bytes, want 64", len(sig))
			}
		})
	}
}

// RFC 7515 §2: the payload is an arbitrary sequence of octets, and the empty
// one base64url-encodes to the empty string.
func TestEmptyPayloadRoundTrip(t *testing.T) {
	s, pub := newP256Signer(t)
	for name, payload := range map[string][]byte{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			token, err := Sign(s, pub, nil, payload)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if parts := strings.Split(token, "."); len(parts) != 3 || parts[1] != "" {
				t.Fatalf("token %q, want an empty middle part", token)
			}
			_, got, err := Verify(token, pub, nil)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if len(got) != 0 {
				t.Fatalf("payload %q, want empty", got)
			}
		})
	}
}

// The alg comes from the curve of pub, recognised by its parameters.
func TestSignAlgFromPublicKey(t *testing.T) {
	p256, p256Pub := newP256Signer(t)
	k1, k1Pub := newSecpSigner(t, false)
	params := *secp256k1.S256().Params()
	k1Copy := &ecdsa.PublicKey{Curve: &params, X: k1Pub.X, Y: k1Pub.Y}
	for _, tc := range []struct {
		name string
		s    Signer
		pub  *ecdsa.PublicKey
		want string
	}{
		{"P-256", p256, p256Pub, AlgES256},
		{"secp256k1", k1, k1Pub, AlgES256K},
		{"secp256k1 on copied parameters", k1, k1Copy, AlgES256K},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, err := Verify(mustSign(t, tc.s, tc.pub, nil, `{}`), tc.pub, nil)
			if err != nil {
				t.Fatal(err)
			}
			if h.Alg() != tc.want {
				t.Fatalf("alg %q, want %q", h.Alg(), tc.want)
			}
		})
	}
}

func TestSignHeaderAlgMustMatchKey(t *testing.T) {
	s, pub := newP256Signer(t)
	for _, alg := range []any{"ES256K", "RS256", "none", "", 1} {
		_, err := Sign(s, pub, map[string]any{"alg": alg}, []byte(`{}`))
		wantErr(t, err, jose.ErrInvalidArgument)
	}
	if _, err := Sign(s, pub, map[string]any{"alg": "ES256"}, []byte(`{}`)); err != nil {
		t.Fatalf("an alg equal to the key's must pass: %v", err)
	}
}

func TestSignRejectsBadPublicKeyBeforeSigning(t *testing.T) {
	p256, pub := newP256Signer(t)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	for name, key := range map[string]*ecdsa.PublicKey{
		"nil":       nil,
		"nil X":     {Curve: pub.Curve, Y: pub.Y},
		"P-384":     &p384.PublicKey,
		"off curve": {Curve: pub.Curve, X: pub.X, Y: new(big.Int).Add(pub.Y, big.NewInt(1))},
	} {
		t.Run(name, func(t *testing.T) {
			s := &countingSigner{Signer: p256}
			_, err := Sign(s, key, nil, []byte(`{}`))
			wantErr(t, err, ErrBadKey)
			if s.calls != 0 {
				t.Fatalf("signer called %d times, want 0", s.calls)
			}
		})
	}
}

func TestSignHeaderNotHTMLEscaped(t *testing.T) {
	s, pub := newP256Signer(t)
	token := mustSign(t, s, pub, map[string]any{"kid": "a<b>&c"}, `{}`)
	h, _ := jose.DecodeSegment(strings.Split(token, ".")[0])
	if !strings.Contains(string(h), `"a<b>&c"`) {
		t.Fatalf("header %s escapes HTML characters", h)
	}
}

func TestSignRejectsExtensionHeaders(t *testing.T) {
	p256, pub := newP256Signer(t)
	for _, h := range []map[string]any{{"crit": []any{"exp"}}, {"b64": false}, {"b64": true}} {
		s := &countingSigner{Signer: p256}
		_, err := Sign(s, pub, h, []byte(`{}`))
		wantErr(t, err, ErrUnsupportedHeader)
		if s.calls != 0 {
			t.Fatalf("%v: signer called %d times, want 0", h, s.calls)
		}
	}
}

// A header that EncodeJSON writes but Verify would refuse to read is a caller
// mistake, caught before the signer is called.
func TestSignRejectsHeaderVerifyWouldRefuse(t *testing.T) {
	p256, pub := newP256Signer(t)
	var deep any = "x"
	for range jose.MaxJSONDepth + 1 {
		deep = map[string]any{"a": deep}
	}
	for name, h := range map[string]Header{
		"nesting deeper than MaxJSONDepth": {"x": deep},
		"duplicate key in a raw value":     {"x": json.RawMessage(`{"a":1,"a":2}`)},
	} {
		t.Run(name, func(t *testing.T) {
			s := &countingSigner{Signer: p256}
			_, err := Sign(s, pub, h, []byte(`{}`))
			wantErr(t, err, jose.ErrInvalidArgument)
			if errors.Is(err, jose.ErrMalformed) {
				t.Fatalf("%v also matches jose.ErrMalformed, which means bad received input", err)
			}
			if s.calls != 0 {
				t.Fatalf("signer called %d times, want 0", s.calls)
			}
		})
	}
}

// Sign checks the signer's answer only by verifying the token with pub, so
// every answer that is not a valid 64-byte r||s by the key of pub is
// ErrSelfCheck, and never ErrBadSignature: the fault is the signer's, not a
// received token's.
func TestSignSelfCheck(t *testing.T) {
	p256, p256Pub := newP256Signer(t)
	k1, k1Pub := newSecpSigner(t, false)
	_, otherP256 := newP256Signer(t)
	_, otherK1 := newSecpSigner(t, false)
	n := elliptic.P256().Params().N
	one := make([]byte, 32)
	one[31] = 1
	nb := make([]byte, 32)
	n.FillBytes(nb)
	answer := func(raw []byte) Signer { return funcSigner(func([]byte) ([]byte, error) { return raw, nil }) }
	der := funcSigner(func(d []byte) ([]byte, error) {
		raw, _ := p256.Sign(d)
		return asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])})
	})
	padded := funcSigner(func(d []byte) ([]byte, error) {
		raw, err := p256.Sign(d)
		return append(raw, 0), err
	})
	for _, tc := range []struct {
		name string
		s    Signer
		pub  *ecdsa.PublicKey
	}{
		{"another P-256 key", p256, otherP256},
		{"another secp256k1 key", k1, otherK1},
		{"secp256k1 signer, P-256 key", k1, p256Pub},
		{"P-256 signer, secp256k1 key", p256, k1Pub},
		{"DER", der, p256Pub},
		{"64 bytes plus one", padded, p256Pub},
		{"63 bytes", answer(make([]byte, 63)), p256Pub},
		{"empty", answer(nil), p256Pub},
		{"r = 0", answer(append(make([]byte, 32), one...)), p256Pub},
		{"s = 0", answer(append(append([]byte{}, one...), make([]byte, 32)...)), p256Pub},
		{"r = n", answer(append(append([]byte{}, nb...), one...)), p256Pub},
		{"s = n", answer(append(append([]byte{}, one...), nb...)), p256Pub},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, err := Sign(tc.s, tc.pub, nil, []byte(`{}`))
			wantErr(t, err, ErrSelfCheck)
			if token != "" {
				t.Fatalf("token %q returned with an error", token)
			}
			if errors.Is(err, ErrBadSignature) || errors.Is(err, ErrAlgKeyMismatch) {
				t.Fatalf("%v also matches a Verify error", err)
			}
		})
	}
}

// A secp256k1 signer that appends the recovery id v answers 65 bytes. RFC 7518
// §3.4 and RFC 8812 §3.2 define the signature as 64-byte R||S, and Sign does
// not repair the answer, so the token fails the self-check.
func TestSign65ByteAnswerIsSelfCheck(t *testing.T) {
	k1v, pub := newSecpSigner(t, true)
	_, err := Sign(k1v, pub, nil, []byte(`{}`))
	wantErr(t, err, ErrSelfCheck)
}

// Sign keeps the signer's r||s byte for byte, so a high-S answer is signed and
// verifies as is: RFC 7518 §3.4 and RFC 8812 §3.2 put no limit on s beyond
// ECDSA verification, which accepts any s in [1, n-1] (FIPS 186-5 §6.4.2 step
// 1).
func TestSignKeepsSignerSignature(t *testing.T) {
	p256, p256Pub := newP256Signer(t)
	k1, k1Pub := newSecpSigner(t, false)
	for _, tc := range []struct {
		name  string
		s     Signer
		pub   *ecdsa.PublicKey
		curve elliptic.Curve
	}{
		{"P-256", p256, p256Pub, elliptic.P256()},
		{"secp256k1", k1, k1Pub, secp256k1.S256()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var answered []byte
			high := highS(tc.s, tc.curve)
			rec := funcSigner(func(d []byte) ([]byte, error) {
				raw, err := high.Sign(d)
				answered = raw
				return raw, err
			})
			token := mustSign(t, rec, tc.pub, nil, `{"a":1}`)
			sig, _ := jose.DecodeSegment(token[strings.LastIndex(token, ".")+1:])
			if !bytes.Equal(sig, answered) {
				t.Fatal("token signature differs from the signer's answer")
			}
			half := new(big.Int).Rsh(tc.curve.Params().N, 1)
			if new(big.Int).SetBytes(sig[32:]).Cmp(half) <= 0 {
				t.Fatal("test signer did not answer high-S")
			}
			if _, _, err := Verify(token, tc.pub, nil); err != nil {
				t.Fatalf("high-S must verify: %v", err)
			}
		})
	}
}

func TestSignPropagatesSignerError(t *testing.T) {
	_, pub := newP256Signer(t)
	boom := errors.New("signer down")
	_, err := Sign(funcSigner(func([]byte) ([]byte, error) { return nil, boom }), pub, nil, []byte(`{}`))
	if !errors.Is(err, boom) || !errors.Is(err, ErrSigner) {
		t.Fatalf("got %v, want ErrSigner and the signer's error wrapped", err)
	}
}

func TestSignRejectsInvalidArguments(t *testing.T) {
	s, pub := newP256Signer(t)
	_, err := Sign(nil, pub, nil, []byte(`{}`))
	wantErr(t, err, jose.ErrInvalidArgument)
	_, err = Sign(s, pub, Header{"x": make(chan int)}, []byte(`{}`))
	wantErr(t, err, jose.ErrInvalidArgument)
}

// craft builds a token from raw parts, signed by s over the given segments.
func craft(t *testing.T, s Signer, header, payload string) string {
	t.Helper()
	input := jose.EncodeSegment([]byte(header)) + "." + jose.EncodeSegment([]byte(payload))
	d := sha256.Sum256([]byte(input))
	sig, err := s.Sign(d[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + jose.EncodeSegment(sig[:64])
}

func TestVerifyMalformed(t *testing.T) {
	s, pub := newP256Signer(t)
	good := mustSign(t, s, pub, nil, `{}`)
	p := strings.Split(good, ".")
	for name, tok := range map[string]string{
		"two parts":         p[0] + "." + p[1],
		"four parts":        good + ".x",
		"empty header":      "." + p[1] + "." + p[2],
		"line break in sig": p[0] + "." + p[1] + "." + p[2][:10] + "\n" + p[2][10:],
		"header not object": craft(t, s, `["ES256"]`, `{}`),
		"alg not string":    craft(t, s, `{"alg":1}`, `{}`),
		"duplicate alg":     craft(t, s, `{"alg":"ES256","alg":"ES256K"}`, `{}`),
		"header trailing":   craft(t, s, `{"alg":"ES256"}x`, `{}`),
		"header not base64": "@@@." + p[1] + "." + p[2],
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := Verify(tok, pub, nil)
			wantErr(t, err, jose.ErrMalformed)
		})
	}
}

func TestVerifyRejectsExtensionHeaders(t *testing.T) {
	s, pub := newP256Signer(t)
	for _, h := range []string{
		`{"alg":"ES256","crit":["exp"]}`,
		`{"alg":"ES256","b64":false}`,
		`{"alg":"ES256","b64":true}`, // RFC 7797 §6: b64 needs crit, which is refused
	} {
		_, _, err := Verify(craft(t, s, h, `{}`), pub, nil)
		wantErr(t, err, ErrUnsupportedHeader)
	}
}

func TestVerifyAlgRules(t *testing.T) {
	p256, p256Pub := newP256Signer(t)
	k1, k1Pub := newSecpSigner(t, false)

	for _, alg := range []string{"none", "HS256", "RS256", "PS256", "EdDSA"} {
		tok := craft(t, p256, `{"alg":"`+alg+`"}`, `{}`)
		_, _, err := Verify(tok, p256Pub, []string{alg, AlgES256})
		wantErr(t, err, ErrAlgNotAllowed)
	}

	es256k := mustSign(t, k1, k1Pub, nil, `{}`)
	_, _, err := Verify(es256k, k1Pub, []string{AlgES256})
	wantErr(t, err, ErrAlgNotAllowed)

	// The key decides: an ES256 header over a secp256k1 key, and the reverse.
	_, _, err = Verify(craft(t, k1, `{"alg":"ES256"}`, `{}`), k1Pub, nil)
	wantErr(t, err, ErrAlgKeyMismatch)
	_, _, err = Verify(craft(t, p256, `{"alg":"ES256K"}`, `{}`), p256Pub, nil)
	wantErr(t, err, ErrAlgKeyMismatch)
}

// The verifier's key is the only key: a jwk in the header naming the signer's
// key does not rescue a token checked against another key.
func TestVerifyIgnoresKeyInHeader(t *testing.T) {
	attacker, attackerPub := newP256Signer(t)
	_, victimPub := newP256Signer(t)
	key, _ := jwk.FromPublicKey(attackerPub)
	tok := mustSign(t, attacker, attackerPub, map[string]any{"jwk": key}, `{}`)
	_, _, err := Verify(tok, victimPub, nil)
	wantErr(t, err, ErrBadSignature)
}

func TestVerifySignatureFormats(t *testing.T) {
	s, pub := newP256Signer(t)
	tok := mustSign(t, s, pub, nil, `{}`)
	p := strings.Split(tok, ".")
	sig, _ := jose.DecodeSegment(p[2])
	der, _ := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])})
	// Zeros before s keep the value of s, so only the 64-octet rule of RFC
	// 7518 §3.4 rejects these.
	zeroThenS := func(zeros int) []byte {
		return append(append(append([]byte{}, sig[:32]...), make([]byte, zeros)...), sig[32:]...)
	}
	for name, raw := range map[string][]byte{
		"65 bytes":       append(append([]byte{}, sig...), 1),
		"r, one zero, s": zeroThenS(1),
		"r, 32 zeros, s": zeroThenS(32),
		"DER":            der,
		"63 bytes":       sig[:63],
		"empty":          nil,
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := Verify(p[0]+"."+p[1]+"."+jose.EncodeSegment(raw), pub, nil)
			wantErr(t, err, ErrBadSignature)
		})
	}
}

func TestVerifyRejectsScalarsOutOfRange(t *testing.T) {
	s, pub := newP256Signer(t)
	p := strings.Split(mustSign(t, s, pub, nil, `{}`), ".")
	sig, _ := jose.DecodeSegment(p[2])
	nb := make([]byte, 32)
	elliptic.P256().Params().N.FillBytes(nb)
	for name, raw := range map[string][]byte{
		"r = 0": append(make([]byte, 32), sig[32:]...),
		"s = n": append(append([]byte{}, sig[:32]...), nb...),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := Verify(p[0]+"."+p[1]+"."+jose.EncodeSegment(raw), pub, nil)
			wantErr(t, err, ErrBadSignature)
		})
	}
}

// decred reduces r and s mod n, so without the range check s = n+1 would
// verify as s = 1. The key is recovered so that (r = Gx, s = 1) is a valid
// signature over the token's signing input.
func TestVerifySecp256k1RejectsScalarAboveN(t *testing.T) {
	input := jose.EncodeSegment([]byte(`{"alg":"ES256K"}`)) + "." + jose.EncodeSegment([]byte(`{}`))
	digest := sha256.Sum256([]byte(input))
	gx := make([]byte, 32)
	secp256k1.S256().Params().Gx.FillBytes(gx)
	one := make([]byte, 32)
	one[31] = 1
	compact := append(append([]byte{27}, gx...), one...) // 27: recovery code 0, G has even y
	key, _, err := decredecdsa.RecoverCompact(compact, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	pub := key.ToECDSA()
	if _, _, err := Verify(input+"."+jose.EncodeSegment(append(append([]byte{}, gx...), one...)), pub, nil); err != nil {
		t.Fatalf("(Gx, 1) must verify: %v", err)
	}
	nPlus1 := make([]byte, 32)
	new(big.Int).Add(secp256k1.S256().Params().N, big.NewInt(1)).FillBytes(nPlus1)
	_, _, err = Verify(input+"."+jose.EncodeSegment(append(append([]byte{}, gx...), nPlus1...)), pub, nil)
	wantErr(t, err, ErrBadSignature)
}

// The same for r: the key is recovered so that (r = 1, s = 1) is valid, and
// r = n+1 must not verify as r = 1.
func TestVerifySecp256k1RejectsRAboveN(t *testing.T) {
	input := jose.EncodeSegment([]byte(`{"alg":"ES256K"}`)) + "." + jose.EncodeSegment([]byte(`{}`))
	digest := sha256.Sum256([]byte(input))
	one := make([]byte, 32)
	one[31] = 1
	compact := append(append([]byte{27}, one...), one...) // 27: recovery code 0, R.x = 1
	key, _, err := decredecdsa.RecoverCompact(compact, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	pub := key.ToECDSA()
	if _, _, err := Verify(input+"."+jose.EncodeSegment(append(append([]byte{}, one...), one...)), pub, nil); err != nil {
		t.Fatalf("(1, 1) must verify: %v", err)
	}
	nPlus1 := make([]byte, 32)
	new(big.Int).Add(secp256k1.S256().Params().N, big.NewInt(1)).FillBytes(nPlus1)
	_, _, err = Verify(input+"."+jose.EncodeSegment(append(nPlus1, one...)), pub, nil)
	wantErr(t, err, ErrBadSignature)
}

// RFC 7515 Appendix A.3: the ES256 example token verifies with the example
// key (d left out: jwk.ToPublicKey refuses a private key) and returns the
// example payload, CRLFs included (Appendix A.1.1).
func TestVerifyRFC7515AppendixA3(t *testing.T) {
	key, err := jwk.ToPublicKey(map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
		"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
	})
	if err != nil {
		t.Fatal(err)
	}
	const token = "eyJhbGciOiJFUzI1NiJ9" +
		"." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
		"." +
		"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA" +
		"pmWQxfKTUJqPP3-Kg6NU1Q"
	header, payload, err := Verify(token, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if header.Alg() != AlgES256 {
		t.Fatalf("alg %q, want ES256", header.Alg())
	}
	const want = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
	if string(payload) != want {
		t.Fatalf("payload %q, want %q", payload, want)
	}

	p := strings.Split(token, ".")
	sig, _ := jose.DecodeSegment(p[2])
	sig[10] ^= 0x01
	_, _, err = Verify(p[0]+"."+p[1]+"."+jose.EncodeSegment(sig), key, nil)
	wantErr(t, err, ErrBadSignature)
}

// The digest is over the received segments: re-encoding the same JSON payload
// differently breaks the signature.
func TestVerifyHashesReceivedBytes(t *testing.T) {
	s, pub := newP256Signer(t)
	p := strings.Split(mustSign(t, s, pub, nil, `{"a": 1}`), ".")
	tampered := p[0] + "." + jose.EncodeSegment([]byte(`{"a":1}`)) + "." + p[2]
	_, _, err := Verify(tampered, pub, nil)
	wantErr(t, err, ErrBadSignature)
}

func TestVerifyWrongKey(t *testing.T) {
	s, pub := newSecpSigner(t, false)
	_, other := newSecpSigner(t, false)
	_, _, err := Verify(mustSign(t, s, pub, nil, `{}`), other, nil)
	wantErr(t, err, ErrBadSignature)
}

func TestVerifyRejectsBadKey(t *testing.T) {
	s, pub := newP256Signer(t)
	tok := mustSign(t, s, pub, nil, `{}`)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	off := &ecdsa.PublicKey{Curve: pub.Curve, X: pub.X, Y: new(big.Int).Add(pub.Y, big.NewInt(1))}
	for name, key := range map[string]*ecdsa.PublicKey{"nil": nil, "P-384": &p384.PublicKey, "off curve": off} {
		t.Run(name, func(t *testing.T) {
			_, _, err := Verify(tok, key, nil)
			wantErr(t, err, ErrBadKey)
		})
	}
}

// Verify refuses a token with too many dots without splitting all of it:
// strings.Split would allocate 16 bytes per dot (16 MB here).
func TestVerifyManyDotsAllocatesLittle(t *testing.T) {
	_, pub := newP256Signer(t)
	dots := strings.Repeat(".", 1<<20)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, _, err := Verify(dots, pub, nil)
	runtime.ReadMemStats(&after)
	wantErr(t, err, jose.ErrMalformed)
	if n := after.TotalAlloc - before.TotalAlloc; n > 64<<10 {
		t.Fatalf("Verify allocated %d bytes for 1 MB of dots, want under 64 KB", n)
	}
}

func TestAlgOfInvalidKindPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic for an invalid curve kind")
		}
	}()
	algOf(0)
}

// UnverifiedHeader and UnverifiedPayload read without any key, and refuse what
// Verify refuses before the signature check.
func TestUnverifiedHeader(t *testing.T) {
	s, pub := newP256Signer(t)
	token := mustSign(t, s, pub, map[string]any{"kid": "key-1"}, `{}`)
	h, err := UnverifiedHeader(token)
	if err != nil {
		t.Fatalf("UnverifiedHeader: %v", err)
	}
	if h.Kid() != "key-1" || h.Alg() != AlgES256 {
		t.Fatalf("header %v", h)
	}
	_, err = UnverifiedHeader(token[:strings.LastIndex(token, ".")])
	wantErr(t, err, jose.ErrMalformed)

	payload, err := UnverifiedPayload(token)
	if err != nil || string(payload) != `{}` {
		t.Fatalf("UnverifiedPayload: %q, %v", payload, err)
	}
	_, err = UnverifiedPayload(token[:strings.LastIndex(token, ".")])
	wantErr(t, err, jose.ErrMalformed)
}

// Cases from RFC 7515 §4.1.9: case-insensitive, "application/" implied when
// the value has no '/', and parameters never shortened.
func TestHeaderTypIs(t *testing.T) {
	for _, tc := range []struct {
		typ       any
		mediaType string
		want      bool
	}{
		{"kb+jwt", "application/kb+jwt", true},
		{"application/kb+jwt", "kb+jwt", true},
		{"KB+JWT", "kb+jwt", true},
		{"kb+jwt", "Application/KB+JWT", true},
		{"text/kb+jwt", "application/kb+jwt", false},
		{`application/example;part="1/2"`, `application/example;part="1/2"`, false},
		{"kb+jwt ", "kb+jwt", false},
		{"\u212Ab+jwt", "kb+jwt", false}, // KELVIN SIGN folds to k only under Unicode rules
		{nil, "", false},
		{123, "123", false},
	} {
		h := Header{"alg": AlgES256}
		if tc.typ != nil {
			h["typ"] = tc.typ
		}
		if got := h.TypIs(tc.mediaType); got != tc.want {
			t.Errorf("typ %#v TypIs(%q) = %v, want %v", tc.typ, tc.mediaType, got, tc.want)
		}
	}
}
