package jws

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
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
	k1v, k1vPub := newSecpSigner(t, true) // 65-byte r||s||v, as a Vault callback returns
	for _, tc := range []struct {
		name string
		s    Signer
		alg  string
		pub  *ecdsa.PublicKey
	}{
		{"ES256 in-memory", p256, AlgES256, p256Pub},
		{"ES256K 64-byte", k1, AlgES256K, k1Pub},
		{"ES256K 65-byte callback", k1v, AlgES256K, k1vPub},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := `{"iss":"https://x", "name":"Nguyễn <a&b>"}`
			token := mustSign(t, tc.s, tc.alg, map[string]any{"typ": "dc+sd-jwt", "kid": "did:x#key-2"}, payload)
			h, got, err := Verify(token, tc.pub, nil)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if string(got) != payload {
				t.Fatalf("payload %q, want the signed bytes unchanged %q", got, payload)
			}
			if h.Alg() != tc.alg || h.Typ() != "dc+sd-jwt" || h.Kid() != "did:x#key-2" {
				t.Fatalf("header %v", h)
			}
			if sig, _ := jose.DecodeSegment(token[strings.LastIndex(token, ".")+1:]); len(sig) != 64 {
				t.Fatalf("signature is %d bytes, want 64", len(sig))
			}
		})
	}
}

func TestSignHeaderNotHTMLEscaped(t *testing.T) {
	s, _ := newP256Signer(t)
	token := mustSign(t, s, AlgES256, map[string]any{"kid": "a<b>&c"}, `{}`)
	h, _ := jose.DecodeSegment(strings.Split(token, ".")[0])
	if !strings.Contains(string(h), `"a<b>&c"`) {
		t.Fatalf("header %s escapes HTML characters", h)
	}
}

func TestSignRejectsAlg(t *testing.T) {
	s, _ := newP256Signer(t)
	for _, alg := range []string{"RS256", "none", "HS256", "EdDSA", ""} {
		_, err := Sign(s, alg, nil, []byte(`{}`))
		wantErr(t, err, jose.ErrAlgNotAllowed)
	}
	_, err := Sign(s, AlgES256, map[string]any{"alg": "ES256K"}, []byte(`{}`))
	wantErr(t, err, jose.ErrInvalidArgument)
	if _, err := Sign(s, AlgES256, map[string]any{"alg": "ES256"}, []byte(`{}`)); err != nil {
		t.Fatalf("an alg equal to the argument must pass: %v", err)
	}
}

func TestSignRejectsExtensionHeaders(t *testing.T) {
	s, _ := newP256Signer(t)
	for _, h := range []map[string]any{{"crit": []any{"exp"}}, {"b64": false}} {
		_, err := Sign(s, AlgES256, h, []byte(`{}`))
		wantErr(t, err, jose.ErrUnsupportedHeader)
	}
}

func TestSignSignatureFormats(t *testing.T) {
	p256, _ := newP256Signer(t)
	der := funcSigner(func(d []byte) ([]byte, error) {
		raw, _ := p256.Sign(d)
		return asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])})
	})
	for name, s := range map[string]Signer{
		"DER":      der,
		"63 bytes": funcSigner(func([]byte) ([]byte, error) { return make([]byte, 63), nil }),
		"66 bytes": funcSigner(func([]byte) ([]byte, error) { return make([]byte, 66), nil }),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Sign(s, AlgES256, nil, []byte(`{}`))
			wantErr(t, err, jose.ErrSignatureFormat)
		})
	}
}

func TestSignRejectsScalarsOutOfRange(t *testing.T) {
	n := elliptic.P256().Params().N
	one := make([]byte, 32)
	one[31] = 1
	nb := make([]byte, 32)
	n.FillBytes(nb)
	for name, raw := range map[string][]byte{
		"r = 0": append(make([]byte, 32), one...),
		"s = 0": append(append([]byte{}, one...), make([]byte, 32)...),
		"r = n": append(append([]byte{}, nb...), one...),
		"s = n": append(append([]byte{}, one...), nb...),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Sign(funcSigner(func([]byte) ([]byte, error) { return raw, nil }), AlgES256, nil, []byte(`{}`))
			wantErr(t, err, jose.ErrSignatureFormat)
		})
	}
}

func TestSignPropagatesSignerError(t *testing.T) {
	boom := errors.New("vault down")
	_, err := Sign(funcSigner(func([]byte) ([]byte, error) { return nil, boom }), AlgES256, nil, []byte(`{}`))
	if !errors.Is(err, boom) || !errors.Is(err, jose.ErrSigner) {
		t.Fatalf("got %v, want jose.ErrSigner and the signer's error wrapped", err)
	}
}

func TestSignRejectsInvalidArguments(t *testing.T) {
	_, err := Sign(nil, AlgES256, nil, []byte(`{}`))
	wantErr(t, err, jose.ErrInvalidArgument)
	s, _ := newP256Signer(t)
	_, err = Sign(s, AlgES256, Header{"x": make(chan int)}, []byte(`{}`))
	wantErr(t, err, jose.ErrInvalidArgument)
}

// A signer answering high-S still yields a low-S token, on both curves; the
// high-S form of the same token still verifies.
func TestSignNormalisesToLowS(t *testing.T) {
	p256, p256Pub := newP256Signer(t)
	k1, k1Pub := newSecpSigner(t, false)
	for _, tc := range []struct {
		name  string
		s     Signer
		alg   string
		pub   *ecdsa.PublicKey
		curve elliptic.Curve
	}{
		{"P-256", p256, AlgES256, p256Pub, elliptic.P256()},
		{"secp256k1", k1, AlgES256K, k1Pub, secp256k1.S256()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := mustSign(t, highS(tc.s, tc.curve), tc.alg, nil, `{"a":1}`)
			parts := strings.Split(token, ".")
			sig, _ := jose.DecodeSegment(parts[2])
			s := new(big.Int).SetBytes(sig[32:])
			half := new(big.Int).Rsh(tc.curve.Params().N, 1)
			if s.Cmp(half) > 0 {
				t.Fatal("Sign returned a high-S signature")
			}
			if _, _, err := Verify(token, tc.pub, nil); err != nil {
				t.Fatalf("low-S: %v", err)
			}
			hs := new(big.Int).Sub(tc.curve.Params().N, s)
			hsb := make([]byte, 32)
			hs.FillBytes(hsb)
			flipped := parts[0] + "." + parts[1] + "." + jose.EncodeSegment(append(append([]byte{}, sig[:32]...), hsb...))
			if _, _, err := Verify(flipped, tc.pub, nil); err != nil {
				t.Fatalf("high-S must verify too: %v", err)
			}
		})
	}
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
	good := mustSign(t, s, AlgES256, nil, `{}`)
	p := strings.Split(good, ".")
	for name, tok := range map[string]string{
		"two parts":         p[0] + "." + p[1],
		"four parts":        good + ".x",
		"empty payload":     p[0] + ".." + p[2],
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
	for _, h := range []string{`{"alg":"ES256","crit":["exp"]}`, `{"alg":"ES256","b64":false}`} {
		_, _, err := Verify(craft(t, s, h, `{}`), pub, nil)
		wantErr(t, err, jose.ErrUnsupportedHeader)
	}
	if _, _, err := Verify(craft(t, s, `{"alg":"ES256","b64":true}`, `{}`), pub, nil); err != nil {
		t.Fatalf("b64:true is the default and must pass: %v", err)
	}
}

func TestVerifyAlgRules(t *testing.T) {
	p256, p256Pub := newP256Signer(t)
	k1, k1Pub := newSecpSigner(t, false)

	for _, alg := range []string{"none", "HS256", "RS256", "PS256", "EdDSA"} {
		tok := craft(t, p256, `{"alg":"`+alg+`"}`, `{}`)
		_, _, err := Verify(tok, p256Pub, []string{alg, AlgES256})
		wantErr(t, err, jose.ErrAlgNotAllowed)
	}

	es256k := mustSign(t, k1, AlgES256K, nil, `{}`)
	_, _, err := Verify(es256k, k1Pub, []string{AlgES256})
	wantErr(t, err, jose.ErrAlgNotAllowed)

	// The key decides: an ES256 header over a secp256k1 key, and the reverse.
	_, _, err = Verify(craft(t, k1, `{"alg":"ES256"}`, `{}`), k1Pub, nil)
	wantErr(t, err, jose.ErrAlgKeyMismatch)
	_, _, err = Verify(craft(t, p256, `{"alg":"ES256K"}`, `{}`), p256Pub, nil)
	wantErr(t, err, jose.ErrAlgKeyMismatch)
}

// The verifier's key is the only key: a jwk in the header naming the signer's
// key does not rescue a token checked against another key.
func TestVerifyIgnoresKeyInHeader(t *testing.T) {
	attacker, attackerPub := newP256Signer(t)
	_, victimPub := newP256Signer(t)
	key, _ := jwk.FromPublicKey(attackerPub)
	tok := mustSign(t, attacker, AlgES256, map[string]any{"jwk": key}, `{}`)
	_, _, err := Verify(tok, victimPub, nil)
	wantErr(t, err, jose.ErrBadSignature)
}

func TestVerifySignatureFormats(t *testing.T) {
	s, pub := newP256Signer(t)
	tok := mustSign(t, s, AlgES256, nil, `{}`)
	p := strings.Split(tok, ".")
	sig, _ := jose.DecodeSegment(p[2])
	der, _ := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])})
	for name, raw := range map[string][]byte{
		"65 bytes": append(append([]byte{}, sig...), 1),
		"DER":      der,
		"63 bytes": sig[:63],
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := Verify(p[0]+"."+p[1]+"."+jose.EncodeSegment(raw), pub, nil)
			wantErr(t, err, jose.ErrBadSignature)
		})
	}
}

func TestVerifyRejectsScalarsOutOfRange(t *testing.T) {
	s, pub := newP256Signer(t)
	p := strings.Split(mustSign(t, s, AlgES256, nil, `{}`), ".")
	sig, _ := jose.DecodeSegment(p[2])
	nb := make([]byte, 32)
	elliptic.P256().Params().N.FillBytes(nb)
	for name, raw := range map[string][]byte{
		"r = 0": append(make([]byte, 32), sig[32:]...),
		"s = n": append(append([]byte{}, sig[:32]...), nb...),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := Verify(p[0]+"."+p[1]+"."+jose.EncodeSegment(raw), pub, nil)
			wantErr(t, err, jose.ErrBadSignature)
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
	wantErr(t, err, jose.ErrBadSignature)
}

// The digest is over the received segments: re-encoding the same JSON payload
// differently breaks the signature.
func TestVerifyHashesReceivedBytes(t *testing.T) {
	s, pub := newP256Signer(t)
	p := strings.Split(mustSign(t, s, AlgES256, nil, `{"a": 1}`), ".")
	tampered := p[0] + "." + jose.EncodeSegment([]byte(`{"a":1}`)) + "." + p[2]
	_, _, err := Verify(tampered, pub, nil)
	wantErr(t, err, jose.ErrBadSignature)
}

func TestVerifyWrongKey(t *testing.T) {
	s, _ := newSecpSigner(t, false)
	_, other := newSecpSigner(t, false)
	_, _, err := Verify(mustSign(t, s, AlgES256K, nil, `{}`), other, nil)
	wantErr(t, err, jose.ErrBadSignature)
}

func TestVerifyRejectsBadKey(t *testing.T) {
	s, pub := newP256Signer(t)
	tok := mustSign(t, s, AlgES256, nil, `{}`)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	off := &ecdsa.PublicKey{Curve: pub.Curve, X: pub.X, Y: new(big.Int).Add(pub.Y, big.NewInt(1))}
	for name, key := range map[string]*ecdsa.PublicKey{"nil": nil, "P-384": &p384.PublicKey, "off curve": off} {
		t.Run(name, func(t *testing.T) {
			_, _, err := Verify(tok, key, nil)
			wantErr(t, err, jose.ErrBadKey)
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

// keyed adds Public to a Signer and counts the calls to Sign.
type keyed struct {
	Signer
	pub   *ecdsa.PublicKey
	calls int
}

func (k *keyed) Public() *ecdsa.PublicKey { return k.pub }

func (k *keyed) Sign(digest []byte) ([]byte, error) {
	k.calls++
	return k.Signer.Sign(digest)
}

// A 65-byte r||s||v only comes from a secp256k1 key: under ES256 it is
// refused, so a secp256k1 Vault key configured as ES256 fails at Sign.
func TestSignAccepts65BytesForES256KOnly(t *testing.T) {
	k1v, _ := newSecpSigner(t, true)
	_, err := Sign(k1v, AlgES256, nil, []byte(`{}`))
	wantErr(t, err, jose.ErrSignatureFormat)

	p256, _ := newP256Signer(t)
	padded := funcSigner(func(d []byte) ([]byte, error) {
		raw, err := p256.Sign(d)
		return append(raw, 0), err
	})
	_, err = Sign(padded, AlgES256, nil, []byte(`{}`))
	wantErr(t, err, jose.ErrSignatureFormat)
}

func TestSignKeyedSigner(t *testing.T) {
	p256, p256Pub := newP256Signer(t)
	k1, k1Pub := newSecpSigner(t, false)
	_, otherP256 := newP256Signer(t)

	t.Run("matching key", func(t *testing.T) {
		for _, tc := range []struct {
			s   *keyed
			alg string
		}{{&keyed{Signer: p256, pub: p256Pub}, AlgES256}, {&keyed{Signer: k1, pub: k1Pub}, AlgES256K}} {
			tok, err := Sign(tc.s, tc.alg, nil, []byte(`{}`))
			if err != nil {
				t.Fatalf("%s: %v", tc.alg, err)
			}
			if _, _, err := Verify(tok, tc.s.pub, nil); err != nil {
				t.Fatalf("%s: %v", tc.alg, err)
			}
		}
	})
	t.Run("key on the other curve is refused before signing", func(t *testing.T) {
		for _, tc := range []struct {
			s   *keyed
			alg string
		}{{&keyed{Signer: k1, pub: k1Pub}, AlgES256}, {&keyed{Signer: p256, pub: p256Pub}, AlgES256K}} {
			_, err := Sign(tc.s, tc.alg, nil, []byte(`{}`))
			wantErr(t, err, jose.ErrAlgKeyMismatch)
			if tc.s.calls != 0 {
				t.Fatalf("%s: signer called %d times, want 0", tc.alg, tc.s.calls)
			}
		}
	})
	t.Run("signature that does not verify with Public", func(t *testing.T) {
		_, err := Sign(&keyed{Signer: p256, pub: otherP256}, AlgES256, nil, []byte(`{}`))
		wantErr(t, err, jose.ErrSignatureFormat)
	})
	t.Run("nil Public skips the checks", func(t *testing.T) {
		if _, err := Sign(&keyed{Signer: p256}, AlgES256, nil, []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
	})
}

func TestNormalizeLowS(t *testing.T) {
	for name, curve := range map[string]elliptic.Curve{"P-256": elliptic.P256(), "secp256k1": secp256k1.S256()} {
		t.Run(name, func(t *testing.T) {
			n := curve.Params().N
			half := new(big.Int).Rsh(n, 1)
			for _, tc := range []struct{ in, want *big.Int }{
				{big.NewInt(1), big.NewInt(1)},
				{half, half},
				{new(big.Int).Add(half, big.NewInt(1)), new(big.Int).Sub(n, new(big.Int).Add(half, big.NewInt(1)))},
				{new(big.Int).Sub(n, big.NewInt(1)), big.NewInt(1)},
			} {
				in := new(big.Int).Set(tc.in)
				got := NormalizeLowS(curve, in)
				if got.Cmp(tc.want) != 0 {
					t.Fatalf("NormalizeLowS(%v) = %v, want %v", tc.in, got, tc.want)
				}
				if got == in {
					t.Fatalf("NormalizeLowS(%v) returned its input", tc.in)
				}
				got.SetInt64(42)
				if in.Cmp(tc.in) != 0 {
					t.Fatalf("changing the result changed the input")
				}
			}
		})
	}
}

func TestNormalizeLowSNilInputs(t *testing.T) {
	if NormalizeLowS(nil, big.NewInt(1)) != nil || NormalizeLowS(elliptic.P256(), nil) != nil {
		t.Fatal("NormalizeLowS with a nil argument must return nil")
	}
}

func TestInScalarRange(t *testing.T) {
	n := elliptic.P256().Params().N
	for _, tc := range []struct {
		v    *big.Int
		want bool
	}{
		{nil, false},
		{big.NewInt(0), false},
		{big.NewInt(1), true},
		{new(big.Int).Sub(n, big.NewInt(1)), true},
		{n, false},
	} {
		if got := inScalarRange(tc.v, n); got != tc.want {
			t.Fatalf("inScalarRange(%v) = %v, want %v", tc.v, got, tc.want)
		}
	}
	if inScalarRange(big.NewInt(1), nil) {
		t.Fatal("nil n must not be in range")
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
