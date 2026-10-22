package sdjwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/pilacorp/go-credential-sdk/jose"
)

func wantErr(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("got error %v, want %v", err, target)
	}
}

func mustNoErr(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func readJSONFile(t testing.TB, name string) (map[string]any, []byte) {
	t.Helper()
	raw, err := os.ReadFile(name)
	mustNoErr(t, err)
	obj, err := jose.DecodeJSONObject(raw)
	mustNoErr(t, err)
	return obj, raw
}

// encodeDisclosure builds a disclosure string from raw JSON text, so tests
// control every byte.
func encodeDisclosure(jsonText string) string {
	return jose.EncodeSegment([]byte(jsonText))
}

func mustParse(t *testing.T, encoded ...string) []Disclosure {
	t.Helper()
	ds := make([]Disclosure, len(encoded))
	for i, e := range encoded {
		d, err := ParseDisclosure(e)
		if err != nil {
			t.Fatalf("ParseDisclosure(%q): %v", e, err)
		}
		ds[i] = d
	}
	return ds
}

func mustObject(t *testing.T, jsonText string) map[string]any {
	t.Helper()
	obj, err := jose.DecodeJSONObject([]byte(jsonText))
	mustNoErr(t, err)
	return obj
}

func assertJSONEqual(t *testing.T, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		g, _ := jose.EncodeJSON(got)
		w, _ := jose.EncodeJSON(want)
		t.Fatalf("got  %s\nwant %s", g, w)
	}
}

// pathFromJSON turns a decoded JSON array into a Path (json.Number → int).
func pathFromJSON(t testing.TB, v any) Path {
	t.Helper()
	var p Path
	for _, el := range v.([]any) {
		switch e := el.(type) {
		case string:
			p = append(p, e)
		case json.Number:
			i, err := e.Int64()
			mustNoErr(t, err)
			p = append(p, int(i))
		default:
			t.Fatalf("path element %T", el)
		}
	}
	return p
}

func fixedSalts(salts map[string]string) SaltProvider {
	return func(p Path) (string, error) {
		s, ok := salts[p.key()]
		if !ok {
			return "", fmt.Errorf("no salt for %s", p)
		}
		return s, nil
	}
}

// counterSalts hands out distinct salts in call order.
func counterSalts() SaltProvider {
	n := 0
	return func(Path) (string, error) {
		n++
		return fmt.Sprintf("salt-%03d", n), nil
	}
}

// pyEncoder encodes like Python's json.dumps with its defaults, which
// sd-jwt-python uses for disclosures: ", " and ": " separators, every
// character outside ' '..'~' escaped as \uXXXX (lowercase hex, surrogate
// pairs above U+FFFF), and object keys in insertion order. Go maps have no
// order, so keys are ordered by their first appearance in the test case's
// user_claims; _sd comes first, as sd-jwt-python inserts it first, and ...
// is always alone in its object.
type pyEncoder struct{ rank map[string]int }

func newPyEncoder(t testing.TB, file []byte) pyEncoder {
	t.Helper()
	rank := map[string]int{keySD: -1, keyEllipsis: -1}
	dec := json.NewDecoder(bytes.NewReader(file))
	var collect func() error
	collect = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch tok {
		case json.Delim('{'):
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return err
				}
				if _, ok := rank[k.(string)]; !ok {
					rank[k.(string)] = len(rank)
				}
				if err := collect(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
		case json.Delim('['):
			for dec.More() {
				if err := collect(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
		}
		return err
	}
	_, err := dec.Token() // {
	mustNoErr(t, err)
	for dec.More() {
		k, err := dec.Token()
		mustNoErr(t, err)
		if k != "user_claims" {
			var skip json.RawMessage
			mustNoErr(t, dec.Decode(&skip))
			continue
		}
		mustNoErr(t, collect())
	}
	return pyEncoder{rank: rank}
}

func (e pyEncoder) encode(v []any) ([]byte, error) {
	var b bytes.Buffer
	err := e.write(&b, v)
	return b.Bytes(), err
}

func (e pyEncoder) write(b *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		fmt.Fprint(b, t)
	case json.Number:
		b.WriteString(string(t))
	case string:
		writePyString(b, t)
	case []any:
		b.WriteByte('[')
		for i, el := range t {
			if i > 0 {
				b.WriteString(", ")
			}
			if err := e.write(b, el); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			if _, ok := e.rank[k]; !ok {
				return fmt.Errorf("pyEncoder: no order for key %q", k)
			}
			keys = append(keys, k)
		}
		slices.SortFunc(keys, func(a, b string) int { return e.rank[a] - e.rank[b] })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteString(", ")
			}
			writePyString(b, k)
			b.WriteString(": ")
			if err := e.write(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("pyEncoder: %T", v)
	}
	return nil
}

func writePyString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r >= ' ' && r <= '~':
			b.WriteRune(r)
		case r > 0xffff:
			r1, r2 := utf16.EncodeRune(r)
			fmt.Fprintf(b, "\\u%04x\\u%04x", r1, r2)
		default:
			fmt.Fprintf(b, "\\u%04x", r)
		}
	}
	b.WriteByte('"')
}

// pyVector is one ported sd-jwt-python test case (testdata/sd-jwt-python).
type pyVector struct {
	name        string
	userClaims  map[string]any
	paths       []Path
	salts       map[string]string
	disclosures []string
	payload     map[string]any
	presented   []string
	expected    map[string]any
	keyBinding  bool
	enc         pyEncoder
}

func loadPyVectors(t testing.TB) []pyVector {
	t.Helper()
	files, err := filepath.Glob("testdata/sd-jwt-python/*.json")
	mustNoErr(t, err)
	var out []pyVector
	for _, f := range files {
		if filepath.Base(f) == "settings.json" {
			continue
		}
		obj, raw := readJSONFile(t, f)
		v := pyVector{
			name:       strings.TrimSuffix(filepath.Base(f), ".json"),
			userClaims: obj["user_claims"].(map[string]any),
			salts:      map[string]string{},
			payload:    obj["payload"].(map[string]any),
			expected:   obj["expect_verified_user_claims"].(map[string]any),
			keyBinding: obj["key_binding"] == true,
			enc:        newPyEncoder(t, raw),
		}
		for _, c := range obj["conceal"].([]any) {
			c := c.(map[string]any)
			p := pathFromJSON(t, c["path"])
			v.paths = append(v.paths, p)
			v.salts[p.key()] = c["salt"].(string)
		}
		for _, d := range obj["disclosures"].([]any) {
			v.disclosures = append(v.disclosures, d.(string))
		}
		for _, d := range obj["presented"].([]any) {
			v.presented = append(v.presented, d.(string))
		}
		out = append(out, v)
	}
	if len(out) != 17 {
		t.Fatalf("%d sd-jwt-python vectors, want 17", len(out))
	}
	return out
}

// rfcExample is one example of RFC 9901 (testdata/rfc9901).
type rfcExample struct {
	name         string
	presentation string
	processed    map[string]any
	digests      [][2]string // digest, disclosure
}

func loadRFCExamples(t *testing.T) []rfcExample {
	t.Helper()
	var out []rfcExample
	for _, name := range []string{"section5", "a1", "a2", "a3", "a4"} {
		obj, _ := readJSONFile(t, filepath.Join("testdata", "rfc9901", name+".json"))
		ex := rfcExample{
			name:         name,
			presentation: obj["presentation"].(string),
			processed:    obj["processed_payload"].(map[string]any),
		}
		for _, p := range obj["digests"].([]any) {
			p := p.(map[string]any)
			ex.digests = append(ex.digests, [2]string{p["digest"].(string), p["disclosure"].(string)})
		}
		out = append(out, ex)
	}
	return out
}

// rfcIssuerKey is the key of RFC 9901 Appendix A.5, also the issuer key of
// sd-jwt-python's test settings.
func rfcIssuerKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	settings, _ := readJSONFile(t, "testdata/sd-jwt-python/settings.json")
	jwk := settings["issuer_key"].(map[string]any)
	key, err := jose.PublicKeyFromJWK(map[string]any{"kty": jwk["kty"], "crv": jwk["crv"], "x": jwk["x"], "y": jwk["y"]})
	mustNoErr(t, err)
	return key
}

// p256Signer signs in memory and returns r||s.
type p256Signer struct{ priv *ecdsa.PrivateKey }

func (s p256Signer) Sign(digest []byte) ([]byte, error) {
	r, sv, err := ecdsa.Sign(rand.Reader, s.priv, digest)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	sv.FillBytes(out[32:])
	return out, nil
}

// holderSigner is the holder key of sd-jwt-python's test settings, whose
// public part is the cnf.jwk of the RFC 9901 examples.
func holderSigner(t *testing.T) (p256Signer, *ecdsa.PublicKey) {
	t.Helper()
	settings, _ := readJSONFile(t, "testdata/sd-jwt-python/settings.json")
	jwk := settings["holder_key"].(map[string]any)
	coord := func(name string) *big.Int {
		b, err := jose.DecodeSegment(jwk[name].(string))
		mustNoErr(t, err)
		return new(big.Int).SetBytes(b)
	}
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: coord("x"), Y: coord("y")},
		D:         coord("d"),
	}
	return p256Signer{priv: priv}, &priv.PublicKey
}

func newP256Signer(t *testing.T) (p256Signer, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mustNoErr(t, err)
	return p256Signer{priv: priv}, &priv.PublicKey
}

// secpSigner signs with secp256k1 and answers r||s||v, as a Vault callback
// does.
type secpSigner struct{ priv *secp256k1.PrivateKey }

func (s secpSigner) Sign(digest []byte) ([]byte, error) {
	sig := decredecdsa.Sign(s.priv, digest)
	r, sv := sig.R(), sig.S()
	rb, sb := r.Bytes(), sv.Bytes()
	return append(append(rb[:], sb[:]...), 1), nil
}

func newSecpSigner(t *testing.T) (secpSigner, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	mustNoErr(t, err)
	return secpSigner{priv: priv}, priv.PubKey().ToECDSA()
}
