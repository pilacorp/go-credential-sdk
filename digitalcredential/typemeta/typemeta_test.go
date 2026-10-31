package typemeta_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/typemeta"
	"github.com/pilacorp/go-credential-sdk/jose"
	"github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

const vct42 = "https://betelgeuse.example.com/education_credential/v42"

// Digests of testdata/figure30.json, computed with
// openssl dgst -sha256|-sha384|-sha512 -binary testdata/figure30.json | base64.
const (
	fig30SHA256 = "sha256-0NNETsymXj4lLpt500run69TjKZK3Auh+Nzyo62cFy4="
	fig30SHA384 = "sha384-K6vzl4qlxvRC/WWssfa6CkEXTI9ZS7ABZXTqlcdJAKeoMQNGzbQz7pSFgHBIeusj"
	fig30SHA512 = "sha512-jkygk2dpt/Sw5MmrAZ7ekuWdfXspiSw1iMwIQ+KwrGrK6wFH1BZKCH2Aq4f5V+SbN77oj0vPbXN8q0OaIz0bcQ=="
	// Of the empty input: a digest that matches no document here.
	emptySHA256 = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
	emptySHA512 = "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="
)

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func load(t *testing.T, ref typemeta.Ref, docs ...string) (*typemeta.Metadata, error) {
	t.Helper()
	var bs [][]byte
	for _, d := range docs {
		bs = append(bs, []byte(d))
	}
	r, err := typemeta.Static(bs...)
	if err != nil {
		t.Fatal(err)
	}
	return typemeta.Load(context.Background(), r, ref)
}

// Figure 30 of draft-ietf-oauth-sd-jwt-vc-19 Appendix A.2, without extends,
// whose parent the draft does not give, checked against Figure 29.
func TestFigure30(t *testing.T) {
	doc := readFile(t, "testdata/figure30.json")
	r, err := typemeta.Static(doc)
	if err != nil {
		t.Fatal(err)
	}
	m, err := typemeta.Load(context.Background(), r, typemeta.Ref{VCT: vct42, Integrity: fig30SHA256})
	if err != nil {
		t.Fatal(err)
	}
	claims := m.Claims()
	if len(claims) != 7 {
		t.Fatalf("got %d claims, want 7", len(claims))
	}
	if c := claims[4]; fmt.Sprint(c.Path) != "[degrees <nil>]" || c.SD != "always" || c.Mandatory {
		t.Errorf("claims[4] = %+v", c)
	}
	if c := claims[0]; !c.Mandatory || c.SD != "always" || len(c.Display) != 2 || c.Display[1].Label != "Name" {
		t.Errorf("claims[0] = %+v", c)
	}
	if c := claims[2]; c.SVGID != "address_street_address" {
		t.Errorf("claims[2].SVGID = %q", c.SVGID)
	}
	d := m.Display()
	if len(d) != 2 || d[1].Locale != "de-DE" || d[0].Rendering.Simple.BackgroundColor != "#12107c" ||
		d[0].Rendering.SVGTemplates[0].Properties.Orientation != "landscape" {
		t.Errorf("display = %+v", d)
	}
	if got := m.Documents(); len(got) != 1 || !bytes.Equal(got[0], doc) {
		t.Error("Documents() is not the document as served")
	}
	enc, err := typemeta.ParseEncoded(doc)
	if err != nil {
		t.Fatal(err)
	}
	if enc.Integrity() != fig30SHA256 {
		t.Errorf("Integrity() = %s, want %s", enc.Integrity(), fig30SHA256)
	}

	payload, err := jose.DecodeJSONObject(readFile(t, "testdata/figure29.json"))
	if err != nil {
		t.Fatal(err)
	}
	disclose := []sdjwt.Path{{"name"}, {"address"}, {"address", "street_address"}}
	for i := range 3 {
		disclose = append(disclose, sdjwt.Path{"degrees", i}, sdjwt.Path{"degrees", i, "date_awarded"})
	}
	if err := m.ValidateIssuance(payload, disclose); err != nil {
		t.Errorf("ValidateIssuance: %v", err)
	}
	// field_of_study is sd: never.
	if err := m.ValidateIssuance(payload, append(disclose, sdjwt.Path{"degrees", 1, "field_of_study"})); !errors.Is(err, typemeta.ErrViolated) {
		t.Errorf("field_of_study disclosed: got %v, want ErrViolated", err)
	}
}

// W3C SRI §3.3.3 parsing and draft 19 §6 matching.
func TestCheckIntegrity(t *testing.T) {
	doc := readFile(t, "testdata/figure30.json")
	ok := []string{
		fig30SHA256,
		fig30SHA384,
		fig30SHA384 + "A " + fig30SHA384, // a digest that does not decode only fails to match
		"SHA256-" + strings.TrimPrefix(fig30SHA256, "sha256-"),
		emptySHA256 + " " + fig30SHA512,
		fig30SHA256 + "?opt",
		"md5-x " + fig30SHA256,
		"sha512-not*base64 " + fig30SHA256, // not hash-with-options, skipped
	}
	for _, s := range ok {
		if err := typemeta.CheckIntegrity(doc, s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	bad := []string{
		emptySHA512 + " " + fig30SHA256, // only the sha512 token counts
		"",
		"md5-x",
		strings.NewReplacer("+", "-", "/", "_").Replace(fig30SHA256), // base64url
		"\u017fha256-" + strings.TrimPrefix(fig30SHA256, "sha256-"),  // U+017F folds to s outside ASCII
		fig30SHA256 + "?\x01", // options are VCHAR
		fig30SHA256 + "?\u00e9",
		// One character past the digest does not decode; the 48 bytes
		// before it must not match, and the token still outranks sha256.
		fig30SHA384 + "A",
		fig30SHA384 + "A " + fig30SHA256,
	}
	for _, s := range bad {
		if err := typemeta.CheckIntegrity(doc, s); !errors.Is(err, typemeta.ErrInvalid) {
			t.Errorf("%q: got %v, want ErrInvalid", s, err)
		}
	}
}

func doc(vct, extra string) string {
	return fmt.Sprintf(`{"vct":%q%s}`, vct, extra)
}

func TestLoadRejects(t *testing.T) {
	a, b := "https://a.example/t", "https://b.example/t"
	child := func(extra string) string { return doc(a, `,"extends":"`+b+`"`+extra) }
	chain := []string{}
	for i := range 9 {
		chain = append(chain, doc(fmt.Sprintf("https://c.example/%d", i), fmt.Sprintf(`,"extends":"https://c.example/%d"`, i+1)))
	}
	chain[8] = doc("https://c.example/8", "")
	parentSD := doc(b, `,"claims":[{"path":["x"],"sd":"always","mandatory":true}]`)
	tests := []struct {
		name string
		ref  typemeta.Ref
		docs []string
		want error
	}{
		{"integrity", typemeta.Ref{VCT: a, Integrity: emptySHA256}, []string{doc(a, "")}, typemeta.ErrInvalid},
		{"md5 only", typemeta.Ref{VCT: a, Integrity: "md5-x"}, []string{doc(a, "")}, typemeta.ErrInvalid},
		{"cycle", typemeta.Ref{VCT: a}, []string{child(""), doc(b, `,"extends":"`+a+`"`)}, typemeta.ErrCycle},
		{"9 documents", typemeta.Ref{VCT: "https://c.example/0"}, chain, typemeta.ErrInvalid},
		{"parent missing", typemeta.Ref{VCT: a}, []string{child("")}, typemeta.ErrInvalid},
		{"not found", typemeta.Ref{VCT: b}, []string{doc(a, "")}, typemeta.ErrNotFound},
		{"sd always to allowed", typemeta.Ref{VCT: a}, []string{child(`,"claims":[{"path":["x"],"sd":"allowed"}]`), parentSD}, typemeta.ErrClaims},
		{"mandatory true to false", typemeta.Ref{VCT: a}, []string{child(`,"claims":[{"path":["x"],"mandatory":false}]`), parentSD}, typemeta.ErrClaims},
		{"svg template without properties", typemeta.Ref{VCT: a}, []string{doc(a, `,"display":[{"locale":"en","name":"n","rendering":{"svg_templates":[{"uri":"https://a.example/1.svg","properties":{"contrast":"high"}},{"uri":"https://a.example/2.svg"}]}}]`)}, typemeta.ErrInvalid},
		{"logo over http", typemeta.Ref{VCT: a}, []string{doc(a, `,"display":[{"locale":"en","name":"n","rendering":{"simple":{"logo":{"uri":"http://a.example/l.png"}}}}]`)}, typemeta.ErrInvalid},
		{"display locale", typemeta.Ref{VCT: a}, []string{doc(a, `,"display":[{"locale":"en_US","name":"n"}]`)}, typemeta.ErrInvalid},
		{"text_color", typemeta.Ref{VCT: a}, []string{doc(a, `,"display":[{"locale":"en","name":"n","rendering":{"simple":{"text_color":"white"}}}]`)}, typemeta.ErrInvalid},
		{"claim display locale", typemeta.Ref{VCT: a}, []string{doc(a, `,"claims":[{"path":["x"],"display":[{"locale":"en_US","label":"X"}]}]`)}, typemeta.ErrClaims},
		{"svg_id twice", typemeta.Ref{VCT: a}, []string{doc(a, `,"claims":[{"path":["x"],"svg_id":"s"},{"path":["y"],"svg_id":"s"}]`)}, typemeta.ErrClaims},
		// §5.4, §5.6: b repeats an svg_id it inherits from g; a overriding
		// the claim does not hide it.
		{"svg_id repeated by a middle level", typemeta.Ref{VCT: a}, []string{
			child(`,"claims":[{"path":["y"],"svg_id":"s3"}]`),
			doc(b, `,"extends":"https://g.example/t","claims":[{"path":["y"],"svg_id":"s1"}]`),
			doc("https://g.example/t", `,"claims":[{"path":["x"],"svg_id":"s1"},{"path":["y"],"svg_id":"s2"}]`),
		}, typemeta.ErrClaims},
		// Merging would hide the repeat: both claims override one path.
		{"svg_id twice on one inherited path", typemeta.Ref{VCT: a}, []string{
			child(`,"claims":[{"path":["x"],"svg_id":"d"},{"path":["x"],"svg_id":"d"}]`),
			doc(b, `,"claims":[{"path":["x"],"svg_id":"s1"}]`),
		}, typemeta.ErrClaims},
		{"claims null", typemeta.Ref{VCT: a}, []string{doc(a, `,"claims":null`)}, typemeta.ErrClaims},
		// The chain is processed before any claims are read (§5.7).
		{"claims null, parent missing", typemeta.Ref{VCT: a}, []string{child(`,"claims":null`)}, typemeta.ErrInvalid},
		{"extends#integrity empty", typemeta.Ref{VCT: a}, []string{child(`,"extends#integrity":""`), doc(b, "")}, typemeta.ErrInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(t, tt.ref, tt.docs...)
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
			if tt.want != typemeta.ErrNotFound && errors.Is(err, typemeta.ErrNotFound) {
				t.Fatalf("%v also wraps ErrNotFound", err)
			}
		})
	}
	for _, s := range []string{"en-US", "de-DE-1996", "x-private", "i-klingon"} {
		if _, err := load(t, typemeta.Ref{VCT: a}, doc(a, `,"display":[{"locale":"`+s+`","name":"n"}]`)); err != nil {
			t.Errorf("locale %s: %v", s, err)
		}
	}
	for _, s := range []string{"#FFF", "rgb(18, 16, 124)", "RGB(10%,0%,0%)"} {
		if _, err := load(t, typemeta.Ref{VCT: a}, doc(a, `,"display":[{"locale":"en","name":"n","rendering":{"simple":{"text_color":"`+s+`"}}}]`)); err != nil {
			t.Errorf("color %s: %v", s, err)
		}
	}
}

// A resolver that answers every vct with the same document.
type answer []byte

func (a answer) Metadata(context.Context, typemeta.Ref) ([]byte, error) { return a, nil }

func TestLoadVCTMismatch(t *testing.T) {
	_, err := typemeta.Load(context.Background(), answer(doc("https://a.example/u", "")), typemeta.Ref{VCT: "https://a.example/t"})
	if !errors.Is(err, typemeta.ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

func clear() *sdjwt.Node     { return &sdjwt.Node{Value: "v"} }
func disclosed() *sdjwt.Node { return &sdjwt.Node{Value: "v", Disclosed: true} }
func hidden() *sdjwt.Node    { return &sdjwt.Node{Hidden: true} }
func object(hiddenFields int, kv ...any) *sdjwt.Node {
	n := &sdjwt.Node{Value: map[string]any{}, Fields: map[string]*sdjwt.Node{}, HiddenFields: hiddenFields}
	for i := 0; i < len(kv); i += 2 {
		n.Fields[kv[i].(string)] = kv[i+1].(*sdjwt.Node)
	}
	return n
}
func array(elems ...*sdjwt.Node) *sdjwt.Node {
	return &sdjwt.Node{Value: []any{}, Elems: append([]*sdjwt.Node{}, elems...)}
}

// Claim metadata validation, draft 19 §5.6, on the payload as issued.
func TestValidateClaims(t *testing.T) {
	const a = "https://a.example/t"
	meta := func(claim string) *typemeta.Metadata {
		m, err := load(t, typemeta.Ref{VCT: a}, doc(a, `,"claims":[`+claim+`]`))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	degrees := `{"path":["degrees",null,"type"],"mandatory":true}`
	tests := []struct {
		name   string
		claim  string
		issued *sdjwt.Node
		all    bool
		ok     bool
	}{
		{"sd always in the clear", `{"path":["x"],"sd":"always"}`, object(0, "x", clear()), false, false},
		{"sd never disclosed", `{"path":["x"],"sd":"never"}`, object(0, "x", disclosed()), false, false},
		{"mandatory missing", `{"path":["x"],"mandatory":true}`, object(0), false, false},
		{"mandatory maybe hidden", `{"path":["x"],"mandatory":true}`, object(2), false, true},
		{"mandatory missing, all disclosures", `{"path":["x"],"mandatory":true}`, object(2), true, false},
		{"key in a string", `{"path":["x","y"]}`, object(0, "x", clear()), false, false},
		{"index as issued", `{"path":["n",1],"mandatory":true,"sd":"never"}`, object(0, "n", array(hidden(), clear())), false, true},
		{"index beyond the array", `{"path":["n",2],"mandatory":true}`, object(0, "n", array(clear(), clear())), false, false},
		{"hidden element is selectively disclosable", `{"path":["n",0],"sd":"always"}`, object(0, "n", array(hidden())), false, true},
		{"hidden element under sd never", `{"path":["n",0],"sd":"never"}`, object(0, "n", array(hidden())), false, false},
		{"decoy dropped, all disclosures", `{"path":["n",1],"mandatory":true}`, object(0, "n", array(hidden(), clear())), true, false},
		{"one degree lacks type", degrees, object(0, "degrees", array(object(0, "type", clear()), object(0))), false, false},
		{"no degrees", degrees, object(0, "degrees", array()), false, true},
		{"hidden degree", degrees, object(0, "degrees", array(object(0, "type", clear()), hidden())), false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := meta(tt.claim).ValidateClaims(tt.issued, typemeta.ValidateOptions{AllDisclosures: tt.all})
			if tt.ok && err != nil {
				t.Fatal(err)
			}
			if !tt.ok && !errors.Is(err, typemeta.ErrViolated) {
				t.Fatalf("got %v, want ErrViolated", err)
			}
		})
	}
	if err := (&typemeta.Metadata{}).ValidateClaims(object(0), typemeta.ValidateOptions{}); !errors.Is(err, jose.ErrInvalidArgument) {
		t.Errorf("zero Metadata: got %v", err)
	}
}

func TestHTTPResolver(t *testing.T) {
	good := []byte(doc("https://placeholder", ""))
	var requests atomic.Int32
	var served atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/t" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if served.Add(1) == 1 {
			w.Write(bytes.Replace(good, []byte("}"), []byte(` }`), 1)) // one byte off
			return
		}
		w.Write(good)
	}))
	defer srv.Close()
	vct := srv.URL + "/t"
	good = []byte(doc(vct, ""))
	r, err := typemeta.NewHTTPResolver(typemeta.Config{Allowed: []string{srv.URL + "/"}, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, v := range []string{"urn:example:t", "http" + strings.TrimPrefix(vct, "https"), "https://other.example/t", vct + "#f"} {
		if _, err := r.Metadata(ctx, typemeta.Ref{VCT: v}); !errors.Is(err, typemeta.ErrNotFound) {
			t.Errorf("%s: got %v, want ErrNotFound", v, err)
		}
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("%d requests for refused vcts", n)
	}
	if _, err := r.Metadata(ctx, typemeta.Ref{VCT: srv.URL + "/missing"}); !errors.Is(err, typemeta.ErrNotFound) {
		t.Errorf("404: got %v, want ErrNotFound", err)
	}
	ref := typemeta.Ref{VCT: vct, Integrity: typemeta.Integrity(good)}
	if _, err := typemeta.Load(ctx, r, ref); !errors.Is(err, typemeta.ErrInvalid) {
		t.Fatalf("first Load: got %v, want ErrInvalid", err)
	}
	for range 2 {
		if _, err := typemeta.Load(ctx, r, ref); err != nil {
			t.Fatalf("Load: %v", err)
		}
	}
	// The document that failed was not cached; the one that passed was.
	if n := served.Load(); n != 2 {
		t.Errorf("served %d times, want 2", n)
	}
	if _, err := typemeta.NewHTTPResolver(typemeta.Config{}); !errors.Is(err, jose.ErrInvalidArgument) {
		t.Errorf("empty Allowed: got %v", err)
	}
}

func TestEncodedAndStatic(t *testing.T) {
	const a = "https://a.example/t"
	ext := []byte(doc(a, `, "x_ext": {"k": 1}, "display":[{"locale":"en","name":"n","dir":"ltr"}]`))
	enc, err := typemeta.ParseEncoded(ext)
	if err != nil || !bytes.Equal(enc.Bytes(), ext) {
		t.Fatalf("ParseEncoded: %v", err)
	}
	r, err := typemeta.Static(enc.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	m, err := typemeta.Load(context.Background(), r, typemeta.Ref{VCT: a, Integrity: enc.Integrity()})
	if err != nil || !bytes.Equal(m.Documents()[0], ext) {
		t.Fatalf("Load: %v", err)
	}
	_, err = typemeta.Document{VCT: a, Claims: []typemeta.Claim{{Path: []any{"x"}, SVGID: "s"}, {Path: []any{"y"}, SVGID: "s"}}}.Encode()
	if !errors.Is(err, typemeta.ErrClaims) {
		t.Errorf("Encode with svg_id twice: got %v, want ErrClaims", err)
	}
	if _, err := typemeta.Static([]byte(doc(a, "")), []byte(doc(a, `,"name":"n"`))); !errors.Is(err, jose.ErrInvalidArgument) {
		t.Errorf("Static with one vct twice: got %v", err)
	}
}
