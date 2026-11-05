package didresolver

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuerkey"
	"github.com/pilacorp/go-credential-sdk/jose"
)

const testDID = "did:example:123"

// resolverFunc is a DIDResolver of a test; one that must not be called fails it.
type resolverFunc func(ctx context.Context, did string) ([]byte, error)

func (f resolverFunc) Resolve(ctx context.Context, did string) ([]byte, error) { return f(ctx, did) }

func TestNewNeedsExactlyOneSource(t *testing.T) {
	r := resolverFunc(func(context.Context, string) ([]byte, error) { return nil, nil })
	for name, cfg := range map[string]Config{
		"neither": {},
		"both":    {URL: "https://resolver.example", Resolver: r},
	} {
		if _, err := New(cfg); !errors.Is(err, jose.ErrInvalidArgument) {
			t.Errorf("%s: err = %v; want jose.ErrInvalidArgument", name, err)
		}
	}
}

// DID Resolution §9.1: "All HTTPS bindings MUST use TLS".
func TestNewRefusesAnEndpointThatIsNotHTTPS(t *testing.T) {
	for _, u := range []string{
		"http://resolver.example",
		"https://",
		"https://user@resolver.example",
		"https://resolver.example?a=b",
		"https://resolver.example#f",
		"https://resolver.example/a b",
		"not a url",
	} {
		if _, err := New(Config{URL: u}); !errors.Is(err, jose.ErrInvalidArgument) {
			t.Errorf("%q: err = %v; want jose.ErrInvalidArgument", u, err)
		}
	}
}

func TestKeysRefusesWhatIsNotADIDBeforeAnyRequest(t *testing.T) {
	r, err := New(Config{Resolver: resolverFunc(func(context.Context, string) ([]byte, error) {
		t.Error("Resolve is not called for an iss that is not a DID")
		return nil, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	for _, iss := range []string{
		"",
		"https://issuer.example",
		"did:",
		"did:example",
		"did:example:",
		"did:Example:123",
		"did:example:a/b",
		"did:example:a?b",
		"did:example:a#b",
		"did:example:a:",
		"did:example:%2",
		"did:example:%zz",
		"DID:example:123",
	} {
		if _, err := r.Keys(context.Background(), iss); !errors.Is(err, issuerkey.ErrIssuerNotSupported) {
			t.Errorf("%q: err = %v; want ErrIssuerNotSupported", iss, err)
		}
	}
}

// The reader of the error has an https issuer and needs to know what to use.
func TestKeysSaysTheCredentialHasNoIss(t *testing.T) {
	r, err := New(Config{Resolver: resolverFunc(func(context.Context, string) ([]byte, error) { return nil, nil })})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Keys(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "has no iss") {
		t.Errorf("err = %v", err)
	}
}

func TestKeysNamesIssuermetaForAnHTTPSIssuer(t *testing.T) {
	r, _ := New(Config{URL: "https://resolver.example"})
	_, err := r.Keys(context.Background(), "https://issuer.example")
	if err == nil || !strings.Contains(err.Error(), "issuermeta.NewResolver") || !strings.Contains(err.Error(), "issuerkey.Multi") {
		t.Errorf("err = %v; want it to name issuermeta.NewResolver and issuerkey.Multi", err)
	}
}

func TestKeysGuardsItsWiring(t *testing.T) {
	var zero Resolver
	if _, err := zero.Keys(context.Background(), testDID); !errors.Is(err, jose.ErrInvalidArgument) {
		t.Errorf("zero Resolver: err = %v", err)
	}
	r, _ := New(Config{URL: "https://resolver.example"})
	//lint:ignore SA1012 the nil context is the case under test
	if _, err := r.Keys(nil, testDID); !errors.Is(err, jose.ErrInvalidArgument) { //nolint:staticcheck
		t.Errorf("nil ctx: err = %v", err)
	}
}

// Keys of the fixtures, written down rather than computed by the code under
// test. multikeyCID is a key from the examples of CID 1.0, hexReal and
// multikeyReal the pair of a live document; the coordinates were worked out
// apart from this package, by decoding base58 and solving the curve equation.
const (
	multikeyCID  = "zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv"
	multikeyCIDX = "8a0ac59a2d3086e8a12a78fd4773a6d52a0ca61ef6c1419e15a05bcc6dafce7b"
	multikeyCIDY = "79fb17e5bd74c7cca3cab8f89f2de919f2dc63b5dbcb52b382a39daa7b2b2483"

	multikeyReal  = "zDnaeU4G2ntJq9dKjL6T5qpK1wpfoBZcoSgTPhr7qB2cjtrMq"
	multikeyRealX = "35df2cece6e82ddd2508ace0c1c16e5336c3a2abee8fa7a8b72f0a8f72f17754"
	multikeyRealY = "6429b5459958315ec947062cc202e635cb2cbc0f99871b8ded53262a072e30ce"

	hexReal  = "0x02b35b116329ad5ce292030a63deac8a75428d0029325500aac957bfdb63273746"
	hexRealX = "b35b116329ad5ce292030a63deac8a75428d0029325500aac957bfdb63273746"
	hexRealY = "4442c01f55fcdac94f902f2092249e899cf995a9ac764cac045de45c3f403db8"

	// The generator of secp256k1, SEC 2 §2.4.1.
	secpGX = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	secpGY = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)

const hexType = "EcdsaSecp256k1VerificationKey2019"

var vmID = testDID + "#k"

func multikeyVM(extra ...any) map[string]any {
	vm := map[string]any{"id": vmID, "type": "Multikey", "controller": testDID, "publicKeyMultibase": multikeyCID}
	for i := 0; i+1 < len(extra); i += 2 {
		vm[extra[i].(string)] = extra[i+1]
	}
	return vm
}

func document(methods []any, assertion any) map[string]any {
	doc := map[string]any{"id": testDID}
	if methods != nil {
		doc["verificationMethod"] = methods
	}
	if assertion != nil {
		doc["assertionMethod"] = assertion
	}
	return doc
}

// keysOf runs Keys on the JSON of v at a fixed time.
func keysOf(t *testing.T, v any, now time.Time) ([]issuerkey.PublicKey, error) {
	t.Helper()
	body, ok := v.([]byte)
	if !ok {
		var err error
		if body, err = json.Marshal(v); err != nil {
			t.Fatal(err)
		}
	}
	r, err := New(Config{Resolver: resolverFunc(func(context.Context, string) ([]byte, error) { return body, nil })})
	if err != nil {
		t.Fatal(err)
	}
	r.now = func() time.Time { return now }
	return r.Keys(context.Background(), testDID)
}

func checkKey(t *testing.T, got crypto.PublicKey, curve elliptic.Curve, x, y string) {
	t.Helper()
	k, ok := got.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("key is %T", got)
	}
	wx, _ := new(big.Int).SetString(x, 16)
	wy, _ := new(big.Int).SetString(y, 16)
	if k.Curve.Params().Name != curve.Params().Name || k.X.Cmp(wx) != 0 || k.Y.Cmp(wy) != 0 {
		t.Errorf("key = %s %x %x; want %s %s %s", k.Curve.Params().Name, k.X, k.Y, curve.Params().Name, x, y)
	}
}

var now = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

// A document as a real resolver writes it: every material property present,
// the unused ones empty, and metadata embedded in the document.
func TestKeysReadsARealDocument(t *testing.T) {
	body := []byte(`{
		"@context": ["https://www.w3.org/ns/did/v1", "https://www.w3.org/ns/cid/v1"],
		"id": "did:example:123",
		"controller": "did:example:issuer",
		"didDocumentMetadata": {"type": "people"},
		"assertionMethod": ["did:example:123#key-1", "did:example:123#key-2"],
		"authentication": ["did:example:123#key-1", "did:example:123#key-2"],
		"verificationMethod": [
			{"id": "did:example:123#key-1", "type": "EcdsaSecp256k1VerificationKey2019",
			 "controller": "did:example:123", "publicKeyHex": "` + hexReal + `", "publicKeyMultibase": ""},
			{"id": "did:example:123#key-2", "type": "Multikey",
			 "controller": "did:example:123", "publicKeyHex": "", "publicKeyMultibase": "` + multikeyReal + `"}
		]}`)
	keys, err := keysOf(t, body, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].KID != "did:example:123#key-1" || keys[1].KID != "did:example:123#key-2" {
		t.Fatalf("keys = %+v", keys)
	}
	checkKey(t, keys[0].Public, secp256k1.S256(), hexRealX, hexRealY)
	checkKey(t, keys[1].Public, elliptic.P256(), multikeyRealX, multikeyRealY)
}

// DID Resolution §7: the same document wrapped in a result reads the same.
func TestKeysReadsAResolutionResult(t *testing.T) {
	keys, err := keysOf(t, map[string]any{
		"didDocument":           document([]any{multikeyVM()}, []any{vmID}),
		"didResolutionMetadata": map[string]any{"contentType": "application/did"},
		"didDocumentMetadata":   map[string]any{"deactivated": false},
	}, now)
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys = %+v, err = %v", keys, err)
	}
	checkKey(t, keys[0].Public, elliptic.P256(), multikeyCIDX, multikeyCIDY)
}

func TestKeysRefusesAnUnusableResolution(t *testing.T) {
	good := document([]any{multikeyVM()}, []any{vmID})
	withID := func(id any) map[string]any {
		d := document([]any{multikeyVM()}, []any{vmID})
		d["id"] = id
		return d
	}
	for name, v := range map[string]any{
		"not JSON":             []byte("<html>"),
		"not an object":        []byte("[]"),
		"duplicate member":     []byte(`{"id":"did:example:123","id":"did:example:123"}`),
		"null didDocument":     map[string]any{"didDocument": nil},
		"didDocument a string": map[string]any{"didDocument": "x"},
		"result with error": map[string]any{
			"didDocument":           good,
			"didResolutionMetadata": map[string]any{"error": map[string]any{"type": "https://www.w3.org/ns/did#NOT_FOUND"}},
		},
		"deactivated result": map[string]any{
			"didDocument":         good,
			"didDocumentMetadata": map[string]any{"deactivated": true},
		},
		"deactivated, metadata in the document": map[string]any{
			"id": testDID, "didDocumentMetadata": map[string]any{"deactivated": true},
			"verificationMethod": []any{multikeyVM()}, "assertionMethod": []any{vmID},
		},
		"no id":                     map[string]any{"assertionMethod": []any{}},
		"another id":                withID("did:example:124"),
		"id in another case":        withID("did:example:ABC"),
		"id not a string":           withID(1),
		"assertionMethod a string":  document([]any{multikeyVM()}, vmID),
		"assertionMethod a number":  document([]any{multikeyVM()}, []any{1}),
		"verificationMethod a map":  map[string]any{"id": testDID, "verificationMethod": map[string]any{}},
		"verificationMethod number": document([]any{1}, []any{vmID}),
		"one id defined twice":      document([]any{multikeyVM(), multikeyVM()}, []any{vmID}),
	} {
		if keys, err := keysOf(t, v, now); !errors.Is(err, issuerkey.ErrNoUsableKey) {
			t.Errorf("%s: keys = %+v, err = %v; want ErrNoUsableKey", name, keys, err)
		}
	}
}

// A result without a document names that, not a mismatch of ids.
func TestKeysSaysAResultHoldsNoDocument(t *testing.T) {
	_, err := keysOf(t, map[string]any{"didDocument": nil}, now)
	if err == nil || !strings.Contains(err.Error(), "holds no DID document") {
		t.Errorf("err = %v", err)
	}
}

// Which verification methods come back: CID §2.2, §2.3.2, §3.3.
func TestKeysReturnsOnlyAssertionMethods(t *testing.T) {
	past, future := now.Add(-time.Hour).Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339)
	other := "did:example:999"
	for name, tc := range map[string]struct {
		doc  map[string]any
		want []string
	}{
		"reference":             {document([]any{multikeyVM()}, []any{vmID}), []string{vmID}},
		"relative reference":    {document([]any{multikeyVM()}, []any{"#k"}), []string{vmID}},
		"relative method id":    {document([]any{multikeyVM("id", "#k")}, []any{vmID}), []string{vmID}},
		"embedded":              {document(nil, []any{multikeyVM()}), []string{vmID}},
		"referenced twice":      {document([]any{multikeyVM()}, []any{vmID, "#k"}), []string{vmID}},
		"no assertionMethod":    {document([]any{multikeyVM()}, nil), nil},
		"reference not defined": {document([]any{multikeyVM()}, []any{testDID + "#gone"}), nil},
		"another document":      {document([]any{multikeyVM("id", other+"#k")}, []any{other + "#k"}), nil},
		"embedded elsewhere":    {document(nil, []any{multikeyVM("id", other+"#k")}), nil},
		"no fragment":           {document(nil, []any{multikeyVM("id", testDID+"#")}), nil},
		"another controller":    {document([]any{multikeyVM("controller", other)}, []any{vmID}), nil},
		"no controller":         {document([]any{multikeyVM("controller", nil)}, []any{vmID}), nil},
		"revoked":               {document([]any{multikeyVM("revoked", past)}, []any{vmID}), nil},
		"revoked now":           {document([]any{multikeyVM("revoked", now.Format(time.RFC3339))}, []any{vmID}), nil},
		"revoked later":         {document([]any{multikeyVM("revoked", future)}, []any{vmID}), []string{vmID}},
		"expired":               {document([]any{multikeyVM("expires", past)}, []any{vmID}), nil},
		"expires now":           {document([]any{multikeyVM("expires", now.Format(time.RFC3339))}, []any{vmID}), nil},
		"expires later":         {document([]any{multikeyVM("expires", future)}, []any{vmID}), []string{vmID}},
		"revoked not a time":    {document([]any{multikeyVM("revoked", "soon")}, []any{vmID}), nil},
		"revoked empty":         {document([]any{multikeyVM("revoked", "")}, []any{vmID}), nil},
		"expires not a string":  {document([]any{multikeyVM("expires", 1)}, []any{vmID}), nil},
		"no material":           {document([]any{multikeyVM("publicKeyMultibase", "")}, []any{vmID}), nil},
		"two materials":         {document([]any{multikeyVM("publicKeyHex", hexReal, "type", hexType)}, []any{vmID}), nil},
		"multikey and JWK":      {document([]any{multikeyVM("publicKeyJwk", map[string]any{"kty": "EC"})}, []any{vmID}), nil},
		"bad key beside a good": {document([]any{multikeyVM("id", "#bad", "publicKeyMultibase", "x"), multikeyVM()}, []any{"#bad", "#k"}), []string{vmID}},
	} {
		keys, err := keysOf(t, tc.doc, now)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		var got []string
		for _, k := range keys {
			got = append(got, k.KID)
		}
		if fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%s: KIDs = %v; want %v", name, got, tc.want)
		}
	}
}

func TestKeysReadsKeyMaterial(t *testing.T) {
	const compressedG = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	jwkOf := func(crv, x, y string) map[string]any {
		return map[string]any{"kty": "EC", "crv": crv, "x": x, "y": y}
	}
	// RFC 7515 §A.3 gives this P-256 key.
	p256 := jwkOf("P-256", "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")
	vm := func(extra ...any) map[string]any {
		return multikeyVM(append([]any{"publicKeyMultibase", ""}, extra...)...)
	}
	for name, tc := range map[string]struct {
		vm    map[string]any
		curve elliptic.Curve
		x, y  string
	}{
		"hex compressed":   {vm("type", hexType, "publicKeyHex", compressedG), secp256k1.S256(), secpGX, secpGY},
		"hex with 0x":      {vm("type", hexType, "publicKeyHex", "0x"+compressedG), secp256k1.S256(), secpGX, secpGY},
		"hex uncompressed": {vm("type", hexType, "publicKeyHex", "04"+secpGX+secpGY), secp256k1.S256(), secpGX, secpGY},
		"JWK P-256": {vm("type", "JsonWebKey", "publicKeyJwk", p256), elliptic.P256(),
			"7fcdce2770f6c45d4183cbee6fdb4b7b580733357be9ef13bacf6e3c7bd15445",
			"c7f144cd1bbd9b7e872cdfedb9eeb9f4b3695d6ea90b24ad8a4623288588e5ad"},
		"bad hex":             {vm("type", hexType, "publicKeyHex", "zz"), nil, "", ""},
		"hex short":           {vm("type", hexType, "publicKeyHex", "02ab"), nil, "", ""},
		"hex hybrid prefix":   {vm("type", hexType, "publicKeyHex", "06"+secpGX+secpGY), nil, "", ""},
		"hex off the curve":   {vm("type", hexType, "publicKeyHex", "04"+secpGX+secpGX), nil, "", ""},
		"hex on another type": {vm("type", "Multikey", "publicKeyHex", compressedG), nil, "", ""},
		"JWK with d": {vm("type", "JsonWebKey", "publicKeyJwk", map[string]any{
			"kty": "EC", "crv": "P-256", "x": p256["x"], "y": p256["y"], "d": "AAAA"}), nil, "", ""},
		"JWK P-384":      {vm("type", "JsonWebKey", "publicKeyJwk", jwkOf("P-384", "AA", "AA")), nil, "", ""},
		"JWK not a map":  {vm("type", "JsonWebKey", "publicKeyJwk", "x"), nil, "", ""},
		"Ed25519 header": {vm("publicKeyMultibase", "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"), nil, "", ""},
		"not base58btc":  {vm("publicKeyMultibase", "u"+multikeyCID[1:]), nil, "", ""},
		"bad character":  {vm("publicKeyMultibase", "z0"+multikeyCID[2:]), nil, "", ""},
		"too long":       {vm("publicKeyMultibase", multikeyCID+"1"), nil, "", ""},
		"far too long":   {vm("publicKeyMultibase", "z"+strings.Repeat("2", 1<<16)), nil, "", ""},
		"too short":      {vm("publicKeyMultibase", "z2"), nil, "", ""},
		// The same point under header 0x8025 and 0x8124, then a bad SEC 1
		// prefix, then x = 1, which has no y on P-256.
		"header low byte":  {vm("publicKeyMultibase", "zDnbxujE5xXpsFuopUBoiErzmZrk4ch9znvmzCCyCxUQFRQqY"), nil, "", ""},
		"header high byte": {vm("publicKeyMultibase", "zDtNK7wgcGtG2AtSZMcDoTqpJgqYqhT3nGbFuzrRG5WgFVtZp"), nil, "", ""},
		"bad point prefix": {vm("publicKeyMultibase", "zDnafTQmwtAtVbvWdbEucYHuURo1b9Fhua4qyMGgcLVwJFUKU"), nil, "", ""},
		"off the curve":    {vm("publicKeyMultibase", "zDnaeQRy3dcKsKa1zmKtVKsTy3m2HYoQnFnfKuxD6HfSTQgYg"), nil, "", ""},
		"over 35 bytes":    {vm("publicKeyMultibase", "z"+strings.Repeat("z", 48)), nil, "", ""},
		// 2^280 + the key of multikeyCID: its low 35 bytes are a valid Multikey.
		"one bit over": {vm("publicKeyMultibase", "zfL7X2vkRH5HMzrbrKNYrkddfVa1phBcWNSXPt9R39ZJbGHAS"), nil, "", ""},
		// Read with "0" as digit -1, this is a point on the curve.
		"bad last character":    {vm("publicKeyMultibase", "zDnaeQRy3dcKsKa1zmKtVKsTy3m2HYoQnFnfKuxD6HfSTQgd0"), nil, "", ""},
		"hex odd length":        {vm("type", hexType, "publicKeyHex", compressedG+"a"), nil, "", ""},
		"JWK beside a Multikey": {vm("type", "JsonWebKey", "publicKeyJwk", p256, "publicKeyMultibase", multikeyCID), nil, "", ""},
	} {
		keys, err := keysOf(t, document([]any{tc.vm}, []any{vmID}), now)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if tc.curve == nil {
			if len(keys) != 0 {
				t.Errorf("%s: keys = %+v; want none", name, keys)
			}
			continue
		}
		if len(keys) != 1 {
			t.Errorf("%s: %d keys; want 1", name, len(keys))
			continue
		}
		checkKey(t, keys[0].Public, tc.curve, tc.x, tc.y)
	}
}

// server serves h over TLS and returns a Resolver for it. Its client is the
// test server's, as a deployment's own client would be.
func server(t *testing.T, h http.HandlerFunc) *Resolver {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	r, err := New(Config{URL: srv.URL + "/1.0/identifiers/", HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestHTTPBindingRequest(t *testing.T) {
	const did = "did:example:a%2Fb"
	var path, accept string
	r := server(t, func(w http.ResponseWriter, req *http.Request) {
		path, accept = req.URL.Path, req.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/did-resolution")
		fmt.Fprintf(w, `{"didDocument":{"id":%q}}`, did)
	})
	keys, err := r.Keys(context.Background(), did)
	if err != nil || len(keys) != 0 {
		t.Fatalf("keys = %+v, err = %v", keys, err)
	}
	// The server decodes once and must get the DID back byte for byte.
	if path != "/1.0/identifiers/"+did {
		t.Errorf("path = %q", path)
	}
	if !strings.HasPrefix(accept, "application/did-resolution") {
		t.Errorf("Accept = %q", accept)
	}
}

// DID Resolution §9.1, the table of status codes.
func TestHTTPBindingStatus(t *testing.T) {
	for status, want := range map[int]error{
		http.StatusBadRequest:          issuerkey.ErrIssuerNotSupported,
		http.StatusNotImplemented:      issuerkey.ErrIssuerNotSupported,
		http.StatusNotFound:            issuerkey.ErrNoUsableKey,
		http.StatusGone:                issuerkey.ErrNoUsableKey,
		http.StatusNotAcceptable:       nil,
		http.StatusInternalServerError: nil,
		http.StatusServiceUnavailable:  nil,
	} {
		r := server(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
		_, err := r.Keys(context.Background(), testDID)
		if want != nil {
			if !errors.Is(err, want) {
				t.Errorf("%d: err = %v; want %v", status, err, want)
			}
			continue
		}
		var se *StatusError
		if !errors.As(err, &se) || se.Code != status ||
			errors.Is(err, issuerkey.ErrNoUsableKey) || errors.Is(err, issuerkey.ErrIssuerNotSupported) {
			t.Errorf("%d: err = %v; want a StatusError alone, so a failure never reads as an answer", status, err)
		}
	}
}

func TestHTTPBindingRefusals(t *testing.T) {
	big := strings.Repeat(" ", 1<<20+1)
	hops := 0
	for name, tc := range map[string]struct {
		h    http.HandlerFunc
		want error
	}{
		"redirect off the origin": {func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "https://other.example/x")
			w.WriteHeader(http.StatusFound)
		}, ErrRedirectNotAllowed},
		"redirect to http": {func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "http://other.example/x")
			w.WriteHeader(http.StatusFound)
		}, ErrRedirectTargetNotAllowed},
		"redirect loop": {func(w http.ResponseWriter, req *http.Request) {
			hops++
			w.Header().Set("Location", req.URL.Path)
			w.WriteHeader(http.StatusFound)
		}, ErrTooManyRedirects},
		"HTML": {func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
		}, ErrContentTypeNotAccepted},
		"over 1 MiB": {func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, big)
		}, ErrBodyTooLarge},
	} {
		_, err := server(t, tc.h).Keys(context.Background(), testDID)
		if !errors.Is(err, tc.want) || errors.Is(err, issuerkey.ErrNoUsableKey) {
			t.Errorf("%s: err = %v; want %v", name, err, tc.want)
		}
	}
	if hops != 4 {
		t.Errorf("the redirect loop made %d requests; want the first and 3 redirects", hops)
	}
}

// The default client refuses a resolver on an address that is not globally
// reachable; the failure tells that from an answer.
func TestDefaultClientRefusesALocalAddress(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	r, err := New(Config{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Keys(context.Background(), testDID); !errors.Is(err, ErrAddressBlocked) {
		t.Errorf("err = %v; want ErrAddressBlocked", err)
	}
}

func TestKeysHonoursContext(t *testing.T) {
	r := server(t, func(http.ResponseWriter, *http.Request) {})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Keys(ctx, testDID); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v; want context.Canceled", err)
	}
}

// Errors of a DIDResolver of the caller's keep their meaning.
func TestKeysPassesOnTheErrorOfADIDResolver(t *testing.T) {
	cause := errors.New("store down")
	r, err := New(Config{Resolver: resolverFunc(func(context.Context, string) ([]byte, error) { return nil, cause })})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Keys(context.Background(), testDID); !errors.Is(err, cause) {
		t.Errorf("err = %v", err)
	}
}
