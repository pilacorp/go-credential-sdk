package jsonmap

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// base64URLAlphabet is RFC 4648 § 5, in index order: the character at index i
// encodes the six-bit value i.
const base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// signedSecp256k1Proof returns a document and a proof over it, signed exactly
// the way AddEcdsaSecp256k1Proof signs, so a test can rewrite the proof and ask
// what the verifier does with it.
func signedSecp256k1Proof(t *testing.T) (JSONMap, *verificationmethod.DIDDocument, *dto.Proof) {
	t.Helper()

	const did = "did:example:secp-malleable"
	priv, err := ethcrypto.HexToECDSA("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	doc := verificationmethod.NewDIDDocument(did, verificationmethod.NewSecp256k1VM(
		did, "key-1", hex.EncodeToString(ethcrypto.CompressPubkey(&priv.PublicKey))))

	m := testCredential()
	if err := (&m).ensureSecp256k1SuiteContext(); err != nil {
		t.Fatalf("context: %v", err)
	}
	proof := &dto.Proof{
		Type:               EcdsaSecp256k1Signature2019,
		Created:            "2026-01-01T00:00:00Z",
		VerificationMethod: did + "#key-1",
		ProofPurpose:       "assertionMethod",
	}

	encHeader, err := encodeDetachedJWSHeader(algES256K)
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	signingInput, err := m.secp256k1SigningInput(proof, encHeader)
	if err != nil {
		t.Fatalf("signing input: %v", err)
	}
	digest := sha256.Sum256(signingInput)
	raw, err := ethcrypto.Sign(digest[:], priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	signature, err := joseSecp256k1Signature(raw)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	proof.JWS = encHeader + ".." + base64.RawURLEncoding.EncodeToString(signature)

	if ok, err := m.verifyEcdsaSecp256k1Proof(doc, proof); !ok || err != nil {
		t.Fatalf("the proof this test starts from does not verify: ok=%v err=%v", ok, err)
	}

	return m, doc, proof
}

// A credential must have one byte form, because Hash() covers the proof and
// that hash is a Merkle leaf. 64 bytes occupy 86 base64url characters — 516
// bits for 512 — so the final character carries four bits nobody signed, and
// all 16 values of those bits decode to the same signature. Strict() is what
// keeps one of them.
func TestSecp256k1Suite_RejectsNonCanonicalBase64(t *testing.T) {
	m, doc, proof := signedSecp256k1Proof(t)

	encHeader, encSig, ok := splitDetachedJWS(proof.JWS)
	if !ok {
		t.Fatal("split: malformed jws")
	}
	last := strings.IndexByte(base64URLAlphabet, encSig[len(encSig)-1])
	if last < 0 {
		t.Fatalf("last character %q is not base64url", encSig[len(encSig)-1])
	}
	// Flip only the four padding bits; the two meaningful bits stay put.
	mutated := encSig[:len(encSig)-1] + string(base64URLAlphabet[last^0x0F])

	original, err := base64.RawURLEncoding.DecodeString(encSig)
	if err != nil {
		t.Fatalf("decode original: %v", err)
	}
	same, err := base64.RawURLEncoding.DecodeString(mutated)
	if err != nil || !bytes.Equal(same, original) {
		t.Fatalf("the mutation changed the signature bytes, so it does not test malleability: err=%v", err)
	}

	proof.JWS = encHeader + ".." + mutated
	ok, err = m.verifyEcdsaSecp256k1Proof(doc, proof)
	if ok || err == nil {
		t.Fatalf("a second spelling of the same signature verified: ok=%v err=%v", ok, err)
	}
}

// The same rule one layer down: (r, s) and (r, n-s) are both valid ECDSA
// signatures over the same digest under the same key, and crypto/ecdsa accepts
// both. Two byte forms again, two hashes again — so the verifier keeps low-S
// only.
func TestSecp256k1Suite_RejectsHighS(t *testing.T) {
	m, doc, proof := signedSecp256k1Proof(t)

	encHeader, encSig, ok := splitDetachedJWS(proof.JWS)
	if !ok {
		t.Fatal("split: malformed jws")
	}
	signature, err := base64.RawURLEncoding.DecodeString(encSig)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	n := ethcrypto.S256().Params().N
	flipped := make([]byte, 64)
	copy(flipped[:32], signature[:32])
	new(big.Int).Sub(n, new(big.Int).SetBytes(signature[32:])).FillBytes(flipped[32:])
	if bytes.Equal(flipped, signature) {
		t.Fatal("n-s equals s; the fixture is not usable for this test")
	}

	// Without the guard this would be enough to pass: plain ECDSA says yes.
	vm, err := verificationmethod.FindVerificationMethod(doc, proof.VerificationMethod)
	if err != nil {
		t.Fatalf("vm: %v", err)
	}
	pub, err := verificationmethod.ECPubFromVM(vm)
	if err != nil {
		t.Fatalf("pub: %v", err)
	}
	signingInput, err := m.secp256k1SigningInput(proof, encHeader)
	if err != nil {
		t.Fatalf("signing input: %v", err)
	}
	digest := sha256.Sum256(signingInput)
	if !crypto.VerifyECDSA(pub, digest[:], flipped) {
		t.Fatal("plain ECDSA rejected (r, n-s); this test no longer tests malleability")
	}

	proof.JWS = encHeader + ".." + base64.RawURLEncoding.EncodeToString(flipped)
	ok, err = m.verifyEcdsaSecp256k1Proof(doc, proof)
	if ok || err == nil || !strings.Contains(err.Error(), "low-S") {
		t.Fatalf("the (r, n-s) form of the same signature was accepted: ok=%v err=%v", ok, err)
	}
}

// A valid signature is not a licence. The key below really did sign the
// document — the signature is untouched — but the DID document grants it
// authentication only, and this proof claims assertionMethod. This is the test
// that goes red if the strictPurposeCheck call is ever dropped from the
// secp256k1 verifier.
func TestSecp256k1Suite_RejectsVMWithoutTheClaimedPurpose(t *testing.T) {
	m, doc, proof := signedSecp256k1Proof(t)

	// Keep the key resolvable and keep it in authentication; take away only
	// the right to issue.
	doc.Authentication = doc.AssertionMethod
	doc.AssertionMethod = nil

	ok, err := m.verifyEcdsaSecp256k1Proof(doc, proof)
	if ok || err == nil || !strings.Contains(err.Error(), "is not granted purpose") {
		t.Fatalf("a login-only key issued a credential: ok=%v err=%v", ok, err)
	}
}

// The other half of the same guard: the key was revoked a month before this
// proof was created. proof.Created is left exactly as signed — moving it would
// break the signature and the test would stop at the wrong check.
func TestSecp256k1Suite_RejectsProofSignedAfterRevocation(t *testing.T) {
	m, doc, proof := signedSecp256k1Proof(t) // proof.Created = 2026-01-01

	revoked, err := time.Parse(time.RFC3339, "2025-12-01T00:00:00Z")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	doc.VerificationMethod[0].Revoked = &revoked
	doc.VerificationMethod[0].RevocationReason = verificationmethod.ReasonSuperseded

	ok, err := m.verifyEcdsaSecp256k1Proof(doc, proof)
	if ok || err == nil || !strings.Contains(err.Error(), "is not earlier") {
		t.Fatalf("a revoked key issued a credential: ok=%v err=%v", ok, err)
	}
}

// And the signer never writes the form the verifier refuses, whatever the
// provider hands back.
func TestJoseSecp256k1Signature_FoldsHighS(t *testing.T) {
	n := ethcrypto.S256().Params().N

	in := make([]byte, 64)
	in[31] = 1                                            // r = 1
	new(big.Int).Sub(n, big.NewInt(1)).FillBytes(in[32:]) // s = n-1, the highest there is

	out, err := joseSecp256k1Signature(in)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if !bytes.Equal(out[:32], in[:32]) {
		t.Fatalf("r changed: %x", out[:32])
	}
	if got := new(big.Int).SetBytes(out[32:]); got.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("s = %s, want 1 (= n-(n-1))", got)
	}
}

// The other direction of the same rule: a header carrying fields this SDK does
// not write is fine, as long as the signature covers it. Refusing those would
// make every proof from another implementation unverifiable here.
func TestSecp256k1Suite_AcceptsAHeaderWithExtraFields(t *testing.T) {
	const did = "did:example:secp-hdr"
	priv, err := ethcrypto.HexToECDSA("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	doc := verificationmethod.NewDIDDocument(did, verificationmethod.NewSecp256k1VM(
		did, "key-1", hex.EncodeToString(ethcrypto.CompressPubkey(&priv.PublicKey))))

	m := testCredential()
	if err := (&m).ensureSecp256k1SuiteContext(); err != nil {
		t.Fatalf("context: %v", err)
	}
	proof := &dto.Proof{
		Type:               EcdsaSecp256k1Signature2019,
		Created:            "2026-01-01T00:00:00Z",
		VerificationMethod: did + "#key-1",
		ProofPurpose:       "assertionMethod",
	}

	// A header with kid, the way another implementation might write it.
	headerJSON, err := json.Marshal(map[string]interface{}{
		"alg": algES256K, "b64": false, "crit": []string{"b64"}, "kid": did + "#key-1",
	})
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	encHeader := base64.RawURLEncoding.EncodeToString(headerJSON)

	signingInput, err := m.secp256k1SigningInput(proof, encHeader)
	if err != nil {
		t.Fatalf("signing input: %v", err)
	}
	digest := sha256.Sum256(signingInput)
	signature, err := ethcrypto.Sign(digest[:], priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	proof.JWS = encHeader + ".." + base64.RawURLEncoding.EncodeToString(signature[:64])

	ok, err := m.verifyEcdsaSecp256k1Proof(doc, proof)
	if err != nil || !ok {
		t.Fatalf("a correctly signed header with kid was refused: ok=%v err=%v", ok, err)
	}
}

// W3C serves the 1.1 context under two URLs and the embedded loader maps both to
// the same document, so both have to count as defining the suite. Miss the
// ".jsonld" one and the narrow context gets appended on top of 1.1's @protected
// terms: signing dies on a redefinition the caller did not cause and cannot fix,
// and the error tells them to rename a term of their own that is not involved.
func TestSecp256k1Suite_AcceptsJsonldSpellingOfTheV11Context(t *testing.T) {
	for _, ctx := range []string{
		credentialsV1Context,
		credentialsV1Context + ".jsonld",
	} {
		t.Run(ctx, func(t *testing.T) {
			m := testCredential()
			m["@context"] = []interface{}{ctx, map[string]interface{}{
				"age":  "https://schema.org/age",
				"name": "https://schema.org/name",
			}}

			if !m.definesSecp256k1Suite() {
				t.Fatalf("%s already defines the suite, but definesSecp256k1Suite said no", ctx)
			}
			if err := (&m).addSuiteContextWithoutChangingMeaning(); err != nil {
				t.Fatalf("a 1.1 document written as %s became unsignable: %v", ctx, err)
			}
			// Nothing was appended: the document already defined the suite.
			if got := len(m["@context"].([]interface{})); got != 2 {
				t.Fatalf("@context grew to %d entries, want 2 — a second definition was added", got)
			}
		})
	}
}

// credentialsV2Context is the VC 2.0 base context. It defines Data Integrity
// only, so a 2.0 document is the case where the suite context really is added.
const credentialsV2Context = "https://www.w3.org/ns/credentials/v2"

// benchCredential returns a document that canonicalizes under ctx: every term
// it uses is defined by the credentials base context.
func benchCredential(ctx interface{}) JSONMap {
	return JSONMap{
		"@context":          ctx,
		"id":                "urn:uuid:noop",
		"type":              []interface{}{"VerifiableCredential"},
		"issuer":            "did:example:issuer",
		"credentialSubject": map[string]interface{}{"id": "did:example:subject"},
	}
}

// When the suite is already defined, adding it is a no-op — and the digest pair
// that guards the addition has nothing to guard. This pins the no-op half: the
// document comes back byte-identical, in every @context shape and for every URL
// that counts as defining the suite, so the early return in
// addSuiteContextWithoutChangingMeaning cannot be hiding a rewrite.
func TestSecp256k1Suite_AddSuiteContextIsANoOpWhenAlreadyDefined(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  interface{}
	}{
		{"1.1 as a single string", credentialsV1Context},
		{"1.1 as an array", []interface{}{credentialsV1Context}},
		{"1.1 as []string", []string{credentialsV1Context}},
		{"1.1 spelled .jsonld", []interface{}{credentialsV1Context + ".jsonld"}},
		{"2.0 plus security/v2", []interface{}{credentialsV2Context, secp256k1SuiteContextAccepted}},
		{"2.0 plus the narrow suite context", []interface{}{credentialsV2Context, secp256k1SuiteContextNarrow}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := benchCredential(tc.ctx)
			before, err := json.Marshal(m)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			if err := (&m).addSuiteContextWithoutChangingMeaning(); err != nil {
				t.Fatalf("a document that already defines the suite was refused: %v", err)
			}

			after, err := json.Marshal(m)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !bytes.Equal(before, after) {
				t.Fatalf("document was rewritten:\n before %s\n after  %s", before, after)
			}
		})
	}
}

// The other half: skipping the digest pair does not let a document that cannot
// canonicalize through. It still fails — later, on the signing path, which
// reports the same underlying cause.
func TestSecp256k1Suite_UncanonicalizableDocumentStillFails(t *testing.T) {
	m := JSONMap{
		"@context":              []interface{}{credentialsV1Context},
		"id":                    "urn:uuid:broken",
		"type":                  []interface{}{"VerifiableCredential"},
		"issuer":                "did:example:issuer",
		"aTermNoContextDefines": "boom",
	}

	err := (&m).AddEcdsaSecp256k1Proof(&testSigner{sig: make([]byte, 64)},
		"did:example:issuer#key-1", "assertionMethod")
	if err == nil {
		t.Fatal("a document that cannot canonicalize was signed")
	}
	if !strings.Contains(err.Error(), "canonicalize") {
		t.Fatalf("err = %v, want one naming canonicalization", err)
	}
}

// Why the early return is there. Run with:
//
//	go test ./credential/common/jsonmap/ -run '^$' -bench AddSuiteContext
//
// AlreadyDefined returns on a string comparison; NeedsAppending canonicalizes
// twice, which is the check doing real work and must stay.
func BenchmarkAddSuiteContext_AlreadyDefined(b *testing.B) {
	for i := 0; i < b.N; i++ {
		m := benchCredential([]interface{}{credentialsV1Context})
		if err := (&m).addSuiteContextWithoutChangingMeaning(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAddSuiteContext_NeedsAppending(b *testing.B) {
	for i := 0; i < b.N; i++ {
		m := benchCredential([]interface{}{credentialsV2Context})
		if err := (&m).addSuiteContextWithoutChangingMeaning(); err != nil {
			b.Fatal(err)
		}
	}
}

// The @context arrives in every shape JSON-LD allows. Only the two the VC data
// model produces can be extended; the rest are refused rather than guessed at.
func TestEnsureSecp256k1SuiteContext_Shapes(t *testing.T) {
	const narrow = secp256k1SuiteContextNarrow

	for _, tc := range []struct {
		name    string
		ctx     interface{}
		want    []interface{}
		wantErr string
	}{
		{
			name: "single string becomes an array",
			ctx:  "https://www.w3.org/ns/credentials/v2",
			want: []interface{}{"https://www.w3.org/ns/credentials/v2", narrow},
		},
		{
			name: "array keeps its order and gets the suite last",
			ctx:  []interface{}{"https://www.w3.org/ns/credentials/v2", map[string]interface{}{"@vocab": "https://example.org/v#"}},
			want: []interface{}{"https://www.w3.org/ns/credentials/v2", map[string]interface{}{"@vocab": "https://example.org/v#"}, narrow},
		},
		{
			name: "a document already defining the suite is left alone",
			ctx:  []interface{}{"https://www.w3.org/ns/credentials/v2", narrow},
			want: []interface{}{"https://www.w3.org/ns/credentials/v2", narrow},
		},
		{
			name:    "no @context at all",
			ctx:     nil,
			wantErr: "has no @context",
		},
		{
			name:    "@context as an object",
			ctx:     map[string]interface{}{"@vocab": "https://example.org/v#"},
			wantErr: "unexpected type",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := JSONMap{"id": "urn:uuid:shape"}
			if tc.ctx != nil {
				m["@context"] = tc.ctx
			}
			err := (&m).ensureSecp256k1SuiteContext()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one mentioning %q", err, tc.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatalf("ensure: %v", err)
			}
			got, _ := m["@context"].([]interface{})
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("@context = %#v, want %#v", got, tc.want)
			}
		})
	}
}
