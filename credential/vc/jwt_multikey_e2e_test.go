package vc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/common/jwt"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

func jwtMultikeyContents(issuerDID string) vc.CredentialContents {
	return vc.CredentialContents{
		Context:   []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:        "urn:uuid:jwt-multikey-001",
		Types:     []string{"VerifiableCredential"},
		Issuer:    issuerDID,
		ValidFrom: time.Now().Add(-time.Hour),
		Subject: []vc.Subject{{
			ID:           "did:example:subject",
			CustomFields: map[string]interface{}{"name": "Nguyen Van A"},
		}},
	}
}

// jwtHeaderAlg reads the alg the credential actually wrote into its header.
func jwtHeaderAlg(t *testing.T, cred vc.Credential) string {
	t.Helper()
	serialized, err := cred.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	token, ok := serialized.(string)
	if !ok {
		t.Fatalf("serialized JWT credential is %T, want string", serialized)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	return header.Alg
}

// The JWT alg follows the key the verification method holds: secp256k1 signs
// ES256K, P-256 signs ES256, and both verify.
func TestJWT_MultiKey_IssueVerify(t *testing.T) {
	const secpPriv = "57600b3f2b7e1054094e14cd85c72a40dc74c4ee062bb381cea604b55ce56aec"

	p256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}

	cases := []struct {
		name     string
		did      string
		provider func(t *testing.T) signer.SignerProvider
		vm       vmpkg.VerificationMethodEntry
		wantAlg  string
	}{
		{
			name: "secp256k1/ES256K",
			did:  "did:example:jwt-secp",
			provider: func(t *testing.T) signer.SignerProvider {
				p, err := signer.NewDefaultProvider(secpPriv)
				if err != nil {
					t.Fatalf("secp provider: %v", err)
				}
				return p
			},
			vm:      vmpkg.NewSecp256k1VM("did:example:jwt-secp", "key-1", pubHex(t, secpPriv)),
			wantAlg: "ES256K",
		},
		{
			name: "P-256/ES256",
			did:  "did:example:jwt-p256",
			provider: func(t *testing.T) signer.SignerProvider {
				p, err := signer.NewP256Provider(p256Priv)
				if err != nil {
					t.Fatalf("p256 provider: %v", err)
				}
				return p
			},
			vm:      mustP256VM(t, "did:example:jwt-p256", "key-1", &p256Priv.PublicKey),
			wantAlg: "ES256",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(tc.did, tc.vm))

			cred, err := vc.NewJWTCredential(jwtMultikeyContents(tc.did),
				vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
			if err != nil {
				t.Fatalf("new jwt credential: %v", err)
			}
			if got := jwtHeaderAlg(t, cred); got != tc.wantAlg {
				t.Fatalf("header alg = %q, want %q", got, tc.wantAlg)
			}

			if err := cred.AddProofByProvider(tc.provider(t)); err != nil {
				t.Fatalf("add proof: %v", err)
			}
			if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
				t.Fatalf("verify: %v", err)
			}

			// The signed token must survive a serialize/parse round trip.
			serialized, err := cred.Serialize()
			if err != nil {
				t.Fatalf("serialize: %v", err)
			}
			parsed, err := vc.ParseJWTCredential(serialized.(string))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if err := parsed.Verify(vc.WithResolver(resolver)); err != nil {
				t.Fatalf("verify after parse: %v", err)
			}
			if got := parsed.ExtractField("credentialSubject.name"); got != "Nguyen Van A" {
				t.Errorf("name = %v, want %q", got, "Nguyen Van A")
			}
		})
	}
}

// A token whose alg does not match the verification method's key must not
// verify, otherwise alg and key could be mixed.
func TestJWT_AlgMustMatchVM(t *testing.T) {
	const did = "did:example:jwt-alg-mismatch"

	p256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	prov, err := signer.NewP256Provider(p256Priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}

	// Issue against a P-256 VM, so the header says ES256.
	p256Resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did,
		mustP256VM(t, did, "key-1", &p256Priv.PublicKey)))

	cred, err := vc.NewJWTCredential(jwtMultikeyContents(did),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(p256Resolver))
	if err != nil {
		t.Fatalf("new jwt credential: %v", err)
	}
	if err := cred.AddProofByProvider(prov); err != nil {
		t.Fatalf("add proof: %v", err)
	}

	// The verifier now resolves a secp256k1 VM for the same kid.
	const secpPriv = "57600b3f2b7e1054094e14cd85c72a40dc74c4ee062bb381cea604b55ce56aec"
	secpResolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did,
		vmpkg.NewSecp256k1VM(did, "key-1", pubHex(t, secpPriv))))

	err = cred.Verify(vc.WithResolver(secpResolver))
	if err == nil || !strings.Contains(err.Error(), "does not match verification method") {
		t.Fatalf("verify err = %v, want an alg/key mismatch error", err)
	}
}

// RSA has no JWT algorithm here, so issuance must refuse it rather than emit a
// token nobody can verify.
func TestJWT_RSAVerificationMethodRejected(t *testing.T) {
	const did = "did:example:jwt-rsa"

	rsaKey := genRSA(t)
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did,
		vmpkg.NewRSAVM(did, "key-1", &rsaKey.PublicKey)))

	_, err := vc.NewJWTCredential(jwtMultikeyContents(did),
		vc.WithVerificationMethodKey("key-1"), vc.WithResolver(resolver))
	if err == nil || !strings.Contains(err.Error(), "not supported for JWT") {
		t.Fatalf("new jwt credential err = %v, want an unsupported-key error", err)
	}
}

// dualCurveDID publishes key-1 as secp256k1 and key-2 as P-256. With no VM
// pinned, the latest one — key-2 — is the default.
func dualCurveDID(t *testing.T, did string) (vmpkg.ResolverProvider, signer.SignerProvider, signer.SignerProvider) {
	t.Helper()
	const secpPriv = "57600b3f2b7e1054094e14cd85c72a40dc74c4ee062bb381cea604b55ce56aec"
	p256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did,
		vmpkg.NewSecp256k1VM(did, "key-1", pubHex(t, secpPriv)),
		mustP256VM(t, did, "key-2", &p256Priv.PublicKey)))

	secpSigner, err := signer.NewDefaultProvider(secpPriv)
	if err != nil {
		t.Fatalf("secp provider: %v", err)
	}
	p256Signer, err := signer.NewP256Provider(p256Priv)
	if err != nil {
		t.Fatalf("p256 provider: %v", err)
	}
	return resolver, secpSigner, p256Signer
}

// A signer that does not hold the key the header names still produces a
// well-formed signature; it must be refused before it is attached, not
// discovered by the verifier. Every signing path is held to that: AddProof,
// AddProofByProvider, and AddCustomProof for a signature made outside the SDK.
// A secp256k1 signer returns r||s||v (65 bytes); JWS carries r||s, so an
// external one is trimmed exactly as the SDK's own signer trims it.
//
// Refusal alone could be the code agreeing with itself, so every refused case
// is also checked independently: the token that signature would have produced
// is assembled by hand and handed to the SDK's existing JWT verifier, which
// must reject it too.
func TestJWT_SignerMustHoldTheHeaderKey(t *testing.T) {
	const (
		did      = "did:example:jwt-dual"
		secpPriv = "57600b3f2b7e1054094e14cd85c72a40dc74c4ee062bb381cea604b55ce56aec"
	)
	resolver, secpSigner, p256Signer := dualCurveDID(t, did)

	cases := []struct {
		name   string
		pin    string
		signer signer.SignerProvider
		via    string // "provider", "addProof" (with secpPriv) or "custom"
		tamper bool   // the external signer signs other data than the signing input
		wantOK bool
	}{
		{name: "default key-2 (P-256), P-256 signer", signer: p256Signer, via: "provider", wantOK: true},
		{name: "default key-2 (P-256), secp256k1 signer", signer: secpSigner, via: "provider"},
		{name: "default key-2 (P-256), AddProof with a secp256k1 key", signer: secpSigner, via: "addProof"},
		{name: "pinned key-1 (secp256k1), secp256k1 signer", pin: "key-1", signer: secpSigner, via: "provider", wantOK: true},
		{name: "pinned key-1 (secp256k1), P-256 signer", pin: "key-1", signer: p256Signer, via: "provider"},
		{name: "custom: default key-2 (P-256), P-256 signature", signer: p256Signer, via: "custom", wantOK: true},
		{name: "custom: pinned key-1 (secp256k1), 65-byte secp256k1 signature", pin: "key-1", signer: secpSigner, via: "custom", wantOK: true},
		{name: "custom: default key-2 (P-256), secp256k1 signature", signer: secpSigner, via: "custom"},
		{name: "custom: pinned key-1 (secp256k1), P-256 signature", pin: "key-1", signer: p256Signer, via: "custom"},
		{name: "custom: right key, signed over other data", signer: p256Signer, via: "custom", tamper: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := []vc.CredentialOpt{vc.WithResolver(resolver)}
			if tc.pin != "" {
				opts = append(opts, vc.WithVerificationMethodKey(tc.pin))
			}
			cred, err := vc.NewJWTCredential(jwtMultikeyContents(did), opts...)
			if err != nil {
				t.Fatalf("new jwt credential: %v", err)
			}
			input, err := cred.GetSigningInput()
			if err != nil {
				t.Fatalf("signing input: %v", err)
			}
			signed := string(input)
			if tc.tamper {
				signed += "tampered"
			}
			external := signExternally(t, tc.signer, signed)

			switch tc.via {
			case "provider":
				err = cred.AddProofByProvider(tc.signer)
			case "addProof":
				err = cred.AddProof(secpPriv)
			case "custom":
				err = cred.AddCustomProof(&dto.Proof{Signature: external})
			}

			if tc.wantOK {
				if err != nil {
					t.Fatalf("sign: %v", err)
				}
				if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
					t.Fatalf("verify: %v", err)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), "does not verify against verification method") {
				t.Fatalf("sign err = %v, want a key mismatch error", err)
			}
			if _, err := cred.Hash(); err == nil {
				t.Fatal("a refused signature must not be attached")
			}
			if err := verifyByHand(resolver, string(input), external); err == nil {
				t.Fatal("the existing verifier accepts this token, so refusing it would be wrong")
			}
		})
	}
}

// signExternally signs data the way a caller outside the SDK does: SHA-256,
// then the raw signer output (65 bytes for secp256k1).
func signExternally(t *testing.T, s signer.SignerProvider, data string) []byte {
	t.Helper()
	digest := sha256.Sum256([]byte(data))
	sig, err := s.Sign(digest[:])
	if err != nil {
		t.Fatalf("external sign: %v", err)
	}
	return sig
}

// verifyByHand builds signingInput.signature (r||s) without the code under test
// and runs it through the JWT verifier.
func verifyByHand(resolver vmpkg.ResolverProvider, signingInput string, sig []byte) error {
	if len(sig) == 65 {
		sig = sig[:64]
	}
	return jwt.NewJWTVerifier(resolver).VerifyJWT(signingInput + "." + base64.RawURLEncoding.EncodeToString(sig))
}

// The mismatch error tells the caller to pass WithVerificationMethodKey to
// NewJWTCredential. Following it must produce a token that verifies; passing
// the option at signing time instead changes nothing, because the header's kid
// is fixed when the token is built.
func TestJWT_MismatchErrorHintWorks(t *testing.T) {
	const did = "did:example:jwt-hint"
	resolver, secpSigner, _ := dualCurveDID(t, did)

	cred, err := vc.NewJWTCredential(jwtMultikeyContents(did), vc.WithResolver(resolver))
	if err != nil {
		t.Fatalf("new jwt credential: %v", err)
	}
	err = cred.AddProofByProvider(secpSigner)
	if err == nil || !strings.Contains(err.Error(), "pass WithVerificationMethodKey to NewJWTCredential") {
		t.Fatalf("sign err = %v, want the mismatch error with its hint", err)
	}
	if err := cred.AddProofByProvider(secpSigner, vc.WithVerificationMethodKey("key-1")); err == nil {
		t.Fatal("the option at signing time must not change the header's kid")
	}

	cred, err = vc.NewJWTCredential(jwtMultikeyContents(did), vc.WithResolver(resolver),
		vc.WithVerificationMethodKey("key-1"))
	if err != nil {
		t.Fatalf("new jwt credential with the hinted option: %v", err)
	}
	if err := cred.AddProofByProvider(secpSigner); err != nil {
		t.Fatalf("sign after following the hint: %v", err)
	}
	if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("verify: %v", err)
	}
}
