package vc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// fixture152Keys returns fixed keys and a resolver that publishes them under
// fixture152DID, so a token signed once stays verifiable in later runs.
func fixture152Keys(t *testing.T) (*signer.DefaultProvider, *signer.P256Provider, verificationmethod.ResolverProvider) {
	t.Helper()
	secpPriv, err := ethcrypto.HexToECDSA(testIssuerPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	secp, err := signer.NewDefaultProvider(testIssuerPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), []byte("fixture-152-p256-key-scalar-0001"))
	if err != nil {
		t.Fatal(err)
	}
	p256, err := signer.NewP256Provider(p)
	if err != nil {
		t.Fatal(err)
	}
	resolver := verificationmethod.NewStaticResolver(verificationmethod.NewDIDDocument(fixture152DID,
		verificationmethod.NewSecp256k1VM(fixture152DID, "key-1", hex.EncodeToString(ethcrypto.FromECDSAPub(&secpPriv.PublicKey))),
		mustP256VM(t, fixture152DID, "key-2", &p.PublicKey)))
	return secp, p256, resolver
}

const fixture152DID = "did:example:fixture-152"

func fixture152Contents() CredentialContents {
	return CredentialContents{
		Context:   []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:        "urn:uuid:fixture-152",
		Types:     []string{"VerifiableCredential"},
		Issuer:    fixture152DID,
		ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Subject: []Subject{{
			ID:           "did:example:subject",
			CustomFields: map[string]interface{}{"name": "Nguyen Van A", "degree": "BSc"},
		}},
	}
}

// fixture152Tokens were signed on main 6e9fde1, before VC and VP moved onto
// module jose (#152), with the keys of fixture152Keys. Each still parses and
// verifies, serializes to the same bytes, and keeps its Hash(), the anchor key
// in authen-service.
var fixture152Tokens = []struct{ name, token, hash string }{
	{"jwt-es256k",
		"eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXhhbXBsZTpmaXh0dXJlLTE1MiNrZXktMSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3NjcyMjU2MDAsImlzcyI6ImRpZDpleGFtcGxlOmZpeHR1cmUtMTUyIiwianRpIjoidXJuOnV1aWQ6Zml4dHVyZS0xNTIiLCJuYmYiOjE3NjcyMjU2MDAsInN1YiI6ImRpZDpleGFtcGxlOnN1YmplY3QiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiZGVncmVlIjoiQlNjIiwiaWQiOiJkaWQ6ZXhhbXBsZTpzdWJqZWN0IiwibmFtZSI6Ik5ndXllbiBWYW4gQSJ9LCJpZCI6InVybjp1dWlkOmZpeHR1cmUtMTUyIiwiaXNzdWVyIjoiZGlkOmV4YW1wbGU6Zml4dHVyZS0xNTIiLCJ0eXBlIjoiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJ2YWxpZEZyb20iOiIyMDI2LTAxLTAxVDAwOjAwOjAwWiJ9fQ.W5fUp-HFSki7fch-iKVjl7z9v2oLR3Z86865cIs4xS0T1CwMa6UBvVavYsbazzVnOC6PUUF4v8nySZ-R-iZL0g",
		"d4be3b7cb973873eb13a842639a7493476fb6a2574a765dcc69514e8215e37fb"},
	{"jose-es256k",
		"eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXhhbXBsZTpmaXh0dXJlLTE1MiNrZXktMSIsInR5cCI6InZjK2p3dCJ9.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiZGVncmVlIjoiQlNjIiwiaWQiOiJkaWQ6ZXhhbXBsZTpzdWJqZWN0IiwibmFtZSI6Ik5ndXllbiBWYW4gQSJ9LCJpYXQiOjE3OTUyNTI4MTUsImlkIjoidXJuOnV1aWQ6Zml4dHVyZS0xNTIiLCJpc3N1ZXIiOiJkaWQ6ZXhhbXBsZTpmaXh0dXJlLTE1MiIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInZhbGlkRnJvbSI6IjIwMjYtMDEtMDFUMDA6MDA6MDBaIn0.QMCcaz_vNehBaQNE9YNmv7zeNxa2WJVLNn1AuG6yDClZU7DOP_oAUVW2nX1xl18w7nICAHOeRxZBOu4N7gmjPA",
		"137bab8886709fe95c17696917da2c41e4cd18f24fe613ce74604766fa924780"},
	{"sdjwt-es256k",
		"eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXhhbXBsZTpmaXh0dXJlLTE1MiNrZXktMSIsInR5cCI6InZjK3NkLWp3dCJ9.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiXSwiX3NkX2FsZyI6InNoYS0yNTYiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJfc2QiOlsiZVhDV0l2OW9MLW9ISVVEdjVjdEZPVXB6RkFna2l4YnV5T2pxbWtkdE5lZyJdLCJkZWdyZWUiOiJCU2MiLCJpZCI6ImRpZDpleGFtcGxlOnN1YmplY3QifSwiaWF0IjoxNzk1MjUyODE1LCJpZCI6InVybjp1dWlkOmZpeHR1cmUtMTUyIiwiaXNzdWVyIjoiZGlkOmV4YW1wbGU6Zml4dHVyZS0xNTIiLCJ0eXBlIjoiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJ2YWxpZEZyb20iOiIyMDI2LTAxLTAxVDAwOjAwOjAwWiJ9.SKI0Vvwlh7zSbQsEajb7Leqphke1CgvUoc4F0jSmPqEsBZ5IUDgmaCcEXt5Hh0ohOYZC43lSGzMEAiFX7EvU5w~WyJHN3VjYzlRdU1nX0NqbnMzY0F5Q1pnIiwibmFtZSIsIk5ndXllbiBWYW4gQSJd~",
		"c8ba29fabeb3d387c83c1351cc78396b18f2328fcc54e367091fde51d8e9fd08"},
	{"jose-es256",
		"eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpleGFtcGxlOmZpeHR1cmUtMTUyI2tleS0yIiwidHlwIjoidmMrand0In0.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiZGVncmVlIjoiQlNjIiwiaWQiOiJkaWQ6ZXhhbXBsZTpzdWJqZWN0IiwibmFtZSI6Ik5ndXllbiBWYW4gQSJ9LCJpYXQiOjE3OTUyNTI4MTUsImlkIjoidXJuOnV1aWQ6Zml4dHVyZS0xNTIiLCJpc3N1ZXIiOiJkaWQ6ZXhhbXBsZTpmaXh0dXJlLTE1MiIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInZhbGlkRnJvbSI6IjIwMjYtMDEtMDFUMDA6MDA6MDBaIn0.esYRH5Qz3ElV0TXAVAL2ovovWbjmaZDIt8UwvJDiEelRu5eNE6m8owow2K9H8R-v3qHBO3ycTOpZxG9yqOo2fw",
		"1d9a9cc9112249713f04d60f3b6c1c274c47636d947e5244e82d7a81c4cf07ea"},
}

func TestTokensSignedBeforeJoseMove_KeepBytesAndHash(t *testing.T) {
	_, _, resolver := fixture152Keys(t)
	for _, fx := range fixture152Tokens {
		t.Run(fx.name, func(t *testing.T) {
			cred, err := ParseCredential([]byte(fx.token), WithResolver(resolver), WithVerifyProof())
			if err != nil {
				t.Fatalf("parse and verify: %v", err)
			}
			s, err := cred.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			if s != fx.token {
				t.Fatalf("serialized bytes changed:\n got %v\nwant %s", s, fx.token)
			}
			h, err := cred.Hash()
			if err != nil {
				t.Fatal(err)
			}
			if h != fx.hash {
				t.Fatalf("Hash() = %s, want %s", h, fx.hash)
			}
		})
	}
}

// ES256K signing is deterministic (RFC 6979), so signing the same contents
// with the same key gives the token main produced: issuance writes the same
// header, payload and signature after the move. A vc+jwt carries iat set to
// the signing time, so only the VC-JWT 1.1 token is compared byte for byte.
func TestIssuanceAfterJoseMove_SameBytesAsBefore(t *testing.T) {
	secp, _, resolver := fixture152Keys(t)
	var want string
	for _, fx := range fixture152Tokens {
		if fx.name == "jwt-es256k" {
			want = fx.token
		}
	}
	if want == "" {
		t.Fatal("fixture jwt-es256k is missing")
	}
	c, err := NewJWTCredential(fixture152Contents(), WithVerificationMethodKey("key-1"), WithResolver(resolver))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddProofByProvider(secp, WithResolver(resolver)); err != nil {
		t.Fatal(err)
	}
	got, err := c.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("issued token differs from main:\n got %v\nwant %s", got, want)
	}
}
