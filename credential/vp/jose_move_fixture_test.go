package vp_test

import (
	"encoding/hex"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// A fixed secp256k1 key and its holder DID, so a presentation signed once on
// main 6e9fde1, before VP moved onto module jose (#152), stays verifiable.
const (
	fixture152VPKey = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
	fixture152VPDID = "did:example:fixture-152-holder"
)

func fixture152VP(t *testing.T) (signer.SignerProvider, vmpkg.ResolverProvider) {
	t.Helper()
	priv, err := ethcrypto.HexToECDSA(fixture152VPKey)
	if err != nil {
		t.Fatal(err)
	}
	prov, err := signer.NewDefaultProvider(fixture152VPKey)
	if err != nil {
		t.Fatal(err)
	}
	return prov, vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(fixture152VPDID,
		vmpkg.NewSecp256k1VM(fixture152VPDID, "key-1", hex.EncodeToString(ethcrypto.FromECDSAPub(&priv.PublicKey)))))
}

func fixture152VPContents() vp.PresentationContents {
	return vp.PresentationContents{
		Context: []interface{}{"https://www.w3.org/ns/credentials/v2"},
		ID:      "urn:uuid:fixture-152-vp",
		Types:   []string{"VerifiablePresentation"},
		Holder:  fixture152VPDID,
	}
}

// Signed on main 6e9fde1 with fixture152VPKey: a vp+jwt with its Hash() and a
// VP-JWT 1.1.
const (
	fixture152VPJOSE     = "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXhhbXBsZTpmaXh0dXJlLTE1Mi1ob2xkZXIja2V5LTEiLCJ0eXAiOiJ2cCtqd3QifQ.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiXSwiaG9sZGVyIjoiZGlkOmV4YW1wbGU6Zml4dHVyZS0xNTItaG9sZGVyIiwiaWF0IjoxNzk1ODYxOTQ5LCJpZCI6InVybjp1dWlkOmZpeHR1cmUtMTUyLXZwIiwidHlwZSI6IlZlcmlmaWFibGVQcmVzZW50YXRpb24ifQ.5j8LyefhhhfzwpA4e7RA6zkfPNnGsRFvUXRpXd65guZYqU_j4xYLwyEjJswnY2x6Xb7BBQuKd2CPKKNeDOdz2w"
	fixture152VPJOSEHash = "095fa5a5cb7dd87295ef0433a4f0ddc4a1e903248fcf41a73264fc35e8565dab"
	fixture152VPJWT      = "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXhhbXBsZTpmaXh0dXJlLTE1Mi1ob2xkZXIja2V5LTEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJkaWQ6ZXhhbXBsZTpmaXh0dXJlLTE1Mi1ob2xkZXIiLCJqdGkiOiJ1cm46dXVpZDpmaXh0dXJlLTE1Mi12cCIsInN1YiI6ImRpZDpleGFtcGxlOmZpeHR1cmUtMTUyLWhvbGRlciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiJdLCJob2xkZXIiOiJkaWQ6ZXhhbXBsZTpmaXh0dXJlLTE1Mi1ob2xkZXIiLCJpZCI6InVybjp1dWlkOmZpeHR1cmUtMTUyLXZwIiwidHlwZSI6IlZlcmlmaWFibGVQcmVzZW50YXRpb24ifX0.Xe47z0PbBw7QAyHptkD_xz_fOMv_71OO3ScIgCeEALUuYvOgLTq1zH9F9DXpNzWIyodCqD9ybcp-cS95dH2gkQ"
)

// Each presentation signed before the move parses, verifies and serializes to
// the same bytes, and the vp+jwt keeps its Hash().
func TestPresentationsSignedBeforeJoseMove_KeepBytesAndHash(t *testing.T) {
	_, resolver := fixture152VP(t)
	for name, token := range map[string]string{"vp+jwt": fixture152VPJOSE, "VP-JWT 1.1": fixture152VPJWT} {
		t.Run(name, func(t *testing.T) {
			p, err := vp.ParsePresentation([]byte(token), vp.WithResolver(resolver))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if err := p.Verify(vp.WithResolver(resolver)); err != nil {
				t.Fatalf("verify: %v", err)
			}
			s, err := p.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			if s != token {
				t.Fatalf("serialized bytes changed:\n got %v\nwant %s", s, token)
			}
			if j, ok := p.(*vp.JOSEPresentation); ok {
				if h, err := j.Hash(); err != nil || h != fixture152VPJOSEHash {
					t.Fatalf("Hash() = %s, %v, want %s", h, err, fixture152VPJOSEHash)
				}
			}
		})
	}
}

// ES256K signing is deterministic (RFC 6979), and a VP-JWT 1.1 carries no
// signing time, so issuing it again gives main's bytes.
func TestPresentationIssuanceAfterJoseMove_SameBytesAsBefore(t *testing.T) {
	prov, resolver := fixture152VP(t)
	p, err := vp.NewJWTPresentation(fixture152VPContents(), vp.WithVerificationMethodKey("key-1"), vp.WithResolver(resolver))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AddProofByProvider(prov, vp.WithResolver(resolver)); err != nil {
		t.Fatal(err)
	}
	if got, err := p.Serialize(); err != nil || got != fixture152VPJWT {
		t.Fatalf("issued token differs from main:\n got %v (%v)\nwant %s", got, err, fixture152VPJWT)
	}
}
