package vp_test

import (
	"testing"

	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// Signed by the SDK before ecdsa-rdfc-2019 moved to multibase proofValues
// (hex proofValue, secp256k1 key below). Pins the legacy verification path.
const legacyHexVP = `{
  "@context": [
    "https://www.w3.org/ns/credentials/v2"
  ],
  "holder": "did:example:legacy-holder",
  "id": "urn:uuid:9a8b7c6d-legacy-vp",
  "proof": {
    "created": "2026-09-14T08:51:57Z",
    "cryptosuite": "ecdsa-rdfc-2019",
    "proofPurpose": "authentication",
    "proofValue": "255945a9f6b7adf05d2261f2ae68f1fb11789fc86b22eb28bb72788b34fbbf07143054ca8eebb479cf706543be5d9e350b4833a1ddae1c91ef80c5b7d75c6ffe01",
    "type": "DataIntegrityProof",
    "verificationMethod": "did:example:legacy-holder#key-1"
  },
  "type": [
    "VerifiablePresentation"
  ],
  "verifiableCredential": [
    {
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://www.w3.org/ns/credentials/examples/v2"
      ],
      "credentialSubject": {
        "age": 30,
        "id": "did:example:legacy-subject",
        "name": "Alice"
      },
      "id": "urn:uuid:7f1e2c3d-legacy-vc",
      "issuer": "did:example:legacy-issuer",
      "proof": {
        "created": "2026-09-14T08:51:57Z",
        "cryptosuite": "ecdsa-rdfc-2019",
        "proofPurpose": "assertionMethod",
        "proofValue": "b95159fb2c2a5f9a5a04f23342eafb0aa66875a0c41b07c0d4f6bff3205a401f078c75299f88d6553cfdfce08050ca566736c23a47c6b575fef656e4f1ce768200",
        "type": "DataIntegrityProof",
        "verificationMethod": "did:example:legacy-issuer#key-1"
      },
      "type": [
        "VerifiableCredential",
        "ExampleDegreeCredential"
      ],
      "validFrom": "2025-01-01T00:00:00Z"
    }
  ]
}`

func TestVP_LegacyHexProofStillVerifies(t *testing.T) {
	const did = "did:example:legacy-holder"
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vmpkg.NewSecp256k1VM(did, "key-1",
		"04e962c45627a43f3bec0af18c6c780ddbacceb8275b5204d494bc2cc44dc96d9805e64ee5ffeb6d05ed37284636c7cf6bfbaaa0d131f950cecc43110ac5510cad")))

	pres, err := vp.ParseJSONPresentation([]byte(legacyHexVP))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := pres.Verify(vp.WithResolver(resolver)); err != nil {
		t.Fatalf("verify legacy hex presentation: %v", err)
	}
}
