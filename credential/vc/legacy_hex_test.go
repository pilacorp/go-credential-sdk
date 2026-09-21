package vc_test

import (
	"testing"

	vmpkg "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

// Signed by the SDK before ecdsa-rdfc-2019 moved to multibase proofValues
// (hex proofValue, secp256k1 key below). Pins the legacy verification path.
const legacyHexVC = `{
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
}`

func TestVC_LegacyHexProofStillVerifies(t *testing.T) {
	const did = "did:example:legacy-issuer"
	resolver := vmpkg.NewStaticResolver(vmpkg.NewDIDDocument(did, vmpkg.NewSecp256k1VM(did, "key-1",
		"04e962c45627a43f3bec0af18c6c780ddbacceb8275b5204d494bc2cc44dc96d9805e64ee5ffeb6d05ed37284636c7cf6bfbaaa0d131f950cecc43110ac5510cad")))

	cred, err := vc.ParseJSONCredential([]byte(legacyHexVC))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := cred.Verify(vc.WithResolver(resolver)); err != nil {
		t.Fatalf("verify legacy hex credential: %v", err)
	}
}
