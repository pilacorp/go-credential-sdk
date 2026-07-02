package bbs

import (
	"crypto/rand"
	"fmt"

	"github.com/pilacorp/go-credential-sdk/credential/common/sd"
)

func createBaseProof(document map[string]interface{}, proofConfig map[string]interface{}, mandatoryPointers []string, issuerSigner Signer) (string, error) {
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		return "", fmt.Errorf("bbs: hmac key: %w", err)
	}
	return createBaseProofWithHMACKey(document, proofConfig, mandatoryPointers, issuerSigner, hmacKey)
}

// createBaseProofWithHMACKey is the base-proof worker with an explicit HMAC key.
// createBaseProof supplies a random key; tests pass a fixed key to reproduce the
// deterministic specification test vectors.
func createBaseProofWithHMACKey(document map[string]interface{}, proofConfig map[string]interface{}, mandatoryPointers []string, issuerSigner Signer, hmacKey []byte) (string, error) {
	proofHash, err := sd.HashProofConfig(proofConfig, document["@context"])
	if err != nil {
		return "", err
	}

	grouped, err := sd.CanonicalizeAndGroup(document, hmacKey, map[string][]string{"mandatory": mandatoryPointers})
	if err != nil {
		return "", err
	}
	grouped = normalizeGroupedCanonLabels(grouped)
	mg := grouped.Groups["mandatory"]
	nonMandatory := sd.OrderedValues(mg.NonMatching)
	mandatoryHash := sd.HashMandatory(mg.Matching)

	header := append(append([]byte{}, proofHash...), mandatoryHash...)
	messages := make([][]byte, len(nonMandatory))
	for i, nq := range nonMandatory {
		messages[i] = []byte(nq)
	}

	sig, err := issuerSigner.Sign(header, messages)
	if err != nil {
		return "", fmt.Errorf("bbs: sign base proof: %w", err)
	}

	return serializeBaseProofValue(&baseProof{
		BBSSignature:      sig,
		BBSHeader:         header,
		PublicKey:         append([]byte{}, issuerSigner.PublicKey()...),
		HMACKey:           hmacKey,
		MandatoryPointers: mandatoryPointers,
	})
}
