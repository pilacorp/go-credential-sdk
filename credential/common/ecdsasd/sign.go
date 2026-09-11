package ecdsasd

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	commoncrypto "github.com/pilacorp/go-credential-sdk/credential/common/crypto"
	"github.com/pilacorp/go-credential-sdk/credential/common/signer"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
)

// createBaseProof produces an ecdsa-sd-2023 base proof value for document.
// issuerSigner signs the base signature with the issuer's key: a P-256 key
// (standard, 64-byte R||S) or, as a non-standard extension, a secp256k1 key
// (65-byte R||S||V). The per-statement ephemeral keys are always P-256. The
// document body is left unchanged (no skolemization is persisted). Ports the
// ecdsa-sd-2023 createSignData + createBaseProofValue steps.
// issuerPub, when non-nil, is the key the verification method publishes; the
// base signature is checked against it.
func createBaseProof(document map[string]interface{}, proofConfig map[string]interface{}, mandatoryPointers []string, issuerSigner signer.SignerProvider, issuerPub *ecdsa.PublicKey) (string, error) {
	// 1. proofHash over the proof configuration.
	proofHash, err := hashProofConfig(proofConfig)
	if err != nil {
		return "", err
	}

	// 2. Random HMAC key to randomize blank-node labels per issuance.
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		return "", fmt.Errorf("ecdsasd: hmac key: %w", err)
	}

	// 3. Canonicalize + group by mandatory pointers.
	grouped, err := canonicalizeAndGroup(document, hmacKey, map[string][]string{"mandatory": mandatoryPointers})
	if err != nil {
		return "", err
	}
	mg := grouped.groups["mandatory"]
	nonMandatory := orderedValues(mg.nonMatching)

	// 4. mandatoryHash.
	mandatoryHash := hashMandatory(mg.matching)

	// 5. Generate an ephemeral P-256 key and sign each non-mandatory quad.
	eph, err := newEphemeralKey()
	if err != nil {
		return "", err
	}
	signatures := make([][]byte, len(nonMandatory))
	for i, nq := range nonMandatory {
		sig, err := eph.signStatement(nq)
		if err != nil {
			return "", err
		}
		signatures[i] = sig
	}
	ephPub, err := verificationmethod.PubToMultikeyBytes(&eph.priv.PublicKey)
	if err != nil {
		return "", err
	}

	// 6. baseSignature over proofHash || ephemeralPub || mandatoryHash.
	toSign := make([]byte, 0, len(proofHash)+len(ephPub)+len(mandatoryHash))
	toSign = append(toSign, proofHash...)
	toSign = append(toSign, ephPub...)
	toSign = append(toSign, mandatoryHash...)
	digest := sha256.Sum256(toSign)
	baseSig, err := issuerSigner.Sign(digest[:])
	if err != nil {
		return "", fmt.Errorf("ecdsasd: base signature: %w", err)
	}
	// Catch a signer bound to the wrong VM here, not at the verifier.
	if issuerPub != nil && !commoncrypto.VerifyECDSA(issuerPub, digest[:], baseSig) {
		return "", fmt.Errorf("ecdsasd: the base signature does not verify against the verification method; the signer does not hold that key")
	}

	// 7. Serialize base proof value.
	return serializeBaseProofValue(&specBaseProof{
		BaseSignature:     baseSig,
		PublicKey:         ephPub,
		HMACKey:           hmacKey,
		Signatures:        signatures,
		MandatoryPointers: mandatoryPointers,
	})
}

func orderedValues(m map[int]string) []string {
	idxs := sortedIndexes(m)
	out := make([]string, len(idxs))
	for i, k := range idxs {
		out[i] = m[k]
	}
	return out
}
