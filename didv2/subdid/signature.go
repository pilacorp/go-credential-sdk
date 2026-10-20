package subdid

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/pilacorp/go-credential-sdk/didv2/did"
	"github.com/pilacorp/go-credential-sdk/didv2/signer"
)

// rootConsentPrefix starts the message the root DID signs for a Sub-DID.
const rootConsentPrefix = "Sub-DID "

const (
	rootConsentKey  = "rootConsent"
	signatureLength = 65
)

var storedSignaturePattern = regexp.MustCompile(`^0x[0-9a-f]{130}$`)

var (
	// ErrConsentInvalid reports a root consent that is malformed or not signed by the root DID.
	ErrConsentInvalid = errors.New("subdid: root consent invalid")
	// ErrPossessionInvalid reports a Sub-DID signature that is malformed or not signed by the Sub-DID.
	ErrPossessionInvalid = errors.New("subdid: sub-DID signature invalid")
)

// normalizeSignature returns a copy of the 65-byte r ‖ s ‖ v signature with v
// in {27, 28}. It refuses another length, a v outside {0, 1, 27, 28} and a high s.
func normalizeSignature(sig []byte) ([]byte, error) {
	if len(sig) != signatureLength {
		return nil, fmt.Errorf("subdid: signature is %d bytes, want %d", len(sig), signatureLength)
	}

	out := append([]byte(nil), sig...)
	switch v := out[64]; v {
	case 0, 1:
		out[64] = v + 27
	case 27, 28:
	default:
		return nil, fmt.Errorf("subdid: signature v = %d, want 0, 1, 27 or 28", v)
	}

	halfN := new(big.Int).Rsh(crypto.S256().Params().N, 1)
	if new(big.Int).SetBytes(out[32:64]).Cmp(halfN) > 0 {
		return nil, errors.New("subdid: signature s is above n/2")
	}

	return out, nil
}

// rootConsentDigest returns the EIP-191 personal_sign digest of
// rootConsentPrefix + subDID.
func rootConsentDigest(subDID string) [32]byte {
	return [32]byte(accounts.TextHash([]byte(rootConsentPrefix + subDID)))
}

// signRootConsent signs the root consent for subDID with the root DID's
// primary key and returns it in the stored form.
func signRootConsent(subDID string, root signer.SignerProvider) ([]byte, error) {
	if err := checkDID(subDID); err != nil {
		return nil, fmt.Errorf("subdid: Sub-DID: %w", err)
	}
	if root == nil {
		return nil, errors.New("subdid: root signer is nil")
	}

	digest := rootConsentDigest(subDID)
	sig, err := root.Sign(digest[:])
	if err != nil {
		return nil, fmt.Errorf("subdid: sign root consent: %w", err)
	}

	sig, err = normalizeSignature(sig)
	if err != nil {
		return nil, fmt.Errorf("subdid: root signer: %w", err)
	}

	return sig, nil
}

// setRootConsent stores sig as didDocumentMetadata.rootConsent, replacing any
// value. It does not check the signer. Compute docHash after this call.
func setRootConsent(doc *did.DIDDocument, sig []byte) error {
	if doc == nil {
		return errors.New("subdid: document is nil")
	}

	normalized, err := normalizeSignature(sig)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrConsentInvalid, err)
	}

	if doc.DocumentMetadata == nil {
		doc.DocumentMetadata = make(map[string]any)
	}
	doc.DocumentMetadata[rootConsentKey] = "0x" + hex.EncodeToString(normalized)

	return nil
}

// getRootConsent returns the 65 bytes of didDocumentMetadata.rootConsent. It
// refuses a value not already in the stored form and does not check the signer.
func getRootConsent(doc *did.DIDDocument) ([]byte, error) {
	if doc == nil {
		return nil, fmt.Errorf("%w: document is nil", ErrConsentInvalid)
	}

	value, ok := doc.DocumentMetadata[rootConsentKey]
	if !ok {
		return nil, fmt.Errorf("%w: rootConsent is missing", ErrConsentInvalid)
	}
	s, ok := value.(string)
	if !ok || !storedSignaturePattern.MatchString(s) {
		return nil, fmt.Errorf("%w: rootConsent must be 0x followed by 130 lowercase hex characters", ErrConsentInvalid)
	}

	sig, err := hex.DecodeString(s[2:])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConsentInvalid, err)
	}
	if sig[64] != 27 && sig[64] != 28 {
		return nil, fmt.Errorf("%w: rootConsent v = %d, want 27 or 28", ErrConsentInvalid, sig[64])
	}
	if _, err := normalizeSignature(sig); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConsentInvalid, err)
	}

	return sig, nil
}

// VerifyRootConsent checks that subDoc's root consent was signed by the key
// whose address is the last segment of rootDID. It cannot see whether the root
// DID is deactivated.
func VerifyRootConsent(subDoc *did.DIDDocument, rootDID string) error {
	sig, err := getRootConsent(subDoc)
	if err != nil {
		return err
	}
	if err := checkDID(rootDID); err != nil {
		return fmt.Errorf("%w: root DID: %w", ErrConsentInvalid, err)
	}
	if err := checkDID(subDoc.Id); err != nil {
		return fmt.Errorf("%w: Sub-DID: %w", ErrConsentInvalid, err)
	}

	if err := checkSigner(rootConsentDigest(subDoc.Id), sig, didAddress(rootDID)); err != nil {
		return fmt.Errorf("%w: %w", ErrConsentInvalid, err)
	}

	return nil
}

// signatureDigest returns the EIP-191 personal_sign digest of the 32 raw
// bytes of docHash.
func signatureDigest(docHash [32]byte) [32]byte {
	return [32]byte(accounts.TextHash(docHash[:]))
}

// signDocument signs the docHash of doc with the Sub-DID's primary key and
// returns the signature in the stored form.
func signDocument(doc *did.DIDDocument, sub signer.SignerProvider) ([]byte, error) {
	if sub == nil {
		return nil, errors.New("subdid: Sub-DID signer is nil")
	}

	h, err := DocHash(doc)
	if err != nil {
		return nil, err
	}

	digest := signatureDigest(h)
	sig, err := sub.Sign(digest[:])
	if err != nil {
		return nil, fmt.Errorf("subdid: sign document: %w", err)
	}

	sig, err = normalizeSignature(sig)
	if err != nil {
		return nil, fmt.Errorf("subdid: Sub-DID signer: %w", err)
	}

	return sig, nil
}

// VerifyDocumentSignature checks that sig signs the docHash of doc with the key
// whose address is the last segment of doc.Id. v may be 0, 1, 27 or 28.
func VerifyDocumentSignature(doc *did.DIDDocument, sig []byte) error {
	normalized, err := normalizeSignature(sig)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPossessionInvalid, err)
	}
	if doc == nil {
		return fmt.Errorf("%w: document is nil", ErrPossessionInvalid)
	}

	h, err := DocHash(doc)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPossessionInvalid, err)
	}
	if err := checkSigner(signatureDigest(h), normalized, didAddress(doc.Id)); err != nil {
		return fmt.Errorf("%w: %w", ErrPossessionInvalid, err)
	}

	return nil
}

func checkSigner(digest [32]byte, storedSig []byte, address string) error {
	sig := append([]byte(nil), storedSig...)
	sig[64] -= 27

	pub, err := crypto.SigToPub(digest[:], sig)
	if err != nil {
		return fmt.Errorf("recover signer: %w", err)
	}

	recovered := strings.ToLower(crypto.PubkeyToAddress(*pub).Hex())
	if recovered != address {
		return fmt.Errorf("signed by %s, not by %s", recovered, address)
	}

	return nil
}
