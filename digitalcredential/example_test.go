package dc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"time"

	dc "github.com/pilacorp/go-credential-sdk/digitalcredential"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuerkey"
	"github.com/pilacorp/go-credential-sdk/jose/jws"
	"github.com/pilacorp/go-credential-sdk/jose/sdjwt"
)

// issuerKeys serves the keys of one issuer. A Verifier usually takes them
// from where the issuer publishes them, through issuermeta.NewResolver or a
// resolver of its own.
type issuerKeys struct {
	iss  string
	keys []issuerkey.PublicKey
}

func (r issuerKeys) Keys(_ context.Context, iss string) ([]issuerkey.PublicKey, error) {
	if iss != r.iss {
		return nil, issuerkey.ErrIssuerNotSupported
	}
	return r.keys, nil
}

// The three roles of draft-ietf-oauth-sd-jwt-vc-19 in one run: the Issuer
// issues a credential with concealed claims bound to the Holder's key, the
// Holder discloses one claim with a Key Binding JWT, and the Verifier
// checks the presentation.
func Example() {
	ctx := context.Background()
	const (
		iss      = "https://issuer.example"
		verifier = "https://verifier.example"
		nonce    = "n-0S6_WzA2Mj" // fresh per transaction, from the Verifier
	)

	// Issuer. Keys are made in memory here; an issuer whose key stays in a
	// KMS or HSM signs through jws.DigestSigner instead.
	issuerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	issuerSigner, err := jws.PrivateKeySigner(issuerPriv)
	if err != nil {
		log.Fatal(err)
	}
	holderPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	cred, err := dc.Issue(ctx, dc.IssueRequest{
		Issuer:    iss,
		VCT:       "https://credentials.example/identity_credential",
		IssuedAt:  time.Now(),
		Expiry:    time.Now().AddDate(1, 0, 0),
		HolderKey: &holderPriv.PublicKey, // written as cnf.jwk
		Claims: map[string]any{
			"given_name":  "Erika",
			"family_name": "Mustermann",
			"birthdate":   "1963-08-12",
		},
		Disclose: []sdjwt.Path{{"given_name"}, {"family_name"}, {"birthdate"}},
	}, issuerkey.SigningKey{Signer: issuerSigner, Public: &issuerPriv.PublicKey, KID: "key-1"})
	if err != nil {
		log.Fatal(err)
	}
	issued := cred.Serialize() // sent to the Holder

	// Holder: keeps the credential, then discloses only given_name to the
	// Verifier, signing a Key Binding JWT with the key of cnf.jwk.
	held, err := dc.Parse(issued)
	if err != nil {
		log.Fatal(err)
	}
	holderSigner, err := jws.PrivateKeySigner(holderPriv)
	if err != nil {
		log.Fatal(err)
	}
	presentation, err := held.Present(ctx, dc.PresentRequest{
		Reveal: []sdjwt.Path{{"given_name"}},
		KeyBinding: &dc.KeyBinding{
			Signer:   holderSigner,
			Audience: verifier,
			Nonce:    nonce,
			IssuedAt: time.Now(),
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	sent := presentation.Serialize() // sent to the Verifier

	// Verifier.
	received, err := dc.Parse(sent)
	if err != nil {
		log.Fatal(err) // a *dc.Error
	}
	issuers := issuerKeys{iss: iss, keys: []issuerkey.PublicKey{{KID: "key-1", Public: &issuerPriv.PublicKey}}}
	res, err := received.Verify(ctx, issuers, dc.WithAudience(verifier), dc.WithNonce(nonce))
	var e *dc.Error
	switch {
	case errors.As(err, &e):
		log.Fatalf("rejected: %s", e.Code)
	case err != nil:
		log.Fatal(err) // dc.ErrPolicy, or ctx ended
	}
	_, familyName := res.Claims["family_name"]
	fmt.Println(res.Issuer, res.VCT)
	fmt.Println("key bound:", res.KeyBound)
	fmt.Println("given_name:", res.Claims["given_name"])
	fmt.Println("family_name disclosed:", familyName)
	// Output:
	// https://issuer.example https://credentials.example/identity_credential
	// key bound: true
	// given_name: Erika
	// family_name disclosed: false
}
