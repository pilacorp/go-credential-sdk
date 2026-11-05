// Package didresolver resolves the keys of an issuer whose iss is a DID, by
// W3C DID Resolution v1.0 (Candidate Recommendation Draft, 3 November 2026).
// draft-ietf-oauth-sd-jwt-vc-19 §2.5 leaves key discovery beyond its own two
// mechanisms to "separate specifications or ecosystem regulations", and a
// Resolver is one such mechanism: an issuerkey.Resolver for the Verifier of
// package dc and for a statuslist.Checker. An https issuer, §4 of that draft,
// is read by package issuermeta; issuerkey.Multi joins the two.
//
// New takes the URL of a DID resolver, reached by the HTTP(S) binding of DID
// Resolution §9.1, or a DIDResolver for any other transport. Either way the
// document is read by the same rules: its id equal to the DID (DID Resolution
// §4), not deactivated (DID Resolution §4.3), and only the verification
// methods its assertionMethod lists (W3C Controlled Identifiers v1.0, CID,
// §2.3.2), each belonging to this document (CID §3.3) and accepted by
// DefaultAcceptKey or Config.AcceptKey.
//
// Every Keys makes one Resolve: nothing is cached, so a revocation is seen on
// the next call. A deployment that wants a cache puts it in a DIDResolver of
// its own or in Config.HTTPClient.
package didresolver

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuerkey"
	"github.com/pilacorp/go-credential-sdk/jose"
)

// DIDResolver performs DID resolution (DID Resolution §4) over a transport of
// the caller's. It may be called from several goroutines at once and should
// return when ctx is done.
type DIDResolver interface {
	// Resolve returns the JSON of the DID Resolution Result of did (DID Resolution §7), or
	// of its DID document alone. did is a conformant DID taken from a token
	// whose signature is not verified yet. Its errors are those of
	// issuerkey.Resolver: wrap ErrIssuerNotSupported for a DID this resolver
	// does not cover, ErrNoUsableKey for one that does not exist or is
	// deactivated, and return any other error, its cause wrapped with %w,
	// when the document could not be found out.
	Resolve(ctx context.Context, did string) ([]byte, error)
}

// Config configures New. Exactly one of URL and Resolver is set.
type Config struct {
	// URL is the DID resolver HTTP(S) endpoint of §9.1, such as
	// https://resolver.example/1.0/identifiers: the DID is appended to it. It
	// is https with a host, and no userinfo, query or fragment.
	URL string
	// Resolver resolves DIDs over a transport of the caller's, such as gRPC
	// or a plain-http service inside the deployment. It is trusted code.
	Resolver DIDResolver
	// HTTPClient, used only with URL, sends the requests; nil uses a client
	// that refuses addresses that are not globally reachable, so a resolver
	// inside the deployment's own network needs a client of the deployment.
	HTTPClient *http.Client
	// AcceptKey decides which keys of the document verify tokens, in place of
	// DefaultAcceptKey; nil uses DefaultAcceptKey. It is called once for each
	// method of assertionMethod that belongs to this document and holds a
	// key this SDK reads. A method whose revoked or expires time cannot be
	// read is dropped without a call. It is trusted code, called from several
	// goroutines at once.
	AcceptKey AcceptKeyFunc
}

// KeyInfo is what a DID document says about a verification method, as given
// to an AcceptKeyFunc.
type KeyInfo struct {
	// ID is the absolute URL of the verification method, the KID of its key.
	ID string
	// Revoked and Expires are the times the document gives, zero when it
	// gives none.
	Revoked, Expires time.Time
	// RevocationReason is the revocationReason the document gives, such as
	// "superseded" or "keyCompromise" (RFC 5280 §5.3.1), "" when it gives
	// none or not as a string. W3C CID defines no such property.
	RevocationReason string
	// At is the time Keys judges the method by.
	At time.Time
}

// AcceptKeyFunc reports whether a key of a DID document may verify tokens.
type AcceptKeyFunc func(KeyInfo) bool

// reasonKeyCompromise is the revocationReason of a key that leaked or may have.
const reasonKeyCompromise = "keyCompromise"

// DefaultAcceptKey is the rule of W3C CID with one exception. A key verifies
// until its revoked or expires time, and not at or after it (CID §2.2), but a
// key revoked for a stated reason other than keyCompromise verifies until it
// expires: its issuer retired it and did not lose it, and refusing it would
// end every credential it signed.
//
// The exception goes beyond CID, which expects no proof to verify at or after
// the revoked time. Keys does not see when a token was signed and compares no
// iat, which an issuer may conceal and the key's holder may write, so such a
// key also verifies tokens signed after it was revoked. A key revoked as
// keyCompromise, or with no reason, fails for every token, those signed before
// it was revoked included: without a reliable time of signing, CID §5.5.1
// leaves only the present moment to judge by. The reason is compared as
// written, so another spelling of keyCompromise counts as another reason.
//
// An AcceptKeyFunc of the caller's may decide otherwise. To apply CID with no
// exception, clear RevocationReason and call DefaultAcceptKey.
func DefaultAcceptKey(k KeyInfo) bool {
	if !k.Expires.IsZero() && !k.At.Before(k.Expires) {
		return false
	}
	if k.Revoked.IsZero() || k.At.Before(k.Revoked) {
		return true
	}
	return k.RevocationReason != "" && k.RevocationReason != reasonKeyCompromise
}

// Resolver returns the signing keys the DID document of an issuer lists.
// Construct it with New. It is safe for concurrent use.
type Resolver struct {
	did    DIDResolver
	now    func() time.Time
	accept AcceptKeyFunc
}

var _ issuerkey.Resolver = (*Resolver)(nil)

// New returns a Resolver for cfg. Neither or both of URL and Resolver, or a
// URL that is not https with a host and without userinfo, query or fragment,
// is jose.ErrInvalidArgument.
func New(cfg Config) (*Resolver, error) {
	if (cfg.URL == "") == (cfg.Resolver == nil) {
		return nil, fmt.Errorf("%w: didresolver: Config needs exactly one of URL, the endpoint of a DID resolver, and Resolver, a DIDResolver of your own", jose.ErrInvalidArgument)
	}
	did := cfg.Resolver
	if cfg.URL != "" {
		h, err := newHTTPResolver(cfg.URL, cfg.HTTPClient)
		if err != nil {
			return nil, err
		}
		did = h
	}
	accept := cfg.AcceptKey
	if accept == nil {
		accept = DefaultAcceptKey
	}
	return &Resolver{did: did, now: time.Now, accept: accept}, nil
}

// Keys returns the keys the DID document of iss lists under assertionMethod,
// each with the absolute URL of its verification method as KID. Its outcomes
// are those of issuerkey.Resolver:
//   - the keys, possibly none. A verification method is skipped when it does
//     not belong to this document, is not accepted by Config.AcceptKey
//     (DefaultAcceptKey: expired, or revoked as keyCompromise or with no
//     reason), or holds no single key this SDK reads:
//     Multikey on P-256, a JWK on P-256 or secp256k1, or publicKeyHex on
//     EcdsaSecp256k1VerificationKey2019, a type older than W3C Controlled
//     Identifiers;
//   - an error wrapping issuerkey.ErrIssuerNotSupported: before any request,
//     iss is not a conformant DID (DID Core 1.0 §3.1); or the DID resolver
//     refuses the DID or its method (400, 501);
//   - an error wrapping issuerkey.ErrNoUsableKey: the DID does not exist or
//     is deactivated (404, 410, DID Resolution §4.4), or its document is not valid;
//   - any other error: the document could not be found out, wrapping the
//     cause. With Config.URL that is a StatusError, ErrRedirectNotAllowed,
//     ErrRedirectTargetNotAllowed, ErrTooManyRedirects,
//     ErrContentTypeNotAccepted, ErrBodyTooLarge, ErrAddressBlocked, or an
//     error of the client, such as context.Canceled.
//
// Error texts quote no iss and nothing of the document.
func (r *Resolver) Keys(ctx context.Context, iss string) ([]issuerkey.PublicKey, error) {
	if r == nil || r.did == nil {
		return nil, fmt.Errorf("%w: didresolver: Resolver not made by New", jose.ErrInvalidArgument)
	}
	if ctx == nil {
		return nil, fmt.Errorf("%w: didresolver: nil context", jose.ErrInvalidArgument)
	}
	if iss == "" {
		return nil, fmt.Errorf("%w: didresolver: the credential has no iss, and this resolver reads only DIDs", issuerkey.ErrIssuerNotSupported)
	}
	if !strings.HasPrefix(iss, "did:") {
		return nil, fmt.Errorf("%w: didresolver: iss is not a DID, and this resolver reads only DIDs; an https issuer is read by issuermeta.NewResolver. To accept both kinds, join them with issuerkey.Multi", issuerkey.ErrIssuerNotSupported)
	}
	if !conformantDID(iss) {
		return nil, fmt.Errorf("%w: didresolver: iss starts with did: but is not a conformant DID (DID Core 1.0 §3.1); the issuer must fix it", issuerkey.ErrIssuerNotSupported)
	}
	body, err := r.did.Resolve(ctx, iss)
	if err != nil {
		return nil, err
	}
	doc, err := parseResolution(body, iss)
	if err != nil {
		return nil, err
	}
	return assertionKeys(doc, iss, r.now(), r.accept)
}

// conformantDID reports whether s matches the did rule of DID Core 1.0 §3.1.
// The rule leaves no "/", "?" or "#", so a DID stays one path segment of a
// request URL, and it is why Keys checks before any request (DID Resolution §4.4 step 1).
func conformantDID(s string) bool {
	method, id, ok := strings.Cut(strings.TrimPrefix(s, "did:"), ":")
	if !ok || method == "" || id == "" || id[len(id)-1] == ':' {
		return false
	}
	for i := 0; i < len(method); i++ {
		if c := method[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case isAlnum(c), c == '.', c == '-', c == '_', c == ':':
		case c == '%' && i+2 < len(id) && isHex(id[i+1]) && isHex(id[i+2]):
			i += 2
		default:
			return false
		}
	}
	return true
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// fault is the error of a resolution result or document that must not be
// used; the arguments are text of this package, never the document's.
func fault(format string, a ...any) error {
	return fmt.Errorf("%w: didresolver: "+format, append([]any{issuerkey.ErrNoUsableKey}, a...)...)
}
