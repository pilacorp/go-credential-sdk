// The HTTP(S) binding of DID Resolution §9.1.

package didresolver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/allowlist"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/safehttp"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/internal/uri"
	"github.com/pilacorp/go-credential-sdk/digitalcredential/issuerkey"
	"github.com/pilacorp/go-credential-sdk/jose"
)

// mediaTypes is sent as Accept and judges the response. application/did-resolution
// comes first, the form §9.1 asks for to get the metadata; the rest are the
// JSON forms of a document alone (§9.2.2, DID Core 1.0 §6), since a resolver
// may answer with one.
var mediaTypes = []string{
	"application/did-resolution",
	"application/did",
	"application/did+json",
	"application/did+ld+json",
	"application/ld+json",
	"application/json",
}

// limits of a request; §9.1 sets none, so every value is SDK policy. The zero
// allowlist.Redirects keeps redirects on the origin of the configured
// endpoint, which is the party the operator chose to trust.
var limits = safehttp.Limits{
	Timeout:      5 * time.Second,
	MaxRedirects: 3,
	MaxBytes:     1 << 20,
	Follow:       allowlist.Redirects{}.Follows,
}

// The causes of a failed request of a Resolver made with Config.URL. An error
// of Keys wraps one when it applies. Packages issuermeta and typemeta export
// the same values.
var (
	// ErrRedirectNotAllowed: a redirect leaves the origin of Config.URL.
	ErrRedirectNotAllowed = safehttp.ErrNotFollowed
	// ErrRedirectTargetNotAllowed: a redirect to a URL that is not https with
	// a host and no userinfo.
	ErrRedirectTargetNotAllowed = safehttp.ErrRedirectTargetNotAllowed
	// ErrTooManyRedirects: a request met more than 3 redirects.
	ErrTooManyRedirects = safehttp.ErrTooManyRedirects
	// ErrContentTypeNotAccepted: the response is not one of the JSON forms of
	// a resolution result or a DID document.
	ErrContentTypeNotAccepted = safehttp.ErrContentTypeNotAccepted
	// ErrBodyTooLarge: the body of the response is over 1 MiB.
	ErrBodyTooLarge = safehttp.ErrBodyTooLarge
	// ErrAddressBlocked: the default client refused an address that is not
	// globally reachable; a resolver on such an address needs
	// Config.HTTPClient.
	ErrAddressBlocked = safehttp.ErrBlockedAddress
)

// StatusError: the DID resolver answered with a status §9.1 gives no definite
// meaning here, held in Code. It is the same type as issuermeta.StatusError.
type StatusError = safehttp.StatusError

// httpResolver is the client of a DID resolver HTTP(S) endpoint.
type httpResolver struct {
	endpoint string // without a final "/"
	client   *http.Client
}

func newHTTPResolver(endpoint string, client *http.Client) (*httpResolver, error) {
	u, err := url.Parse(endpoint)
	if err != nil || !uri.Valid(endpoint) || !safehttp.HTTPSURL(u) || strings.ContainsAny(endpoint, "?#") {
		return nil, fmt.Errorf("%w: didresolver: Config.URL is not an https URL with a host and no userinfo, query or fragment (DID Resolution §9.1 requires TLS); a resolver reached another way goes in Config.Resolver", jose.ErrInvalidArgument)
	}
	if client == nil {
		client = safehttp.NewClient()
	}
	return &httpResolver{endpoint: strings.TrimRight(endpoint, "/"), client: client}, nil
}

// Resolve requests did from the endpoint and reads the status by the table of
// §9.1. PathEscape keeps ":" and turns "%" into "%25", so the resolver decodes
// back the exact DID, percent-encoding included.
func (h *httpResolver) Resolve(ctx context.Context, did string) ([]byte, error) {
	body, _, err := safehttp.Get(ctx, h.client, h.endpoint+"/"+url.PathEscape(did), mediaTypes, limits)
	if err == nil {
		return body, nil
	}
	var status *safehttp.StatusError
	if errors.As(err, &status) {
		switch status.Code {
		case http.StatusBadRequest, http.StatusNotImplemented:
			return nil, fmt.Errorf("%w: didresolver: the DID resolver refuses this DID or its method (status %d, DID Resolution §9.1)", issuerkey.ErrIssuerNotSupported, status.Code)
		case http.StatusNotFound:
			return nil, fault("the DID resolver found no such DID (status 404, DID Resolution §9.1)")
		case http.StatusGone:
			return nil, fault("the DID is deactivated (status 410, DID Resolution §9.1)")
		}
	}
	return nil, fmt.Errorf("didresolver: requesting the DID resolver: %w", err)
}
