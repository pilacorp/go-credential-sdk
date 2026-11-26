package verificationmethod

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TC-05: HTTPResolver wraps 404 and 410 as ErrDIDNotFound; a non-404 failure
// (such as 500 or a refused connection) is not ErrDIDNotFound.

func TestHTTPResolver404ReturnsErrDIDNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()
	r := NewHTTPResolver(srv.URL, WithHTTPClient(srv.Client()))
	_, err := r.ResolveDocument(context.Background(), "did:example:missing")
	if !errors.Is(err, ErrDIDNotFound) {
		t.Errorf("404: err = %v; want ErrDIDNotFound", err)
	}
}

func TestHTTPResolver410ReturnsErrDIDNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusGone)
	}))
	defer srv.Close()
	r := NewHTTPResolver(srv.URL, WithHTTPClient(srv.Client()))
	_, err := r.ResolveDocument(context.Background(), "did:example:deactivated")
	if !errors.Is(err, ErrDIDNotFound) {
		t.Errorf("410: err = %v; want ErrDIDNotFound", err)
	}
}

func TestHTTPResolver500IsNotErrDIDNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()
	r := NewHTTPResolver(srv.URL, WithHTTPClient(srv.Client()))
	_, err := r.ResolveDocument(context.Background(), "did:example:123")
	if err == nil {
		t.Fatal("500: expected an error")
	}
	if errors.Is(err, ErrDIDNotFound) {
		t.Error("500: err should not be ErrDIDNotFound")
	}
}

func TestHTTPResolverConnectionRefusedIsNotErrDIDNotFound(t *testing.T) {
	// A server that is started and immediately closed gives a refused connection.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	r := NewHTTPResolver(url)
	_, err := r.ResolveDocument(context.Background(), "did:example:123")
	if err == nil {
		t.Fatal("connection refused: expected an error")
	}
	if errors.Is(err, ErrDIDNotFound) {
		t.Error("connection refused: err should not be ErrDIDNotFound")
	}
}
