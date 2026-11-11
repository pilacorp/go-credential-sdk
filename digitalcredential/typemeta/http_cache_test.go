package typemeta

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A document without integrity is cached for its max-age, at most 24 hours,
// so one its publisher changes is fetched again within a day.
func TestHTTPCacheAtMost24Hours(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=31536000")
		fmt.Fprintf(w, `{"vct":%q}`, "https://"+r.Host+r.URL.Path)
	}))
	defer srv.Close()
	res, err := NewHTTPResolver(Config{TrustedPublisherOrigins: []string{srv.URL + "/"}, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Unix(1_800_000_000, 0)
	now := start
	res.(*httpResolver).now = func() time.Time { return now }
	ref := Ref{VCT: srv.URL + "/t"}
	for _, at := range []time.Duration{0, 24*time.Hour - time.Second, 24 * time.Hour} {
		now = start.Add(at)
		if _, err := res.Metadata(context.Background(), ref); err != nil {
			t.Fatalf("Metadata at +%v: %v", at, err)
		}
	}
	if n := hits.Load(); n != 2 {
		t.Errorf("server got %d requests, want 2 (cached until +24h, fetched again at +24h)", n)
	}
}
