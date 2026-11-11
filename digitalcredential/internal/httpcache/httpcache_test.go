package httpcache

import (
	"net/http"
	"testing"
	"time"
)

// RFC 9111 §5.2.2.4, §5.2.2.5, §4.1, §4.2.1, §4.2.3, §1.2.2, and a
// quoted-string argument that holds a max-age.
func TestFreshness(t *testing.T) {
	for _, c := range []struct {
		name               string
		cacheControl, vary string
		age                string
		want               time.Duration
	}{
		{"no-store", "max-age=600, no-store", "", "", 0},
		{"no-cache", "no-cache, max-age=600", "", "", 0},
		{"Vary not set by the caller", "max-age=600", "Accept, Cookie", "", 0},
		{"Age 100", "max-age=600", "", "100", 500 * time.Second},
		{"Age = max-age", "max-age=600", "", "600", 0},
		{"over 24 h", "max-age=9223372037", "", "", 24 * time.Hour},
		{"quoted max-age", `x-ext=", max-age=86400, "`, "", "", 0},
	} {
		h := http.Header{"Cache-Control": {c.cacheControl}}
		if c.vary != "" {
			h.Set("Vary", c.vary)
		}
		if c.age != "" {
			h.Set("Age", c.age)
		}
		if got := Freshness(h, 24*time.Hour); got != c.want {
			t.Errorf("%s: freshness = %v, want %v", c.name, got, c.want)
		}
	}
}
