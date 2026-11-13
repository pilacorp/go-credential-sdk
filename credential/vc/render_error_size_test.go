package vc

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Values taken from a credential or a fetched document have no size limit,
// so an error quotes only their start. Each case puts 1 MiB in one value.
func TestRenderErrorsQuoteOnlyTheStartOfAValue(t *testing.T) {
	long := strings.Repeat("a", 1<<20)
	budget := 1 << 20
	cases := map[string]func() error{
		"id without a fetcher": func() error {
			_, err := RenderMethod{ID: "https://example.com/" + long}.Dereference(context.Background(), nil)
			return err
		},
		"fetched type differs": func() error {
			method := RenderMethod{ID: "https://example.com/m", Type: "SuiteRenderMethod", RenderSuite: "summary"}
			fetcher := summaryFetcher{data: []byte(`{"type":"` + long + `","renderSuite":"summary"}`)}
			_, err := method.Dereference(context.Background(), fetcher)
			return err
		},
		"accessMode": func() error {
			return (&OutputPreference{AccessMode: []string{long}}).validate()
		},
		"pointer segment not found": func() error {
			_, err := resolveJSONPointer(map[string]any{}, "/"+long)
			return err
		},
		"pointer array index": func() error {
			_, err := resolveJSONPointer(map[string]any{"l": []any{}}, "/l/"+long)
			return err
		},
		"pointer through a scalar": func() error {
			_, err := resolveJSONPointer(map[string]any{"s": "x"}, "/s/"+long)
			return err
		},
		"summary pointer resolves to null": func() error {
			_, err := resolveNode("/"+long, CredentialData{long: nil}, false, true, &budget)
			return err
		},
	}
	fetch := func(handler http.HandlerFunc) error {
		server := httptest.NewServer(handler)
		defer server.Close()
		_, err := HTTPFetcher{Client: server.Client(), MaxResponseSize: 64}.Fetch(context.Background(), TemplateReference{ID: server.URL})
		return err
	}
	cases["redirect to a long address"] = func() error {
		return fetch(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://127.0.0.1:1/"+long, http.StatusFound)
		})
	}
	cases["long data: id sent to the fetcher"] = func() error {
		_, err := HTTPFetcher{Client: http.DefaultClient, MaxResponseSize: 64}.Fetch(context.Background(), TemplateReference{ID: "data:," + long})
		return err
	}
	cases["long status reason"] = func() error {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = http.ReadRequest(bufio.NewReader(conn))
			_, _ = conn.Write([]byte("HTTP/1.1 500 " + long + "\r\nContent-Length: 0\r\n\r\n"))
		}()
		_, err = HTTPFetcher{Client: http.DefaultClient, MaxResponseSize: 64}.Fetch(context.Background(), TemplateReference{ID: "http://" + listener.Addr().String()})
		return err
	}
	cases["unknown multibyte summary template member"] = func() error {
		template := `{"name":"n","description":"d","fields":[],"` + strings.Repeat("中", 1<<18) + `":1}`
		return RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Embedded: &EmbeddedTemplate{MediaType: "application/json", Bytes: []byte(template)}}}.Validate()
	}
	cases["unknown summary template member"] = func() error {
		template := `{"name":"n","description":"d","fields":[],"` + long + `":1}`
		return RenderMethod{Type: "SuiteRenderMethod", RenderSuite: "summary", Template: &Template{Embedded: &EmbeddedTemplate{MediaType: "application/json", Bytes: []byte(template)}}}.Validate()
	}
	for name, run := range cases {
		err := run()
		if err == nil {
			t.Errorf("%s: error = nil, want an error", name)
			continue
		}
		if len(err.Error()) > 1024 {
			t.Errorf("%s: error is %d bytes, want at most 1024", name, len(err.Error()))
		}
	}
}
