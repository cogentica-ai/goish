package http_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The request LINE is the one part of an outbound HTTP request that a
// client writes verbatim and a server parses positionally, so what goes
// in it has to be the ESCAPED form of the URL and nothing else. Go
// builds it from url.URL.RequestURI(), which is EscapedPath plus the
// raw query — never the decoded Path.
//
// The difference shows up in three ways, and each is a different kind
// of wrong:
//
//   * "%2F" decoded back to "/" makes the server see a different
//     resource than the client asked for. That disagreement between
//     the two ends of a connection is what path confusion IS.
//   * A non-ASCII path sent raw is not a valid request target.
//   * A SPACE in the path ends the request target early, so the server
//     reads a malformed request line — the request does not fail
//     usefully, it fails as a closed connection.
//
// The echo server here reports r.RequestURI, which is the request line
// as RECEIVED, so this measures what crossed the socket rather than
// what the client meant.
func TestGoishRef(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s", r.RequestURI)
	}))
	defer srv.Close()

	for _, p := range []string{
		"/a%2Fb", "/%E2%98%83", "/a%20b", "/plain", "/a b",
		"/a+b", "/%2e%2e/x", "/x?q=1", "/x?q=a%20b", "/x?q=a+b",
		"/%00", "/%41", "/a%3Fb", "/a%23b", "/#frag", "/x?a=1#f",
		"/dir/", "//double", "/tr%61iling",
	} {
		u, perr := url.Parse(srv.URL + p)
		if perr != nil {
			fmt.Printf("parse %-14s -> err=%q\n", p, perr.Error())
			continue
		}
		fmt.Printf("parse %-14s -> Path=%-12q RawPath=%-12q Escaped=%-14q RequestURI=%q\n",
			p, u.Path, u.RawPath, u.EscapedPath(), u.RequestURI())
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			fmt.Printf("get   %-14s -> err=%s\n", p, trimAddr(err.Error(), srv.URL))
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		fmt.Printf("get   %-14s -> code=%d saw=%q\n", p, resp.StatusCode, string(body))
	}

	// A control character in the URL must be REFUSED, not written. A CR
	// or LF reaching the request line ends it early and everything
	// after is read as headers — request splitting from whatever built
	// the URL.
	for _, c := range []struct{ name, path string }{
		{"cr", "/a\rb"},
		{"lf", "/a\nb"},
		{"crlf-header", "/a\r\nX-Injected: yes\r\n"},
		{"nul", "/a\x00b"},
		{"del", "/a\x7fb"},
		{"tab", "/a\tb"},
	} {
		u, _ := url.Parse(srv.URL)
		u.Path = c.path
		req, rerr := http.NewRequest("GET", "http://x/", nil)
		if rerr != nil {
			fmt.Printf("ctl %-12s -> newreq-err=%q\n", c.name, rerr.Error())
			continue
		}
		req.URL = u
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			fmt.Printf("ctl %-12s -> err=%s\n", c.name, trimAddr(err.Error(), srv.URL))
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		fmt.Printf("ctl %-12s -> code=%d saw=%q\n", c.name, resp.StatusCode, string(body))
	}
}

// The server's address carries a random port, so it is replaced: the
// measurement is of the refusal, not of which port the kernel handed
// out.
func trimAddr(s, srvURL string) string {
	host := strings.TrimPrefix(srvURL, "http://")
	return strings.ReplaceAll(s, host, "ADDR")
}
