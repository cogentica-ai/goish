package httputil

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"log"
	"net/url"
	"sort"
	"strings"
	"testing"
)

// ReverseProxy sits between a client and a backend, which makes every
// header it forwards a statement the backend will believe. Two of its
// rules are load-bearing for anything behind it:
//
//   * HOP-BY-HOP headers are stripped, and so is any header NAMED in
//     the client's own Connection header. That second half is the one
//     that matters: without it a client can name any header it likes
//     in Connection and have the proxy delete it — including the one
//     the proxy itself just set. It also means a client cannot smuggle
//     a Connection-listed header through to the backend.
//   * X-Forwarded-For is APPENDED to, not replaced. A backend that
//     trusts the whole list is trusting the client, because the client
//     controls every entry but the last. Pinning the exact shape says
//     which entry is the trustworthy one.
//
// The backend here echoes back precisely what it received, so the
// measurement is of what CROSSED the proxy rather than of what the
// proxy meant to send.
func TestGoishRef(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var keys []string
		for k := range r.Header {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%q", k, strings.Join(r.Header[k], "|")))
		}
		fmt.Fprintf(w, "method=%s uri=%q proto=%s host=%q hdr=[%s]",
			r.Method, r.RequestURI, r.Proto, r.Host, strings.Join(parts, " "))
	}))
	defer backend.Close()
	burl, _ := url.Parse(backend.URL)

	// The backend's host carries a random port, so it is replaced with
	// a placeholder: the measurement is of what the proxy FORWARDED,
	// not of which port the kernel handed out.
	norm := func(s string) string { return strings.ReplaceAll(s, burl.Host, "BACKEND") }
	quiet := log.New(io.Discard, "", 0)

	// Everything goes through NewSingleHostReverseProxy, Go's Director
	// path. Its X-Forwarded-For handling is the APPENDING one, which is
	// the interesting case: the client controls every entry but the
	// last, so only the last is worth believing.
	run := func(label string, target *url.URL, req *http.Request) {
		p := NewSingleHostReverseProxy(target)
		p.ErrorLog = quiet
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)
		fmt.Printf("%-28s code=%d %s\n", label, w.Code, norm(w.Body.String()))
	}

	mkreq := func(target string, hdrs ...string) *http.Request {
		r := httptest.NewRequest("GET", target, nil)
		r.RemoteAddr = "192.0.2.9:1234"
		for i := 0; i+1 < len(hdrs); i += 2 {
			r.Header.Add(hdrs[i], hdrs[i+1])
		}
		return r
	}

	// 1. Hop-by-hop stripping, including Connection-named headers.
	run("hop/plain", burl, mkreq("http://front/x"))
	run("hop/connection-close", burl, mkreq("http://front/x",
		"Connection", "close", "X-Keep", "yes"))
	run("hop/connection-names", burl, mkreq("http://front/x",
		"Connection", "X-Secret", "X-Secret", "sensitive", "X-Keep", "yes"))
	run("hop/connection-multi", burl, mkreq("http://front/x",
		"Connection", "X-A, X-B", "X-A", "1", "X-B", "2", "X-C", "3"))
	run("hop/connection-empty-item", burl, mkreq("http://front/x",
		"Connection", "X-A,,X-B", "X-A", "1", "X-B", "2"))
	run("hop/connection-spaces", burl, mkreq("http://front/x",
		"Connection", "  X-A  ", "X-A", "1"))
	run("hop/all-hop-headers", burl, mkreq("http://front/x",
		"Keep-Alive", "timeout=5", "Proxy-Connection", "keep-alive",
		"Proxy-Authenticate", "Basic", "Proxy-Authorization", "Basic x",
		"Te", "trailers", "Trailer", "X-T", "Upgrade", "websocket",
		"X-Survives", "yes"))
	run("hop/te-not-trailers", burl, mkreq("http://front/x",
		"Te", "gzip", "X-Keep", "yes"))
	run("hop/connection-names-xff", burl, mkreq("http://front/x",
		"Connection", "X-Forwarded-For", "X-Forwarded-For", "1.2.3.4"))

	// 2. X-Forwarded-For: APPENDED to, never replaced. A backend that
	//    trusts the whole list is trusting the client, because every
	//    entry but the last is client-supplied.
	run("xff/absent", burl, mkreq("http://front/x"))
	run("xff/present", burl, mkreq("http://front/x",
		"X-Forwarded-For", "1.2.3.4"))
	run("xff/chain", burl, mkreq("http://front/x",
		"X-Forwarded-For", "1.2.3.4, 5.6.7.8"))
	run("xff/multi-header", burl, mkreq("http://front/x",
		"X-Forwarded-For", "1.2.3.4", "X-Forwarded-For", "5.6.7.8"))
	run("xff/spoofed-private", burl, mkreq("http://front/x",
		"X-Forwarded-For", "127.0.0.1"))
	run("xff/client-sets-proto", burl, mkreq("http://front/x",
		"X-Forwarded-Proto", "https", "X-Forwarded-Host", "evil.example"))
	run("xff/connection-names-xff", burl, mkreq("http://front/x",
		"Connection", "X-Forwarded-For", "X-Forwarded-For", "1.2.3.4"))

	// 3. Path and query joining through SetURL.
	for _, c := range []struct{ name, target, req string }{
		{"root->root", "", "http://front/x"},
		{"prefix", "/api", "http://front/x"},
		{"prefix-slash", "/api/", "http://front/x"},
		{"prefix+slash-req", "/api/", "http://front//x"},
		{"req-root", "/api", "http://front/"},
		{"req-empty", "/api", "http://front"},
		{"escaped-req", "/api", "http://front/a%2Fb"},
		{"dots-req", "/api", "http://front/a/../b"},
		{"query-req", "/api", "http://front/x?a=1"},
		{"query-both", "/api?t=9", "http://front/x?a=1"},
		{"query-target-only", "/api?t=9", "http://front/x"},
		{"semicolon-query", "/api", "http://front/x?a=1;b=2"},
		{"unicode", "/api", "http://front/%E2%98%83"},
	} {
		u := *burl
		if c.target != "" {
			tu, _ := url.Parse(burl.String() + c.target)
			u = *tu
		}
		run("path/"+c.name, &u, mkreq(c.req))
	}

	// 4. What the proxy does when the backend is unreachable.
	{
		dead, _ := url.Parse("http://127.0.0.1:1")
		p := NewSingleHostReverseProxy(dead)
		p.ErrorLog = quiet
		w := httptest.NewRecorder()
		p.ServeHTTP(w, mkreq("http://front/x"))
		fmt.Printf("%-28s code=%d body=%q\n", "error/unreachable", w.Code, w.Body.String())
	}

	// 5. The response direction: hop-by-hop headers coming BACK are
	//    stripped too, so a backend cannot set them on the client.
	{
		b2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Connection", "X-Backend-Secret")
			w.Header().Set("X-Backend-Secret", "leaked")
			w.Header().Set("Keep-Alive", "timeout=5")
			w.Header().Set("X-Ok", "fine")
			w.Header().Set("Trailer", "X-T")
			w.WriteHeader(203)
			io.WriteString(w, "body")
		}))
		defer b2.Close()
		u2, _ := url.Parse(b2.URL)
		p := NewSingleHostReverseProxy(u2)
		p.ErrorLog = quiet
		w := httptest.NewRecorder()
		p.ServeHTTP(w, mkreq("http://front/x"))
		var keys []string
		for k := range w.Header() {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			if k == "Date" || k == "Content-Length" {
				continue
			}
			parts = append(parts, fmt.Sprintf("%s=%q", k, strings.Join(w.Header()[k], "|")))
		}
		fmt.Printf("%-28s code=%d hdr=[%s] body=%q\n",
			"resp/hop-stripped", w.Code, strings.Join(parts, " "), w.Body.String())
	}
}
