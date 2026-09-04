package http_test

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
)

// http.ReadRequest is the largest untrusted-input surface a server has:
// every byte of it came off a socket, and the framing decisions it
// makes are exactly the ones request smuggling attacks target. If a
// front-end proxy and a back-end server disagree about where one
// request ends and the next begins, an attacker can prepend bytes to
// somebody else's request. So the interesting cases here are not the
// well-formed ones.
//
// The rules that must hold, and that a permissive parser breaks:
//
//   * Content-Length and Transfer-Encoding together is the classic
//     smuggling primitive. Go REFUSES the request rather than picking a
//     winner, because picking one is how two hops end up picking
//     differently.
//   * Two Content-Length headers that disagree are refused; two that
//     agree are collapsed. A single header carrying "1, 1" is also
//     handled, and "1, 2" is not.
//   * A Content-Length that is negative, non-numeric, or has a sign is
//     refused — not clamped, not parsed leniently.
//   * A Transfer-Encoding that is anything other than "chunked" is
//     refused, and "chunked" must be the LAST encoding.
//   * HTTP/1.1 requires a Host header, and a request line carrying an
//     absolute URI overrides it.
//   * The method is a token: no spaces, no control bytes.
//   * A header line with a space before the colon is refused, because
//     proxies have historically disagreed about how to read it.
func TestGoishRef(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"simple", "GET / HTTP/1.1\r\nHost: x\r\n\r\n"},
		{"http10", "GET / HTTP/1.0\r\n\r\n"},
		{"no-host-11", "GET / HTTP/1.1\r\n\r\n"},
		{"absolute-uri", "GET http://a.example/p?q=1 HTTP/1.1\r\nHost: b.example\r\n\r\n"},
		{"asterisk", "OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n"},
		{"post-cl", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"},
		{"cl-zero", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"},
		{"cl-neg", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n"},
		{"cl-plus", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +5\r\n\r\nhello"},
		{"cl-junk", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n"},
		{"cl-space", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5 \r\n\r\nhello"},
		{"cl-dup-same", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"},
		{"cl-dup-diff", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello"},
		{"cl-list-same", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5, 5\r\n\r\nhello"},
		{"cl-list-diff", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5, 6\r\n\r\nhello"},
		{"chunked", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"},
		{"te-and-cl", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\nhello"},
		{"te-gzip", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n"},
		{"te-chunked-not-last", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"},
		{"te-http10", "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n"},
		{"space-before-colon", "GET / HTTP/1.1\r\nHost : x\r\n\r\n"},
		{"method-space", "GE T / HTTP/1.1\r\nHost: x\r\n\r\n"},
		{"method-lower", "get / HTTP/1.1\r\nHost: x\r\n\r\n"},
		{"bad-version", "GET / HTTP/9.9\r\nHost: x\r\n\r\n"},
		{"no-version", "GET /\r\nHost: x\r\n\r\n"},
		{"empty", ""},
		{"only-crlf", "\r\n"},
		{"dup-host", "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"},
		{"header-case", "GET / HTTP/1.1\r\nhOsT: x\r\ncontent-type: t\r\n\r\n"},
		{"multi-value", "GET / HTTP/1.1\r\nHost: x\r\nX-A: 1\r\nX-A: 2\r\n\r\n"},
		{"obs-fold", "GET / HTTP/1.1\r\nHost: x\r\nX-A: 1\r\n  2\r\n\r\n"},
		{"bare-lf-line", "GET / HTTP/1.1\nHost: x\n\n"},
		{"trailing-space-value", "GET / HTTP/1.1\r\nHost: x\r\nX-A:  v  \r\n\r\n"},
		{"empty-value", "GET / HTTP/1.1\r\nHost: x\r\nX-A:\r\n\r\n"},
	}
	for _, c := range cases {
		br := bufio.NewReader(strings.NewReader(c.raw))
		req, err := http.ReadRequest(br)
		if err != nil {
			fmt.Printf("req %-21s -> err=%q\n", c.name, err.Error())
			continue
		}
		body, berr := io.ReadAll(req.Body)
		fmt.Printf("req %-21s -> m=%-8q uri=%-26q proto=%-9q host=%-9q cl=%-3d te=%v hdr=%s body=%q berr=%v\n",
			c.name, req.Method, req.URL.String(), req.Proto, req.Host,
			req.ContentLength, req.TransferEncoding, hdrString(req.Header),
			body, errText(berr))
	}

	// Cookie parsing: what a server accepts from a client, and what it
	// refuses in a Set-Cookie it is asked to parse.
	for _, v := range []string{
		"a=1", "a=1; b=2", "a=1;b=2", "a=", "=1", "a", "a=1; ; b=2",
		`a="quoted"`, "a=1; a=2", "A=1; a=2", "a=b=c", "a=1;", " a = 1 ",
		"a=\x00", "a=1\t", "önem=1",
	} {
		h := http.Header{"Cookie": {v}}
		r := &http.Request{Header: h}
		var parts []string
		for _, c := range r.Cookies() {
			parts = append(parts, c.Name+"="+c.Value)
		}
		fmt.Printf("cookie %-14q -> %v\n", v, parts)
	}
	for _, v := range []string{
		"a=1", "a=1; Path=/; HttpOnly", "a=1; Max-Age=0", "a=1; Max-Age=-1",
		"a=1; Max-Age=abc", "a=1; Secure; SameSite=Lax", "a=1; SameSite=Bogus",
		"a=1; Domain=.example.com", "a=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
		"=1", "a", "", "a=1; Path=/x\x00y",
	} {
		c, err := http.ParseSetCookie(v)
		if err != nil {
			fmt.Printf("setcookie %-42q -> err=%q\n", v, err.Error())
			continue
		}
		fmt.Printf("setcookie %-42q -> name=%-3q val=%-4q path=%-4q dom=%-13q maxage=%-3d secure=%-5v httponly=%-5v samesite=%d str=%q\n",
			v, c.Name, c.Value, c.Path, c.Domain, c.MaxAge, c.Secure,
			c.HttpOnly, int(c.SameSite), c.String())
	}

	// CanonicalHeaderKey over the forms a client can send.
	for _, k := range []string{
		"content-type", "CONTENT-TYPE", "Content-Type", "x-a-b", "X_A",
		"a", "", "-", "--", "a-", "-a", "aB-cD", "x-forwarded-for",
		"Sec-WebSocket-Key", "a b", "a\tb",
	} {
		fmt.Printf("canon %-20q -> %q\n", k, http.CanonicalHeaderKey(k))
	}
}

func hdrString(h http.Header) string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString("=")
		for i, v := range h[k] {
			if i > 0 {
				sb.WriteString("|")
			}
			sb.WriteString(v)
		}
		sb.WriteString(";")
	}
	return sb.String()
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
