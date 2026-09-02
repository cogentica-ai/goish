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

// http.ReadResponse is the client-side twin of ReadRequest, and it has
// the same problem from the other direction: a client and an
// intermediary that disagree about where a response ends can be made to
// desync, so the next response a client reads is attacker-chosen. Its
// framing rules are also subtler than the request side's, because the
// STATUS CODE decides whether a body is allowed at all.
//
// The rules that must hold:
//
//   * 1xx, 204 and 304 have NO body regardless of what the headers say.
//     Go reports ContentLength 0 for 204/304 and refuses to read a body,
//     so a Content-Length on a 304 does not make the client consume the
//     next response's bytes.
//   * HEAD responses carry the headers a GET would, including
//     Content-Length, but no body — and ReadResponse must be told which
//     request it is answering to get that right.
//   * A response to a request Go does not know about defaults to
//     "read until EOF" when there is no Content-Length and no chunked
//     encoding, which is the HTTP/1.0 close-delimited case.
//   * Content-Length and Transfer-Encoding conflicts, duplicate
//     Content-Length headers and non-numeric values are refused the
//     same way as on the request side.
//   * The status line is "HTTP/1.1 200 OK", the reason phrase is
//     optional, and the code must be three digits.
func TestGoishRef(t *testing.T) {
	type tc struct {
		name string
		raw  string
		req  string // request method this responds to
	}
	for _, c := range []tc{
		{"simple", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", "GET"},
		{"no-reason", "HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n", "GET"},
		{"reason-spaces", "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", "GET"},
		{"http10-close", "HTTP/1.0 200 OK\r\n\r\nbody-to-eof", "GET"},
		{"chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", "GET"},
		{"204", "HTTP/1.1 204 No Content\r\n\r\n", "GET"},
		{"204-with-cl", "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\nhello", "GET"},
		{"304", "HTTP/1.1 304 Not Modified\r\n\r\n", "GET"},
		{"304-with-cl", "HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\nhello", "GET"},
		{"100", "HTTP/1.1 100 Continue\r\n\r\n", "GET"},
		{"head", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", "HEAD"},
		{"head-chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "HEAD"},
		{"cl-neg", "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n", "GET"},
		{"cl-junk", "HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n", "GET"},
		{"cl-dup-diff", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx", "GET"},
		{"cl-dup-same", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx", "GET"},
		{"te-and-cl", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n", "GET"},
		{"te-gzip", "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n", "GET"},
		{"bad-code", "HTTP/1.1 20 OK\r\n\r\n", "GET"},
		{"code-4digit", "HTTP/1.1 2000 OK\r\n\r\n", "GET"},
		{"code-nonnum", "HTTP/1.1 abc OK\r\n\r\n", "GET"},
		{"bad-proto", "ICY 200 OK\r\n\r\n", "GET"},
		{"empty", "", "GET"},
		{"only-status", "HTTP/1.1 200 OK\r\n", "GET"},
		{"conn-close", "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 1\r\n\r\nx", "GET"},
		{"multi-header", "HTTP/1.1 200 OK\r\nX-A: 1\r\nX-A: 2\r\nContent-Length: 0\r\n\r\n", "GET"},
	} {
		req, _ := http.NewRequest(c.req, "http://x/", nil)
		br := bufio.NewReader(strings.NewReader(c.raw))
		res, err := http.ReadResponse(br, req)
		if err != nil {
			fmt.Printf("res %-14s -> err=%q\n", c.name, err.Error())
			continue
		}
		body, berr := io.ReadAll(res.Body)
		fmt.Printf("res %-14s -> code=%-4d status=%-16q proto=%-9q cl=%-3d te=%v close=%-5v hdr=%s body=%q berr=%v\n",
			c.name, res.StatusCode, res.Status, res.Proto, res.ContentLength,
			res.TransferEncoding, res.Close, hdrString(res.Header), body,
			errText(berr))
	}

	// Header writing: the CRLF injection a value must never carry, and
	// what Go does about it.
	for _, v := range []string{
		"plain", "with\rcr", "with\nlf", "with\r\ncrlf", "with\x00nul",
		"trailing ", " leading", "tab\there",
	} {
		h := http.Header{}
		h.Set("X-Test", v)
		var sb strings.Builder
		err := h.Write(&sb)
		fmt.Printf("hdrwrite %-12q -> out=%-30q err=%v\n", v, sb.String(), errText(err))
	}
	for _, k := range []string{"X-Ok", "X-Bad\r\nInjected", "X Bad", ""} {
		h := http.Header{}
		h[k] = []string{"v"}
		var sb strings.Builder
		err := h.Write(&sb)
		fmt.Printf("hdrkey %-20q -> out=%-26q err=%v\n", k, sb.String(), errText(err))
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
