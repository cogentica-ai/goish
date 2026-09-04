package cgi

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
)

// The CHILD half of net/http/cgi: the writer a handler is handed
// INSIDE a CGI process.
//
// A CGI handler is an ordinary http.Handler, so it reaches for the
// same optional interfaces any handler does — and the one that matters
// for CGI in particular is Flusher. CGI is how a long-running script
// streams progress to a client; a handler that calls Flush and finds
// nothing there buffers its whole response instead, and the only
// symptom is that the output arrives all at once at the end. Nothing
// errors, nothing logs.
//
// The response is constructed directly rather than through Serve,
// which reads os.Stdin and writes os.Stdout: what is being measured is
// the WRITER's interface set and the bytes it produces, not the
// process plumbing.
//
// Pinned: which assertions succeed, the CGI header block (which uses
// "Status:" in place of HTTP's status line), and the body.
func TestGoishRef(t *testing.T) {
	probe := func(label string, h func(w http.ResponseWriter)) {
		var buf bytes.Buffer
		req, _ := http.NewRequest("GET", "http://example.test/p", nil)
		rw := &response{
			req:    req,
			header: make(http.Header),
			bufw:   bufio.NewWriter(&buf),
		}
		var w http.ResponseWriter = rw
		_, flusher := w.(http.Flusher)
		_, hijacker := w.(http.Hijacker)
		h(w)
		rw.Write(nil) // Serve's "make sure a response is sent"
		rw.bufw.Flush()
		fmt.Printf("cgi %-14s -> flusher=%-5v hijacker=%-5v out=%q\n",
			label, flusher, hijacker, normalize(buf.String()))
	}

	probe("plain", func(w http.ResponseWriter) {
		w.Header().Set("X-From-Handler", "1")
		w.WriteHeader(201)
		io.WriteString(w, "body")
	})
	probe("streaming", func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "chunk-a")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		io.WriteString(w, "chunk-b")
	})
	probe("no-write", func(w http.ResponseWriter) {
		w.Header().Set("X-Empty", "yes")
	})
	probe("status-only", func(w http.ResponseWriter) {
		w.WriteHeader(404)
	})
	probe("flush-before-write", func(w http.ResponseWriter) {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		io.WriteString(w, "after")
	})
}

// The header block's field order is map-iteration order, so it is
// sorted before comparison; the Status line and body are not.
func normalize(s string) string {
	i := strings.Index(s, "\r\n\r\n")
	if i < 0 {
		return s
	}
	lines := strings.Split(s[:i], "\r\n")
	sort.Strings(lines)
	return strings.Join(lines, "|") + "||" + s[i+4:]
}
