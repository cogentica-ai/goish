package http_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// A HEAD response must carry the headers a GET would, including
// Content-Length, and NO body. A body on a HEAD desyncs a keep-alive
// connection, so this is framing, not cosmetics.
func TestGoishRef(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		body   string
		setCL  string
	}{
		{"head-writes-body", "HEAD", "hello world", ""},
		{"get-writes-body", "GET", "hello world", ""},
		{"head-empty", "HEAD", "", ""},
		{"head-explicit-cl", "HEAD", "hello world", "11"},
		{"head-wrong-cl", "HEAD", "hi", "999"},
	} {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		srv := &http.Server{Handler: http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if tc.setCL != "" {
					w.Header().Set("Content-Length", tc.setCL)
				}
				if tc.body != "" {
					fmt.Fprint(w, tc.body)
				}
			})}
		go srv.Serve(ln)

		c, _ := net.Dial("tcp", ln.Addr().String())
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		fmt.Fprintf(c, "%s / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", tc.method)
		raw, _ := io.ReadAll(c)
		c.Close()
		srv.Close()

		s := regexp.MustCompile(`Date: [^\r\n]+`).ReplaceAllString(string(raw), "Date: DATE")
		// Sort the header block; goish orders Connection differently
		// (ROADMAP 2i) and that is not what this measures.
		if i := strings.Index(s, "\r\n\r\n"); i >= 0 {
			head := strings.Split(s[:i], "\r\n")
			sort.Strings(head[1:])
			s = strings.Join(head, "\r\n") + s[i:]
		}
		fmt.Printf("%-18s %q\n", tc.name, strings.ReplaceAll(s, "\r\n", "\\r\\n"))
	}
}
