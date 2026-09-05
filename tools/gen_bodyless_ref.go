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

// Statuses that allow no body: 204, 304, 1xx. They must not carry
// Content-Length or a body, and a handler that writes one anyway must
// not be able to desync the connection.
func TestGoishRef(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		setCL  string
	}{
		{"204-clean", 204, "", ""},
		{"204-handler-writes", 204, "oops", ""},
		{"304-clean", 304, "", ""},
		{"304-handler-writes", 304, "oops", ""},
		{"304-explicit-cl", 304, "", "42"},
		{"205-reset", 205, "", ""},
		{"200-empty", 200, "", ""},
	} {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		srv := &http.Server{Handler: http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if tc.setCL != "" {
					w.Header().Set("Content-Length", tc.setCL)
				}
				w.WriteHeader(tc.status)
				if tc.body != "" {
					fmt.Fprint(w, tc.body)
				}
			})}
		go srv.Serve(ln)

		c, _ := net.Dial("tcp", ln.Addr().String())
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		raw, _ := io.ReadAll(c)
		c.Close()
		srv.Close()

		s := regexp.MustCompile(`Date: [^\r\n]+`).ReplaceAllString(string(raw), "Date: DATE")
		if i := strings.Index(s, "\r\n\r\n"); i >= 0 {
			head := strings.Split(s[:i], "\r\n")
			sort.Strings(head[1:])
			s = strings.Join(head, "\r\n") + s[i:]
		}
		fmt.Printf("%-20s %q\n", tc.name, strings.ReplaceAll(s, "\r\n", "\\r\\n"))
	}
}
