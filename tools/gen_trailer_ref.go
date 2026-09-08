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

// Response trailers. A trailer must be ANNOUNCED in the Trailer header
// before the body and emitted after the last chunk, which only works
// under chunked encoding.
func TestGoishRef(t *testing.T) {
	for _, tc := range []struct {
		name     string
		announce string
		set      map[string]string
		flush    bool
	}{
		{"announced-and-set", "X-Sum", map[string]string{"X-Sum": "42"}, true},
		{"announced-not-set", "X-Sum", nil, true},
		{"set-not-announced", "", map[string]string{"X-Sum": "42"}, true},
		{"no-trailers", "", nil, true},
		{"announced-no-flush", "X-Sum", map[string]string{"X-Sum": "42"}, false},
	} {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		srv := &http.Server{Handler: http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if tc.announce != "" {
					w.Header().Set("Trailer", tc.announce)
				}
				fmt.Fprint(w, "body")
				if tc.flush {
					w.(http.Flusher).Flush()
				}
				for k, v := range tc.set {
					w.Header().Set(k, v)
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
		// Sort the response header block; goish orders it differently
		// (ROADMAP 2i) and that is not what this measures. The BODY —
		// chunks and trailers — is compared verbatim.
		if i := strings.Index(s, "\r\n\r\n"); i >= 0 {
			head := strings.Split(s[:i], "\r\n")
			sort.Strings(head[1:])
			s = strings.Join(head, "\r\n") + s[i:]
		}
		fmt.Printf("%-20s %q\n", tc.name, strings.ReplaceAll(s, "\r\n", "\\r\\n"))
	}
}
