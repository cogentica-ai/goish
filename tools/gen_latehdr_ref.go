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

// A header set AFTER the handler's first write. Go snapshots the
// header when the head is committed, so a late Set is ignored.
func TestGoishRef(t *testing.T) {
	for _, tc := range []struct{ name string; before, after bool }{
		{"set-before-write", true, false},
		{"set-after-write", false, true},
	} {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		srv := &http.Server{Handler: http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if tc.before {
					w.Header().Set("X-Late", "yes")
				}
				fmt.Fprint(w, "body")
				if tc.after {
					w.Header().Set("X-Late", "yes")
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
		fmt.Printf("%-18s has-x-late=%v  %q\n", tc.name,
			strings.Contains(s, "X-Late"), strings.ReplaceAll(s, "\r\n", "\\r\\n"))
	}
}
