package http_test

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Server.MaxHeaderBytes bounds the request head. Go answers 431 past
// it. The default is DefaultMaxHeaderBytes (1 MiB).
func TestGoishRef(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int
		pad   int
		count int
	}{
		{"default-small", 0, 100, 0},
		{"set-8k-under", 8 << 10, 4000, 0},
		{"set-8k-over", 8 << 10, 20000, 0},
		{"default-over", 0, 2 << 20, 0},
		// One header LINE far past any bufio buffer but well under the
		// 1 MiB default: the server analogue of the client's long-line
		// bug. Go's textproto accumulates, so this is a 200.
		{"long-line", 0, 100 << 10, 0},
		{"count-200", 0, 0, 200},
		{"count-5000", 0, 0, 5000},
	} {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		srv := &http.Server{
			MaxHeaderBytes: tc.limit,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, "ok")
			}),
		}
		go srv.Serve(ln)

		c, _ := net.Dial("tcp", ln.Addr().String())
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if tc.count > 0 {
			var b strings.Builder
			b.WriteString("GET / HTTP/1.1\r\nHost: x\r\n")
			for i := 0; i < tc.count; i++ {
				fmt.Fprintf(&b, "X-H%d: v\r\n", i)
			}
			b.WriteString("Connection: close\r\n\r\n")
			fmt.Fprint(c, b.String())
		} else {
			fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: x\r\nX-Pad: %s\r\nConnection: close\r\n\r\n",
				strings.Repeat("a", tc.pad))
		}
		br := bufio.NewReader(c)
		status, err := br.ReadString('\n')
		if err != nil {
			fmt.Printf("%-14s limit=%-8d pad=%-8d count=%-6d err=%v\n", tc.name, tc.limit, tc.pad, tc.count, err)
		} else {
			fmt.Printf("%-14s limit=%-8d pad=%-8d count=%-6d %q\n", tc.name, tc.limit, tc.pad, tc.count, status)
		}
		c.Close()
		srv.Close()
	}
}
