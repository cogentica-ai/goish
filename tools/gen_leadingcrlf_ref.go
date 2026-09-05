package http_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// Go discards leading CR/LF before a request line, but ONLY when the
// previous request on the connection was a POST — "RFC 7230 section 3
// tolerance for old buggy clients" (server.go:1036).
func TestGoishRef(t *testing.T) {
	for _, first := range []string{"POST", "GET"} {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		srv := &http.Server{Handler: http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "ok:%s", r.Method)
			})}
		go srv.Serve(ln)

		c, _ := net.Dial("tcp", ln.Addr().String())
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		br := bufio.NewReader(c)

		// First request, with a body for POST so the connection is
		// reusable either way.
		if first == "POST" {
			fmt.Fprint(c, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi")
		} else {
			fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
		}
		// Drain the first response exactly: headers, then precisely
		// Content-Length body bytes, so nothing of it leaks into the
		// line read below.
		clen := 0
		for {
			line, err := br.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
			var n int
			if _, e := fmt.Sscanf(line, "Content-Length: %d", &n); e == nil {
				clen = n
			}
		}
		io.ReadFull(br, make([]byte, clen))
		time.Sleep(50 * time.Millisecond)

		// Second request preceded by stray CRLF.
		fmt.Fprint(c, "\r\n\r\nGET /second HTTP/1.1\r\nHost: x\r\n\r\n")
		status, err := br.ReadString('\n')
		if err != nil {
			fmt.Printf("after=%-5s second-request: err=%v\n", first, err)
		} else {
			fmt.Printf("after=%-5s second-request: %q\n", first, status)
		}
		c.Close()
		srv.Close()
	}
}
