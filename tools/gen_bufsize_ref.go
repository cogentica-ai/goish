package http_test

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
)

// Transport.ReadBufferSize sizes the conn's bufio.Reader
// (transport.go:1944), which is what bounds a single response header
// LINE. Raising it lets a longer line through.
func TestGoishRef(t *testing.T) {
	n := 8000
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 4096)
				c.Read(buf)
				// One header line of ~8 KiB: over the 4 KiB default,
				// under a raised 16 KiB buffer.
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\n")
				fmt.Fprintf(c, "X-Long: %s\r\n", strings.Repeat("a", n))
				fmt.Fprint(c, "Content-Length: 2\r\n\r\nhi")
			}(c)
		}
	}()

	for _, tc := range []struct{ size, hdr int }{{0, 8000}, {16384, 8000}, {0, 64000}} {
		size := tc.size
		n = tc.hdr
		tr := &http.Transport{ReadBufferSize: size}
		c := &http.Client{Transport: tr}
		resp, err := c.Get("http://" + ln.Addr().String() + "/")
		if err != nil {
			fmt.Printf("readbuf=%-6d hdr=%-6d err=%v\n", size, n, err)
			continue
		}
		fmt.Printf("readbuf=%-6d hdr=%-6d status=%d longlen=%d\n",
			size, n, resp.StatusCode, len(resp.Header.Get("X-Long")))
		resp.Body.Close()
	}
}
