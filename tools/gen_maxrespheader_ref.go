package http_test

import (
	"fmt"
	"net"
	"net/http"
	"testing"
)

// Transport.MaxResponseHeaderBytes bounds the TOTAL response head, not
// one line. Go's default when unset is 10 MiB.
func TestGoishRef(t *testing.T) {
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
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\n")
				// Many small headers: each line is short, the total is
				// not. A per-line bound never fires here.
				for i := 0; i < 20000; i++ {
					fmt.Fprintf(c, "X-Pad-%d: %s\r\n", i, "0123456789")
				}
				fmt.Fprint(c, "Content-Length: 2\r\n\r\nhi")
			}(c)
		}
	}()

	for _, limit := range []int64{0, 1 << 10, 1 << 16, 1 << 20} {
		tr := &http.Transport{MaxResponseHeaderBytes: limit}
		c := &http.Client{Transport: tr}
		resp, err := c.Get("http://" + ln.Addr().String() + "/")
		if err != nil {
			fmt.Printf("limit=%-8d err=%v\n", limit, err)
			continue
		}
		fmt.Printf("limit=%-8d status=%d headers=%d\n", limit, resp.StatusCode, len(resp.Header))
		resp.Body.Close()
	}
}
