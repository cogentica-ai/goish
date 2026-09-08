package http_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// Server.ReadTimeout is documented as "the maximum duration for reading
// the entire request, including the body". A client that sends headers
// promptly and then dribbles the body must still be cut off.
func TestGoishRef(t *testing.T) {
	for _, name := range []string{"slow-body", "prompt-body"} {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		got := make(chan string, 1)
		srv := &http.Server{
			ReadTimeout: 500 * time.Millisecond,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, err := io.ReadAll(r.Body)
				got <- fmt.Sprintf("read=%d err=%v", len(b), err)
				fmt.Fprint(w, "ok")
			}),
		}
		go srv.Serve(ln)

		c, _ := net.Dial("tcp", ln.Addr().String())
		fmt.Fprint(c, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n")
		if name == "prompt-body" {
			fmt.Fprint(c, "0123456789")
		} else {
			// Two bytes, then stall well past ReadTimeout.
			fmt.Fprint(c, "01")
			time.Sleep(1500 * time.Millisecond)
			fmt.Fprint(c, "23456789")
		}
		select {
		case s := <-got:
			fmt.Printf("%-12s handler: %s\n", name, s)
		case <-time.After(3 * time.Second):
			fmt.Printf("%-12s handler: never ran\n", name)
		}
		c.Close()
		srv.Close()
	}
}
