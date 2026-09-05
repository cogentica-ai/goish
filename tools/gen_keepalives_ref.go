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

// Server.SetKeepAlivesEnabled(false) must stop the server reusing a
// connection. Two things are observable and they are not the same: the
// Connection header the server sends, and whether a second request on
// the same socket is actually answered.
func TestGoishRef(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		for _, proto := range []string{"1.1", "1.0"} {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			srv := &http.Server{Handler: http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprint(w, "hi")
				})}
			srv.SetKeepAlivesEnabled(enabled)
			go srv.Serve(ln)

			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			write := func() {
				req := "GET / HTTP/" + proto + "\r\nHost: x\r\n"
				if proto == "1.0" {
					req += "Connection: keep-alive\r\n"
				}
				fmt.Fprint(c, req+"\r\n")
			}
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			br := bufio.NewReader(c)

			write()
			conn := ""
			for {
				line, err := br.ReadString('\n')
				if err != nil || line == "\r\n" {
					break
				}
				if len(line) > 11 && line[:11] == "Connection:" {
					conn = line[12 : len(line)-2]
				}
			}
			io.ReadFull(br, make([]byte, 2)) // the "hi" body

			// Second request on the same socket: answered or not?
			write()
			status, err2 := br.ReadString('\n')
			reused := err2 == nil && len(status) > 8 && status[:4] == "HTTP"
			fmt.Printf("enabled=%-5v proto=%s connection=%-10q reused=%v\n",
				enabled, proto, conn, reused)
			c.Close()
			srv.Close()
		}
	}
}
