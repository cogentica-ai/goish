package http_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
)

// After a 101, the response body IS the connection: Go's transport
// hands back a readWriteCloserBody and the caller asserts
// `res.Body.(io.ReadWriteCloser)` to speak the new protocol. Reading
// it is only half — a client that cannot WRITE cannot upgrade to
// anything.
func TestGoishRef(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		br := bufio.NewReader(c)
		http.ReadRequest(br)
		io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
		// Echo one line back, uppercased by hand.
		line, _ := br.ReadString('\n')
		io.WriteString(c, "echo:"+line)
	}()

	req, _ := http.NewRequest("GET", "http://"+ln.Addr().String()+"/", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "echo")
	resp, rerr := http.DefaultTransport.RoundTrip(req)
	if rerr != nil {
		fmt.Printf("roundtrip err=%v\n", rerr)
		return
	}
	fmt.Printf("status=%d upgrade=%q\n", resp.StatusCode, resp.Header.Get("Upgrade"))

	rwc, ok := resp.Body.(io.ReadWriteCloser)
	fmt.Printf("body is ReadWriteCloser=%v\n", ok)
	if !ok {
		return
	}
	io.WriteString(rwc, "ping\n")
	buf := make([]byte, 32)
	n, _ := rwc.Read(buf)
	fmt.Printf("read back=%q\n", string(buf[:n]))
	rwc.Close()
}
