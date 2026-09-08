package http_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
)

// bodyEOFSignal.Read (transport.go:2989) keeps `rerr`, the first read
// error, and returns it from every later Read. A truncated response —
// Content-Length promises 100, the server sends 10 and closes — must
// therefore report the SAME failure each time, not decay into EOF or
// retry the dead connection.
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
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789")
		c.Close()
	}()

	resp, gerr := http.Get("http://" + ln.Addr().String() + "/")
	if gerr != nil {
		fmt.Printf("get err=%v\n", gerr)
		return
	}
	buf := make([]byte, 8)
	for i := 0; i < 4; i++ {
		n, e := resp.Body.Read(buf)
		fmt.Printf("read%d n=%d err=%v\n", i, n, e)
	}
	resp.Body.Close()
	n, e := resp.Body.Read(buf)
	fmt.Printf("after close n=%d err=%v\n", n, e)
}
