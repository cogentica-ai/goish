package http_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A raw listener that records exactly what the client wrote, then
// replies with a fixed 200.
func rawServer(t *testing.T, out chan<- string) (string, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				br := bufio.NewReader(c)
				var sb strings.Builder
				// read the head
				for {
					ln, err := br.ReadString('\n')
					if err != nil {
						break
					}
					sb.WriteString(ln)
					if ln == "\r\n" {
						break
					}
				}
				head := sb.String()
				// Read the body according to the framing the client
				// just declared, so the capture is deterministic.
				var body string
				if strings.Contains(head, "Transfer-Encoding: chunked") {
					var bb strings.Builder
					for {
						ln, err := br.ReadString('\n')
						if err != nil {
							break
						}
						bb.WriteString(ln)
						if strings.HasSuffix(bb.String(), "0\r\n\r\n") {
							break
						}
					}
					body = bb.String()
				} else {
					n := 0
					for _, ln := range strings.Split(head, "\r\n") {
						if strings.HasPrefix(ln, "Content-Length: ") {
							fmt.Sscanf(ln, "Content-Length: %d", &n)
						}
					}
					if n > 0 {
						buf := make([]byte, n)
						io.ReadFull(br, buf)
						body = string(buf)
					}
				}
				out <- head + "|BODY|" + body
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestGoishRef(t *testing.T) {
	seen := make(chan string, 8)
	addr, stop := rawServer(t, seen)
	defer stop()

	show := func(label string, req *http.Request) {
		tr := &http.Transport{DisableKeepAlives: true}
		resp, err := tr.RoundTrip(req)
		if err != nil {
			fmt.Printf("%-16s roundtrip error: %v\n", label, err)
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		raw := <-seen
		parts := strings.SplitN(raw, "|BODY|", 2)
		head, body := parts[0], parts[1]
		// normalise the Host line (port varies) and sort nothing else
		head = strings.ReplaceAll(head, addr, "HOST")
		fmt.Printf("%-16s head=%q body=%q\n", label, head, body)
	}

	mk := func(method, path string, body io.Reader) *http.Request {
		r, err := http.NewRequest(method, "http://"+addr+path, body)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	show("get", mk("GET", "/a", nil))
	show("post-strings", mk("POST", "/a", strings.NewReader("hello")))
	// a reader whose length the client cannot know → chunked
	show("post-unknown", mk("POST", "/a", io.LimitReader(strings.NewReader("hello"), 5)))
	r := mk("POST", "/a", strings.NewReader("hello"))
	r.ContentLength = 5
	show("post-explicit-cl", r)
	r = mk("POST", "/a", strings.NewReader(""))
	show("post-empty", r)
	r = mk("GET", "/a", nil)
	r.Close = true
	show("get-close", r)
	r = mk("GET", "/a", nil)
	r.Header.Set("User-Agent", "")
	show("get-no-ua", r)
	r = mk("GET", "/a?x=1&y=2", nil)
	show("get-query", r)
}
