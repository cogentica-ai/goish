package http_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGoishRef(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "path=%s cl=%d te=%v body=%q", r.URL.Path, r.ContentLength, r.TransferEncoding, string(b))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	addr := strings.TrimPrefix(ts.URL, "http://")

	run := func(label, req string) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
		io.WriteString(c, req)
		b, _ := io.ReadAll(io.LimitReader(c, 4096))
		raw := string(b)
		status := "<none>"
		if i := strings.Index(raw, "\r\n"); i > 0 {
			status = raw[:i]
		}
		nresp := strings.Count(raw, "HTTP/1.1 ")
		body := ""
		if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
			body = raw[i+4:]
			if j := strings.Index(body, "HTTP/1.1 "); j >= 0 {
				body = body[:j]
			}
		}
		fmt.Printf("%-20s n=%d status=%-32s body=%q\n", label, nresp, status, body)
	}

	run("cl+te", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	run("dup-cl-same", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc")
	run("dup-cl-diff", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabc")
	run("cl-list-same", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3, 3\r\nConnection: close\r\n\r\nabc")
	run("te-chunked-twice", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n")
	run("te-identity", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: identity\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc")
	run("cl-plus", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +3\r\nConnection: close\r\n\r\nabc")
	run("cl-space", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3 \r\nConnection: close\r\n\r\nabc")
	run("cl-hex", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0x3\r\nConnection: close\r\n\r\nabc")
	run("space-before-colon", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length : 3\r\nConnection: close\r\n\r\nabc")
	run("te-10", "POST / HTTP/1.0\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
	run("chunk-ext", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5;foo=bar\r\nhello\r\n0\r\n\r\n")
	run("bad-chunk-size", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5x\r\nhello\r\n0\r\n\r\n")
	run("neg-cl", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\nConnection: close\r\n\r\n")
}
