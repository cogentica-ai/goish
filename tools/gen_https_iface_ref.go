package http_test

import (
	"crypto/tls"
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
	mux.HandleFunc("/ifaces", func(w http.ResponseWriter, r *http.Request) {
		_, f := w.(http.Flusher)
		_, hj := w.(http.Hijacker)
		_, cn := w.(http.CloseNotifier)
		fmt.Fprintf(w, "flusher=%v hijacker=%v closenotifier=%v", f, hj, cn)
	})
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "part1")
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		time.Sleep(200 * time.Millisecond)
		io.WriteString(w, "part2")
	})

	ts := httptest.NewTLSServer(mux)
	defer ts.Close()
	addr := strings.TrimPrefix(ts.URL, "https://")

	raw := func(path string) string {
		c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", path)
		b, _ := io.ReadAll(io.LimitReader(c, 8192))
		return string(b)
	}
	_ = net.Dial

	r1 := raw("/ifaces")
	i := strings.Index(r1, "\r\n\r\n")
	fmt.Printf("HTTPS handler sees: %s\n", r1[i+4:])

	r2 := raw("/stream")
	fmt.Printf("HTTPS stream: chunked=%v has_cl=%v part1=%v part2=%v\n",
		strings.Contains(r2, "Transfer-Encoding: chunked"),
		strings.Contains(r2, "Content-Length:"),
		strings.Contains(r2, "part1"),
		strings.Contains(r2, "part2"))
}
