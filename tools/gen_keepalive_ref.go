package http_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
	"testing"
)

func TestGoishRef(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "body")
	})
	mux.HandleFunc("/hclose", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		io.WriteString(w, "body")
	})
	mux.HandleFunc("/overrun", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "4")
		n1, e1 := io.WriteString(w, "abcd")
		n2, e2 := io.WriteString(w, "EXTRA")
		fmt.Printf("      overrun handler: n1=%d e1=%v n2=%d e2=%v\n", n1, e1, n2, e2)
	})
	mux.HandleFunc("/under", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "10")
		io.WriteString(w, "abc")
	})
	mux.HandleFunc("/empty204", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()
	addr := strings.TrimPrefix(ts.URL, "http://")

	hdr := func(raw, name string) string {
		for _, ln := range strings.Split(raw, "\r\n") {
			if ln == "" {
				break
			}
			if strings.HasPrefix(strings.ToLower(ln), strings.ToLower(name)+":") {
				return strings.TrimSpace(ln[len(name)+1:])
			}
		}
		return "-"
	}

	// one request, verbatim request line + headers
	probe := func(label, req string) string {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		io.WriteString(c, req)
		b, _ := io.ReadAll(io.LimitReader(c, 4096))
		raw := string(b)
		fmt.Printf("%-22s conn=%-10s cl=%-4s te=%-8s body=%q\n",
			label, hdr(raw, "Connection"), hdr(raw, "Content-Length"),
			hdr(raw, "Transfer-Encoding"), bodyOf(raw))
		return raw
	}

	probe("11-default", "GET /ok HTTP/1.1\r\nHost: x\r\n\r\n")
	probe("11-close", "GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	probe("11-handler-close", "GET /hclose HTTP/1.1\r\nHost: x\r\n\r\n")
	probe("10-default", "GET /ok HTTP/1.0\r\n\r\n")
	probe("10-keepalive", "GET /ok HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
	probe("11-204", "GET /empty204 HTTP/1.1\r\nHost: x\r\n\r\n")
	probe("10-204", "GET /empty204 HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
	probe("11-head", "HEAD /ok HTTP/1.1\r\nHost: x\r\n\r\n")
	probe("11-overrun", "GET /overrun HTTP/1.1\r\nHost: x\r\n\r\n")
	probe("11-under", "GET /under HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

	// two requests on one connection: does the server actually reuse it?
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	io.WriteString(c, "GET /ok HTTP/1.1\r\nHost: x\r\n\r\nGET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	b, _ := io.ReadAll(io.LimitReader(c, 4096))
	c.Close()
	fmt.Printf("%-22s responses=%d\n", "pipelined-2", strings.Count(string(b), "HTTP/1.1 200"))
}

func bodyOf(raw string) string {
	i := strings.Index(raw, "\r\n\r\n")
	if i < 0 {
		return ""
	}
	return raw[i+4:]
}
