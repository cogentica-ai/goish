package http_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func raw(t *testing.T, srv *http.Server, req string) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer ln.Close()
	time.Sleep(50 * time.Millisecond)
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	io.WriteString(c, req)
	b, _ := io.ReadAll(io.LimitReader(c, 4096))
	raw := string(b)
	status := raw
	if i := strings.Index(raw, "\r\n"); i > 0 {
		status = raw[:i]
	}
	body := ""
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		body = raw[i+4:]
	}
	return fmt.Sprintf("%-24s body=%q", status, body)
}

func TestGoishRef(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "handler saw %s %s", r.Method, r.URL.Path)
	})

	// OPTIONS * — Go answers it itself unless the flag disables that.
	fmt.Printf("%-28s %s\n", "options-star-default",
		raw(t, &http.Server{Handler: h}, "OPTIONS * HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
	fmt.Printf("%-28s %s\n", "options-star-disabled",
		raw(t, &http.Server{Handler: h, DisableGeneralOptionsHandler: true},
			"OPTIONS * HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
	// A normal OPTIONS on a path always reaches the handler.
	fmt.Printf("%-28s %s\n", "options-path",
		raw(t, &http.Server{Handler: h}, "OPTIONS /p HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))

	// MaxHeaderBytes: a header block past the cap is refused.
	big := strings.Repeat("a", 6000)
	fmt.Printf("%-28s %s\n", "maxheader-under",
		raw(t, &http.Server{Handler: h, MaxHeaderBytes: 8000},
			"GET /p HTTP/1.1\r\nHost: x\r\nX-Pad: "+big+"\r\nConnection: close\r\n\r\n"))
	fmt.Printf("%-28s %s\n", "maxheader-over",
		raw(t, &http.Server{Handler: h, MaxHeaderBytes: 1000},
			"GET /p HTTP/1.1\r\nHost: x\r\nX-Pad: "+big+"\r\nConnection: close\r\n\r\n"))
}
