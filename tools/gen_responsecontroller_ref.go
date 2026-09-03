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

func TestGoishRef(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		fmt.Fprintf(w, "R:flush=%v ", errStr(rc.Flush()))
		fmt.Fprintf(w, "setread=%v ", errStr(rc.SetReadDeadline(time.Now().Add(time.Minute))))
		fmt.Fprintf(w, "setwrite=%v ", errStr(rc.SetWriteDeadline(time.Now().Add(time.Minute))))
		fmt.Fprintf(w, "fullduplex=%v", errStr(rc.EnableFullDuplex()))
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	defer ln.Close()
	time.Sleep(60 * time.Millisecond)
	c, _ := net.Dial("tcp", ln.Addr().String())
	c.SetReadDeadline(time.Now().Add(time.Second))
	io.WriteString(c, "GET /x HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
	b, _ := io.ReadAll(io.LimitReader(c, 4096))
	c.Close()
	raw := string(b)
	body := ""
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		body = raw[i+4:]
	}
	// chunked framing may wrap it; strip hex chunk headers
	body = strings.ReplaceAll(body, "\r\n", "")
	if i := strings.Index(body, "R:"); i >= 0 {
		body = body[i+2:]
	}
	if i := strings.LastIndex(body, "0"); i == len(body)-1 {
		body = body[:i]
	}
	fmt.Printf("responsecontroller %s\n", body)
}

func errStr(err error) string {
	if err == nil {
		return "nil"
	}
	return err.Error()
}
