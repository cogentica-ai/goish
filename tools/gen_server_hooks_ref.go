package http_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type ctxKey string

func TestGoishRef(t *testing.T) {
	var logbuf bytes.Buffer
	var mu sync.Mutex

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base, _ := r.Context().Value(ctxKey("base")).(string)
		conn, _ := r.Context().Value(ctxKey("conn")).(string)
		fmt.Fprintf(w, "base=%q conn=%q", base, conn)
		// A second WriteHeader is the classic ErrorLog trigger.
		w.WriteHeader(200)
		w.WriteHeader(201)
	})

	srv := &http.Server{
		Handler: h,
		BaseContext: func(ln net.Listener) context.Context {
			return context.WithValue(context.Background(), ctxKey("base"), "B")
		},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, ctxKey("conn"), "C")
		},
		ErrorLog: log.New(&logbuf, "", 0),
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer ln.Close()
	time.Sleep(60 * time.Millisecond)

	c, _ := net.Dial("tcp", ln.Addr().String())
	c.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	io.WriteString(c, "GET /p HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	b, _ := io.ReadAll(io.LimitReader(c, 4096))
	c.Close()
	raw := string(b)
	body := ""
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		body = raw[i+4:]
	}
	fmt.Printf("%-16s %s\n", "handler-ctx", body)

	time.Sleep(80 * time.Millisecond)
	mu.Lock()
	logged := logbuf.String()
	mu.Unlock()
	fmt.Printf("%-16s errorlog-used=%v mentions-superfluous=%v\n",
		"errorlog", len(logged) > 0, strings.Contains(logged, "superfluous"))
}
