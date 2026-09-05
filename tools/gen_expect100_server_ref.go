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

// The SERVER half of Expect: 100-continue. Go sends the interim 100
// lazily — only when the handler actually reads the body — so a
// handler that rejects outright never makes the client upload.
func TestGoishRef(t *testing.T) {
	for _, tc := range []struct {
		name   string
		expect string
		read   bool
		status int
	}{
		{"reads-body", "100-continue", true, 200},
		{"rejects-unread", "100-continue", false, 401},
		{"bad-expect", "chunked-ext", false, 200},
		{"no-expect", "", true, 200},
	} {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		srv := &http.Server{Handler: http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if tc.read {
					io.ReadAll(r.Body)
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, "done")
			})}
		go srv.Serve(ln)

		c, _ := net.Dial("tcp", ln.Addr().String())
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		req := "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n"
		if tc.expect != "" {
			req += "Expect: " + tc.expect + "\r\n"
		}
		req += "Connection: close\r\n\r\n"
		fmt.Fprint(c, req)
		// Give the server a beat to decide whether to send 100 BEFORE
		// any body is written.
		time.Sleep(200 * time.Millisecond)
		interim := make([]byte, 256)
		c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _ := c.Read(interim)
		// Semantics, not bytes: the status line and whether an
		// interim 100 was sent. Header ORDER and the Date value are
		// noise here (goish sorts Connection into its header block;
		// see ROADMAP 2i), and this row is about which response the
		// server chose, not how it laid the headers out.
		earlyRaw := string(interim[:n])
		early := ""
		if i := strings.Index(earlyRaw, "\r\n"); i >= 0 {
			early = earlyRaw[:i]
		} else {
			early = earlyRaw
		}
		sent100 := strings.HasPrefix(earlyRaw, "HTTP/1.1 100 ")
		// Now send the body regardless, and read the rest.
		c.SetWriteDeadline(time.Now().Add(time.Second))
		fmt.Fprint(c, "HELLO")
		c.SetReadDeadline(time.Now().Add(time.Second))
		rest, _ := io.ReadAll(c)
		first := strings.SplitN(string(rest), "\r\n", 2)[0]
		fmt.Printf("%-14s sent100=%-5v early=%-34q then=%q\n",
			tc.name, sent100, early, first)
		c.Close()
		srv.Close()
	}
}
