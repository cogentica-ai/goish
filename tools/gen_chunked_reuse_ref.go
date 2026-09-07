package http_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// bodyEOFSignal.Close (transport.go:3012) banks the connection for
// reuse unless the body ended early: `if es.earlyCloseFn != nil &&
// es.rerr != io.EOF`. Reaching io.EOF is what makes a conn reusable —
// not the FRAMING it used. A chunked response read to the end is as
// reusable as a Content-Length one.
func TestGoishRef(t *testing.T) {
	var conns int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No Content-Length + a Flush = chunked.
		w.Write([]byte("part-one "))
		w.(http.Flusher).Flush()
		w.Write([]byte("part-two"))
	}))
	srv.Config.ConnState = func(c net.Conn, s http.ConnState) {
		if s == http.StateNew {
			atomic.AddInt32(&conns, 1)
		}
	}
	srv.Start()
	defer srv.Close()

	c := srv.Client()
	for i := 0; i < 3; i++ {
		resp, err := c.Get(srv.URL)
		if err != nil {
			fmt.Printf("get %d err=%v\n", i, err)
			return
		}
		b, _ := io.ReadAll(resp.Body)
		te := "none"
		if len(resp.TransferEncoding) > 0 {
			te = resp.TransferEncoding[0]
		}
		resp.Body.Close()
		if i == 0 {
			fmt.Printf("body=%q te=%s\n", string(b), te)
		}
	}
	fmt.Printf("three chunked requests opened %d connection(s)\n", atomic.LoadInt32(&conns))

	// The same thing with a REAL trailer section. This is the case
	// that decides whether consuming trailers is done right: if the
	// trailer lines are left on the wire, the next response on that
	// connection starts mid-trailer and parses as garbage.
	var tconns int32
	tsrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Checksum")
		w.Write([]byte("with-trailer"))
		w.(http.Flusher).Flush()
		w.Header().Set("X-Checksum", "abc123")
	}))
	tsrv.Config.ConnState = func(c net.Conn, s http.ConnState) {
		if s == http.StateNew {
			atomic.AddInt32(&tconns, 1)
		}
	}
	tsrv.Start()
	defer tsrv.Close()

	tc := tsrv.Client()
	for i := 0; i < 3; i++ {
		resp, err := tc.Get(tsrv.URL)
		if err != nil {
			fmt.Printf("trailer get %d err=%v\n", i, err)
			return
		}
		b, rerr := io.ReadAll(resp.Body)
		resp.Body.Close()
		fmt.Printf("trailer req %d body=%q err=%v\n", i, string(b), rerr)
	}
	fmt.Printf("three trailered requests opened %d connection(s)\n", atomic.LoadInt32(&tconns))
}
