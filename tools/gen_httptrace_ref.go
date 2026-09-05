package http_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"testing"
)

// Which ClientTrace hooks fire for an ordinary plaintext GET, and in
// what order. GetConn/GotConn/WroteHeaders/WroteRequest/
// GotFirstResponseByte are called by net/http itself; the connect and
// DNS hooks come through internal/nettrace, which goish has not
// ported.
func TestGoishRef(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "hi")
		}))
	defer srv.Close()

	for _, reuse := range []bool{false, true} {
		var order []string
		trace := &httptrace.ClientTrace{
			GetConn:              func(hostPort string) { order = append(order, "GetConn") },
			GotConn:              func(i httptrace.GotConnInfo) { order = append(order, fmt.Sprintf("GotConn(reused=%v)", i.Reused)) },
			WroteHeaders:         func() { order = append(order, "WroteHeaders") },
			WroteRequest:         func(httptrace.WroteRequestInfo) { order = append(order, "WroteRequest") },
			GotFirstResponseByte: func() { order = append(order, "GotFirstResponseByte") },
			PutIdleConn:          func(error) { order = append(order, "PutIdleConn") },
		}
		c := srv.Client()
		if reuse {
			// Warm the pool so the second request reuses a conn.
			resp, _ := c.Get(srv.URL)
			io.ReadAll(resp.Body)
			resp.Body.Close()
			order = nil
		}
		req, _ := http.NewRequest("GET", srv.URL, nil)
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
		resp, err := c.Do(req)
		if err != nil {
			fmt.Printf("reuse=%-5v err=%v\n", reuse, err)
			continue
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		fmt.Printf("reuse=%-5v hooks=%v\n", reuse, order)
	}
}
