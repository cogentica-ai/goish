package http_test

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// Transport.Clone (transport.go:329) "returns a deep copy of t's
// exported fields" — ALL of them. The dial hooks are the ones that
// matter most if dropped: a Transport configured to reach the network
// a particular way hands its clone nothing, and the clone dials
// straight out, silently ignoring the configuration.
func TestGoishRef(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	var used int32
	tr := &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			atomic.AddInt32(&used, 1)
			return net.Dial(network, addr)
		},
	}
	clone := tr.Clone()

	c := &http.Client{Transport: clone}
	resp, err := c.Get(srv.URL)
	code := 0
	if err == nil {
		code = resp.StatusCode
		resp.Body.Close()
	}
	fmt.Printf("clone-dial used=%v status=%d err=%v\n", atomic.LoadInt32(&used) > 0, code, err)
}
