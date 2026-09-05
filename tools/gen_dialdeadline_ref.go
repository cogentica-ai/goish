package http_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// Client.Timeout is documented to cover "connection time". 192.0.2.1
// is TEST-NET-1 (RFC 5737): the connect never completes and never
// errors, so only the timeout can end it.
func TestGoishRef(t *testing.T) {
	for _, d := range []time.Duration{500 * time.Millisecond, 2 * time.Second} {
		c := &http.Client{Timeout: d}
		start := time.Now()
		_, err := c.Get("http://192.0.2.1/x")
		took := time.Since(start)
		within := took >= d && took < d+2*time.Second
		fmt.Printf("timeout=%-6s within=%v err=%v\n", d, within, err)
	}
}
