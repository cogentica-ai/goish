package http_test

import (
	"fmt"
	"net/http"
	"testing"
)

// Go normalises the colon:port in NewRequest — "The host's colon:port
// should be normalized. See Issue 14836." (request.go:910). It is the
// only caller of removeEmptyPort.
func TestGoishRef(t *testing.T) {
	for _, u := range []string{
		"http://example.com/p",
		"http://example.com:/p",
		"http://example.com:80/p",
		"https://example.com:/p",
		"http://example.com:0/p",
		"http://[::1]:/p",
		"http://[::1]/p",
		"http://[::1]:8080/p",
		"http://user:pw@example.com:/p",
		"http://example.com:/",
	} {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			fmt.Printf("%-30s err=%v\n", u, err)
			continue
		}
		fmt.Printf("%-30s urlhost=%q host=%q\n", u, req.URL.Host, req.Host)
	}
}
