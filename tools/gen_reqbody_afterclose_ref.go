package http_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// body.Close marks the server's request body closed, and bodyLocked.Read
// (transfer.go:1038) then answers ErrBodyReadAfterClose — "http:
// invalid Read on closed Body" — rather than handing out more bytes.
func TestGoishRef(t *testing.T) {
	var line string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first := make([]byte, 5)
		n1, e1 := r.Body.Read(first)
		cerr := r.Body.Close()
		n2, e2 := r.Body.Read(make([]byte, 5))
		line = fmt.Sprintf("read1 n=%d err=%v close=%v read-after-close n=%d err=%v",
			n1, e1, cerr, n2, e2)
	})
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Post(srv.URL, "text/plain", strings.NewReader("hello world"))
	if err != nil {
		fmt.Printf("post err=%v\n", err)
		return
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Println(line)
}
