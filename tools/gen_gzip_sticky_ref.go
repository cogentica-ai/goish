package http_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The transport wraps a gzip-encoded response in `gzipReader`, whose
// `zerr` is documented "any error from gzip.NewReader; sticky". The
// stickiness is the whole point: a body that failed to gunzip must
// keep reporting that failure, and must NOT decay into EOF, or a
// caller that reads again after an error sees a corrupt response as a
// complete empty one. The check also precedes the closed flag, so the
// error survives Close.
func TestGoishRef(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write([]byte("not gzip at all, just bytes"))
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	for i := 1; i <= 3; i++ {
		n, e := resp.Body.Read(buf)
		fmt.Printf("read%d n=%d err=%v\n", i, n, e)
	}
	resp.Body.Close()
	n, e := resp.Body.Read(buf)
	fmt.Printf("after close n=%d err=%v\n", n, e)
}
