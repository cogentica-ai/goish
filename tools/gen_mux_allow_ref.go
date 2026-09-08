package http_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ServeMux.matchingMethods (server.go:2831) builds the Allow header of
// a 405. It runs the tree match TWICE: once for the path as given and
// again with a trailing slash added, "because matchOrRedirect will try
// appending a trailing slash if there is no match". A pattern
// registered only as "POST /x/" is therefore an allowed method for a
// GET of "/x".
func TestGoishRef(t *testing.T) {
	mux := http.NewServeMux()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	mux.Handle("POST /x/", h)
	mux.Handle("GET /y", h)
	mux.Handle("PUT /y", h)
	mux.Handle("GET /z/", h)

	for _, c := range []struct{ method, path string }{
		{"GET", "/x"},
		{"GET", "/x/"},
		{"DELETE", "/y"},
		{"POST", "/y/"},
		// Guard: the method DOES match here, so this must stay a
		// redirect to /z/ and never become a 405.
		{"GET", "/z"},
	} {
		req := httptest.NewRequest(c.method, c.path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		fmt.Printf("%-6s %-4s status=%d allow=%q loc=%q\n",
			c.method, c.path, w.Code, w.Header().Get("Allow"), w.Header().Get("Location"))
	}
}
