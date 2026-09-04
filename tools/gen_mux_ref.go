package http_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ServeMux decides which handler a request reaches. That is a routing
// question until an authenticating middleware is registered on one
// pattern and not another, at which point it is an authorisation
// question — a request that matches the wrong pattern skips the checks
// the right one would have applied.
//
// Go 1.22 replaced the old prefix rules with a pattern language, and
// its precedence is the part worth pinning: the MOST SPECIFIC pattern
// wins, where "specific" is defined by which pattern matches a strict
// subset of the other's requests, not by registration order and not by
// length. Two patterns that overlap without one being more specific are
// a CONFLICT and panic at registration — which is a much better failure
// than silently picking one.
//
// The other half is the path handling before matching happens: a
// request with a dot segment or a doubled slash is REDIRECTED to the
// cleaned path rather than matched against it, so a handler never sees
// "/a/../b". A mux that matched first and cleaned later would let
// "/admin/../public" reach the admin handler.
//
// Every step of that happens on the ESCAPED path, which is the detail
// worth pinning hardest. "%2F" is an encoded slash, and Go never lets
// it become a separator: it is not a separator for cleanPath, not one
// for the segment split, and a segment that unescapes to exactly "/"
// fails to match a single wildcard at all. A mux that cleaned the
// DECODED path instead would collapse "/v/%2F/2" to "/v/2" — serving
// one resource in answer to a request for a different one, which is
// the disagreement between proxy and origin that path confusion is
// made of. The "%2e%2e" and "..%2f" cases below are the same question
// asked the other way: an encoded dot segment is NOT a dot segment,
// so it survives cleaning intact and reaches the handler encoded.
func TestGoishRef(t *testing.T) {
	// 1. Precedence between overlapping patterns.
	{
		mux := http.NewServeMux()
		for _, p := range []string{
			"/", "/a", "/a/", "/a/b", "/a/{x}", "/a/{x}/c", "/b/{x...}",
			"GET /m", "POST /m", "/m/{$}", "example.com/host",
		} {
			pp := p
			mux.HandleFunc(pp, func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "%s", pp)
			})
		}
		for _, req := range []struct{ method, target string }{
			{"GET", "/"}, {"GET", "/a"}, {"GET", "/a/"}, {"GET", "/a/b"},
			{"GET", "/a/z"}, {"GET", "/a/z/c"}, {"GET", "/a/b/c"},
			{"GET", "/b/x/y/z"}, {"GET", "/b/"}, {"GET", "/m"},
			{"POST", "/m"}, {"PUT", "/m"}, {"GET", "/m/"}, {"GET", "/m/x"},
			{"GET", "/zzz"}, {"HEAD", "/m"},
		} {
			r := httptest.NewRequest(req.method, "http://other.example"+req.target, nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			_, pat := mux.Handler(r)
			fmt.Printf("route %-5s %-10s -> code=%d pat=%-12q body=%q\n",
				req.method, req.target, w.Code, pat, w.Body.String())
		}
		// A host-specific pattern only matches that host.
		for _, host := range []string{"example.com", "other.example"} {
			r := httptest.NewRequest("GET", "http://"+host+"/host", nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			fmt.Printf("host  %-14s -> code=%d body=%q\n", host, w.Code, w.Body.String())
		}
	}

	// 2. Wildcards and the values they bind.
	{
		mux := http.NewServeMux()
		mux.HandleFunc("/v/{a}/{b}", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "a=%q b=%q", r.PathValue("a"), r.PathValue("b"))
		})
		mux.HandleFunc("/w/{rest...}", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "rest=%q", r.PathValue("rest"))
		})
		for _, target := range []string{
			"/v/1/2", "/v/1", "/v/1/2/3", "/v//2", "/v/%2F/2", "/v/a%20b/c",
			"/v/%2Fx/2", "/v/%2F//x", "/v/a+b/c", "/v/%41/%42",
			"/w/", "/w/x/y", "/w", "/w/a%20b", "/w/%2F",
		} {
			r := httptest.NewRequest("GET", "http://x"+target, nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			fmt.Printf("bind  %-12s -> code=%d body=%q loc=%q\n",
				target, w.Code, w.Body.String(), w.Header().Get("Location"))
		}
	}

	// 3. Path cleaning happens BEFORE matching, as a redirect.
	{
		mux := http.NewServeMux()
		mux.HandleFunc("/clean/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "clean:%s", r.URL.Path)
		})
		mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "ADMIN")
		})
		for _, target := range []string{
			"/clean/", "/clean//x", "/clean/./x", "/clean/../admin",
			"/admin", "//admin", "/admin/", "/./admin", "/a/../admin",
			"/clean/%2e%2e/admin", "/clean/..%2fadmin", "/admin%2F",
			"/clean/%2E./admin", "/clean/x/../../admin",
		} {
			r := httptest.NewRequest("GET", "http://x"+target, nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			fmt.Printf("clean %-16s -> code=%d loc=%-18q body=%q\n",
				target, w.Code, w.Header().Get("Location"), w.Body.String())
		}
	}
}
