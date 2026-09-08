package http_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
)

func TestGoishRef(t *testing.T) {
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "yes")
		w.Header().Set("Connection", "X-Secret")
		w.Header().Set("X-Secret", "leak")
		if r.URL.Path == "/redir" {
			http.Redirect(w, r, "http://elsewhere.invalid/", http.StatusFound)
			return
		}
		fmt.Fprintf(w, "xff=%q ua=%q up=%q", r.Header.Get("X-Forwarded-For"),
			r.Header.Get("User-Agent"), r.Header.Get("X-Rewritten"))
	}))
	defer back.Close()
	tgt, _ := url.Parse(back.URL)

	probe := func(label string, rp *httputil.ReverseProxy, path string) {
		front := httptest.NewServer(rp)
		defer front.Close()
		c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		req, _ := http.NewRequest("GET", front.URL+path, nil)
		req.Header.Set("User-Agent", "")
		resp, err := c.Do(req)
		if err != nil {
			fmt.Printf("%-16s err=%v\n", label, err)
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		fmt.Printf("%-16s code=%d backend=%q secret=%q mod=%q body=%s\n",
			label, resp.StatusCode, resp.Header.Get("X-Backend"),
			resp.Header.Get("X-Secret"), resp.Header.Get("X-Modified"),
			strings.TrimSpace(string(b)))
	}

	probe("director", &httputil.ReverseProxy{Director: func(r *http.Request) {
		r.URL.Scheme = tgt.Scheme
		r.URL.Host = tgt.Host
	}}, "/")

	probe("rewrite", &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(tgt)
		pr.Out.Header.Set("X-Rewritten", "1")
	}}, "/")

	probe("modifyresponse", &httputil.ReverseProxy{
		Director: func(r *http.Request) { r.URL.Scheme = tgt.Scheme; r.URL.Host = tgt.Host },
		ModifyResponse: func(res *http.Response) error {
			res.Header.Set("X-Modified", "yes")
			return nil
		},
	}, "/")

	probe("modify-error", &httputil.ReverseProxy{
		Director: func(r *http.Request) { r.URL.Scheme = tgt.Scheme; r.URL.Host = tgt.Host },
		ModifyResponse: func(res *http.Response) error {
			return fmt.Errorf("nope")
		},
	}, "/")

	probe("errorhandler", &httputil.ReverseProxy{
		Director: func(r *http.Request) { r.URL.Scheme = tgt.Scheme; r.URL.Host = tgt.Host },
		ModifyResponse: func(res *http.Response) error { return fmt.Errorf("nope") },
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			w.WriteHeader(http.StatusTeapot)
		},
	}, "/")

	probe("relays-3xx", &httputil.ReverseProxy{Director: func(r *http.Request) {
		r.URL.Scheme = tgt.Scheme
		r.URL.Host = tgt.Host
	}}, "/redir")

	probe("both-set", &httputil.ReverseProxy{
		Director: func(r *http.Request) {},
		Rewrite:  func(pr *httputil.ProxyRequest) {},
	}, "/")
}
