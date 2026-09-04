package http_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGoishRef(t *testing.T) {
	modtime := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	const etag = `"v1"`
	body := "hello world"

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", etag)
		http.ServeContent(w, r, "f.txt", modtime, strings.NewReader(body))
	})

	before := modtime.Add(-time.Hour).UTC().Format(http.TimeFormat)
	after := modtime.Add(time.Hour).UTC().Format(http.TimeFormat)
	exact := modtime.UTC().Format(http.TimeFormat)

	cases := []struct {
		name   string
		method string
		hdr    map[string]string
	}{
		{"plain", "GET", nil},
		{"inm-match", "GET", map[string]string{"If-None-Match": etag}},
		{"inm-star", "GET", map[string]string{"If-None-Match": "*"}},
		{"inm-nomatch", "GET", map[string]string{"If-None-Match": `"other"`}},
		{"inm-weak", "GET", map[string]string{"If-None-Match": `W/"v1"`}},
		{"inm-list", "GET", map[string]string{"If-None-Match": `"a", "v1", "b"`}},
		{"ims-after", "GET", map[string]string{"If-Modified-Since": after}},
		{"ims-exact", "GET", map[string]string{"If-Modified-Since": exact}},
		{"ims-before", "GET", map[string]string{"If-Modified-Since": before}},
		{"ims-junk", "GET", map[string]string{"If-Modified-Since": "not a date"}},
		{"inm-wins", "GET", map[string]string{"If-None-Match": `"other"`, "If-Modified-Since": after}},
		{"im-match", "GET", map[string]string{"If-Match": etag}},
		{"im-nomatch", "GET", map[string]string{"If-Match": `"other"`}},
		{"im-star", "GET", map[string]string{"If-Match": "*"}},
		{"ium-before", "GET", map[string]string{"If-Unmodified-Since": before}},
		{"ium-after", "GET", map[string]string{"If-Unmodified-Since": after}},
		{"range", "GET", map[string]string{"Range": "bytes=0-4"}},
		{"ifrange-etag-ok", "GET", map[string]string{"Range": "bytes=0-4", "If-Range": etag}},
		{"ifrange-etag-bad", "GET", map[string]string{"Range": "bytes=0-4", "If-Range": `"other"`}},
		{"ifrange-date-ok", "GET", map[string]string{"Range": "bytes=0-4", "If-Range": exact}},
		{"ifrange-date-bad", "GET", map[string]string{"Range": "bytes=0-4", "If-Range": before}},
		{"head-inm", "HEAD", map[string]string{"If-None-Match": etag}},
		{"head-plain", "HEAD", nil},
		{"post-im-nomatch", "POST", map[string]string{"If-Match": `"other"`}},
		{"inm-empty", "GET", map[string]string{"If-None-Match": ""}},
	}

	ts := httptest.NewServer(h)
	defer ts.Close()

	for _, c := range cases {
		req, _ := http.NewRequest(c.method, ts.URL+"/f.txt", nil)
		for k, v := range c.hdr {
			req.Header.Set(k, v)
		}
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		fmt.Printf("%-18s %d ct=%-24q cr=%-16q etag=%-6q lm=%v len=%d body=%q\n",
			c.name, resp.StatusCode,
			resp.Header.Get("Content-Type"),
			resp.Header.Get("Content-Range"),
			resp.Header.Get("ETag"),
			resp.Header.Get("Last-Modified") != "",
			len(b), string(b))
	}
}
