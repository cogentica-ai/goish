package http_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func dump(label string, rec *httptest.ResponseRecorder) {
	h := rec.Header()
	ct := h.Get("Content-Type")
	loc := h.Get("Location")
	ns := h.Get("X-Content-Type-Options")
	body := rec.Body.String()
	fmt.Printf("%-26s code=%d ct=%q loc=%q nosniff=%q body=%q\n", label, rec.Code, ct, loc, ns, body)
}

func TestGoishRef(t *testing.T) {
	// ── http.Error ──
	for _, tc := range []struct {
		name, msg string
		code      int
	}{
		{"error-plain", "boom", 500},
		{"error-html", "<script>x</script>", 400},
		{"error-empty", "", 404},
		{"error-newline", "a\nb", 500},
	} {
		rec := httptest.NewRecorder()
		http.Error(rec, tc.msg, tc.code)
		dump(tc.name, rec)
	}

	// ── http.Redirect: the URL reaches an HTML body, so escaping matters ──
	for _, tc := range []struct {
		name, url string
		code      int
		method    string
	}{
		{"redirect-simple", "/x", 302, "GET"},
		{"redirect-quote", `/x"><script>alert(1)</script>`, 302, "GET"},
		{"redirect-amp", "/x?a=1&b=2", 302, "GET"},
		{"redirect-abs", "https://example.com/x", 301, "GET"},
		{"redirect-post", "/x", 303, "POST"},
		{"redirect-307", "/x", 307, "GET"},
		{"redirect-empty", "", 302, "GET"},
		{"redirect-rel-dots", "../x", 302, "GET"},
		{"redirect-newline", "/x\r\nSet-Cookie: a=b", 302, "GET"},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, "/dir/page", nil)
		http.Redirect(rec, req, tc.url, tc.code)
		dump(tc.name, rec)
	}

	// ── Redirect with non-ASCII in the target ──
	//
	// Go escapes every byte >= 0x80 in the Location HEADER
	// (hexEscapeNonASCII) and leaves the <a href> body unescaped apart
	// from HTML entities, so the two disagree on purpose. Space and
	// DEL stay raw in both — the rule is >= 0x80, not "non-printable".
	for _, tc := range []struct{ name, url string }{
		{"redirect-utf8", "/café"},
		{"redirect-utf8-query", "/s?q=été"},
		{"redirect-raw-high", "/\xff\xfe"},
		{"redirect-space", "/a b"},
		{"redirect-del", "/a\x7fb"},
		{"redirect-abs-utf8", "https://example.com/ü"},
		{"redirect-pct-already", "/caf%C3%A9"},
	} {
		rec := httptest.NewRecorder()
		http.Redirect(rec, httptest.NewRequest("GET", "/dir/page", nil), tc.url, 302)
		dump(tc.name, rec)
	}

	// Content-Type PRESENT but empty: Go tests key presence, so it
	// neither overwrites the header nor writes the HTML body.
	{
		rec := httptest.NewRecorder()
		rec.Header().Set("Content-Type", "")
		http.Redirect(rec, httptest.NewRequest("GET", "/dir/page", nil), "/x", 302)
		dump("redirect-empty-ct", rec)
	}

	// ── NotFound ──
	rec := httptest.NewRecorder()
	http.NotFound(rec, httptest.NewRequest("GET", "/nope", nil))
	dump("notfound", rec)

	// ── StripPrefix ──
	for _, tc := range []struct{ name, prefix, path string }{
		{"strip-match", "/api", "/api/v1/x"},
		{"strip-nomatch", "/api", "/other/x"},
		{"strip-exact", "/api", "/api"},
		{"strip-empty", "", "/x"},
		{"strip-escaped", "/a b", "/a%20b/c"},
	} {
		rec := httptest.NewRecorder()
		h := http.StripPrefix(tc.prefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "path=%q rawpath=%q", r.URL.Path, r.URL.RawPath)
		}))
		h.ServeHTTP(rec, httptest.NewRequest("GET", tc.path, nil))
		dump(tc.name, rec)
	}

	// ── MaxBytesHandler ──
	for _, tc := range []struct {
		name string
		n    int64
		body string
	}{
		{"maxbytes-under", 10, "abc"},
		{"maxbytes-over", 2, "abcdef"},
	} {
		rec := httptest.NewRecorder()
		h := http.MaxBytesHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, err := io.ReadAll(r.Body)
			fmt.Fprintf(w, "read=%q err=%v", string(b), err)
		}), tc.n)
		req := httptest.NewRequest("POST", "/x", strings.NewReader(tc.body))
		h.ServeHTTP(rec, req)
		dump(tc.name, rec)
	}
}
