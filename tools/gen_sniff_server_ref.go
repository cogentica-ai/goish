package http_test

import (
	"fmt"
	"io"
	"net/http"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
)

type tc struct {
	name string
	fn   func(w http.ResponseWriter)
}

func TestGoishRef(t *testing.T) {
	cases := []tc{
		{"html-no-ct", func(w http.ResponseWriter) { io.WriteString(w, "<html><body>hi</body></html>") }},
		{"text-no-ct", func(w http.ResponseWriter) { io.WriteString(w, "just some words") }},
		{"empty-no-ct", func(w http.ResponseWriter) {}},
		{"png-no-ct", func(w http.ResponseWriter) { w.Write([]byte("\x89PNG\r\n\x1a\ndata")) }},
		{"gif-no-ct", func(w http.ResponseWriter) { w.Write([]byte("GIF89a....")) }},
		{"pdf-no-ct", func(w http.ResponseWriter) { w.Write([]byte("%PDF-1.7\n%%EOF")) }},
		{"json-no-ct", func(w http.ResponseWriter) { io.WriteString(w, `{"a":1}`) }},
		{"xml-no-ct", func(w http.ResponseWriter) { io.WriteString(w, `<?xml version="1.0"?><r/>`) }},
		{"explicit-ct", func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/vnd.custom")
			io.WriteString(w, "<html>ignored</html>")
		}},
		{"nosniff-no-ct", func(w http.ResponseWriter) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			io.WriteString(w, "<html><body>hi</body></html>")
		}},
		{"two-writes", func(w http.ResponseWriter) {
			io.WriteString(w, "<html>")
			io.WriteString(w, "\x89PNG\r\n\x1a\n")
		}},
		{"lead-ws-html", func(w http.ResponseWriter) { io.WriteString(w, "  \n\t<html>x</html>") }},
		{"204-no-body", func(w http.ResponseWriter) { w.WriteHeader(204) }},
		{"304-no-body", func(w http.ResponseWriter) { w.WriteHeader(304) }},
		{"utf8-bom", func(w http.ResponseWriter) { w.Write([]byte("\xef\xbb\xbfhello")) }},
		{"binary-junk", func(w http.ResponseWriter) { w.Write([]byte{0x00, 0x01, 0x02, 0x03, 0xff}) }},
		{"flush-then-html", func(w http.ResponseWriter) {
			io.WriteString(w, "<html>")
			w.(http.Flusher).Flush()
			io.WriteString(w, "</html>")
		}},
		{"explicit-te", func(w http.ResponseWriter) {
			w.Header().Set("Transfer-Encoding", "chunked")
			io.WriteString(w, "<html>x</html>")
		}},
		{"empty-ct", func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "")
			io.WriteString(w, "<html>x</html>")
		}},
		{"big-body", func(w http.ResponseWriter) {
			w.Write(append([]byte(strings.Repeat(" ", 600)), []byte("<html>x</html>")...))
		}},
		{"ct-after-write", func(w http.ResponseWriter) {
			io.WriteString(w, "<html>x</html>")
			w.Header().Set("Content-Type", "application/too-late")
		}},
		{"304-with-hdrs", func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Length", "99")
			w.Header().Set("Transfer-Encoding", "chunked")
			w.WriteHeader(304)
		}},
		{"cl-too-big", func(w http.ResponseWriter) {
			w.Header().Set("Content-Length", "100")
			io.WriteString(w, "short")
		}},
		{"cl-too-small", func(w http.ResponseWriter) {
			w.Header().Set("Content-Length", "2")
			io.WriteString(w, "much longer body")
		}},
		{"own-date", func(w http.ResponseWriter) {
			w.Header().Set("Date", "Mon, 01 Jan 2001 00:00:00 GMT")
			io.WriteString(w, "x")
		}},
		{"gzip-ce", func(w http.ResponseWriter) {
			w.Header().Set("Content-Encoding", "gzip")
			io.WriteString(w, "<html>x</html>")
		}},
		{"wh200-then-html", func(w http.ResponseWriter) {
			w.WriteHeader(200)
			io.WriteString(w, "<html>x</html>")
		}},
	}

	mux := http.NewServeMux()
	for _, c := range cases {
		c := c
		mux.HandleFunc("/"+c.name, func(w http.ResponseWriter, r *http.Request) { c.fn(w) })
	}
	ts := httptest.NewServer(mux)
	defer ts.Close()
	addr := strings.TrimPrefix(ts.URL, "http://")

	hdr := func(raw, name string) string {
		for _, ln := range strings.Split(raw, "\r\n") {
			if ln == "" {
				break
			}
			if strings.HasPrefix(strings.ToLower(ln), strings.ToLower(name)+":") {
				return strings.TrimSpace(ln[len(name)+1:])
			}
		}
		return "-"
	}

	for _, c := range cases {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "GET /%s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", c.name)
		b, _ := io.ReadAll(io.LimitReader(conn, 8192))
		conn.Close()
		raw := string(b)
		d := hdr(raw, "Date")
		if d != "-" {
			d = "<present>"
		}
		fmt.Printf("%-16s ct=%-31s cl=%-4s te=%-8s date=%s\n",
			c.name, hdr(raw, "Content-Type"), hdr(raw, "Content-Length"), hdr(raw, "Transfer-Encoding"), d)
		switch c.name {
		case "cl-too-big", "cl-too-small", "own-date", "304-with-hdrs":
			fmt.Printf("      raw: %q\n", raw)
		}
	}
}
