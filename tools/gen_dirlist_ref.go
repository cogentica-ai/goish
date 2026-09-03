package http_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoishRef(t *testing.T) {
	dir := t.TempDir()
	// Filenames that exercise the escaping in dirList.
	names := []string{
		"plain.txt",
		"with space.txt",
		`<script>alert(1).txt`,
		`quote"and'apos.txt`,
		"amp&sym.txt",
		"héllo.txt",
		"hash#frag.txt",
		"question?q=1.txt",
		"percent%20.txt",
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "index.html"), []byte("INDEX"), 0o644); err != nil {
		t.Fatal(err)
	}

	fs := http.FileServer(http.Dir(dir))
	ts := httptest.NewServer(fs)
	defer ts.Close()

	// The listing itself, verbatim — this is the escaping surface.
	resp, err := ts.Client().Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.Contains(ln, "<a href=") {
			fmt.Printf("list %q\n", strings.TrimSpace(ln))
		}
	}
	fmt.Printf("list-ct %q\n", resp.Header.Get("Content-Type"))

	// Path handling. No redirects followed, so the 301s are visible.
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for _, p := range []string{
		"/plain.txt",
		"/sub",
		"/sub/",
		"/sub/index.html",
		"/../etc/passwd",
		"/..%2fetc%2fpasswd",
		"/%2e%2e/etc/passwd",
		"/./plain.txt",
		"//plain.txt",
		"/nonexistent.txt",
		"/plain.txt/",
		"/with%20space.txt",
		"/h%C3%A9llo.txt",
	} {
		resp, err := client.Get(ts.URL + p)
		if err != nil {
			fmt.Printf("path %-22q err=%v\n", p, err)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		body := string(b)
		if len(body) > 24 {
			body = body[:24]
		}
		fmt.Printf("path %-22q %d loc=%-12q body=%q\n",
			p, resp.StatusCode, resp.Header.Get("Location"), body)
	}
}
