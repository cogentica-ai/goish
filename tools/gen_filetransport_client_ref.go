package http_test

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// The end-to-end path from filetransport.go's own doc comment:
// t.RegisterProtocol("file", NewFileTransport(Dir(dir))) and then an
// ordinary Client.Get of a file:// URL.
func TestGoishRef(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello\n"), 0o644)
	os.Mkdir(filepath.Join(dir, "sub"), 0o755)

	tr := &http.Transport{}
	tr.RegisterProtocol("file", http.NewFileTransport(http.Dir(dir)))
	c := &http.Client{Transport: tr}

	for _, u := range []string{
		"file:///a.txt",
		"file:///missing.txt",
		"file:///sub",
		"file:///../etc/passwd",
	} {
		resp, err := c.Get(u)
		if err != nil {
			fmt.Printf("%-24s err=%v\n", u, err)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		body := string(b)
		if len(body) > 24 {
			body = body[:24] + "..."
		}
		fmt.Printf("%-24s status=%d ct=%q body=%q\n", u, resp.StatusCode,
			resp.Header.Get("Content-Type"), body)
	}
}
