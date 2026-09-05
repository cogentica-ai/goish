package http_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// A multi-range request makes ServeContent emit multipart/byteranges.
// Go precomputes the length with rangesMIMESize because it streams the
// body through a pipe; the bytes on the wire are what matter here.
func TestGoishRef(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.txt")
	os.WriteFile(path, []byte("0123456789abcdefghijklmnopqrstuvwxyz"), 0o644)

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := &http.Server{Handler: http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			f, _ := os.Open(path)
			defer f.Close()
			http.ServeContent(w, r, "f.txt", time.Time{}, f)
		})}
	go srv.Serve(ln)
	defer srv.Close()

	for _, rng := range []string{"bytes=0-9,20-29", "bytes=0-0,5-5,10-10", "bytes=0-9"} {
		c, _ := net.Dial("tcp", ln.Addr().String())
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		fmt.Fprintf(c, "GET /f.txt HTTP/1.1\r\nHost: x\r\nRange: %s\r\nConnection: close\r\n\r\n", rng)
		raw, _ := io.ReadAll(c)
		c.Close()

		s := string(raw)
		// The boundary is random; normalise it so the shape can be
		// pinned. Go's is 60 hex chars.
		s = regexp.MustCompile(`[0-9a-f]{40,}`).ReplaceAllString(s, "BOUNDARY")
		// Date varies.
		s = regexp.MustCompile(`Date: [^\r\n]+`).ReplaceAllString(s, "Date: DATE")
		// Sort the response header block. goish emits Connection
		// inside its sorted header map; Go appends it last through
		// extraHeader. Header order is not significant in HTTP, and
		// the point of this reference is the multipart BODY, so the
		// order is normalised on both sides rather than compared.
		if i := strings.Index(s, "\r\n\r\n"); i >= 0 {
			head := strings.Split(s[:i], "\r\n")
			sort.Strings(head[1:])
			s = strings.Join(head, "\r\n") + s[i:]
		}
		s = strings.ReplaceAll(s, "\r\n", "\\r\\n")
		fmt.Printf("range=%-20s %s\n", rng, s)
	}
}
