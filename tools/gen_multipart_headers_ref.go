package multipart

import (
	"fmt"
	"io"
	"strings"
	"testing"
)

// A part's headers go through textproto.ReadMIMEHeader (via
// populateHeaders/readMIMEHeader), which is not a CRLF split: a line
// starting with space or tab CONTINUES the previous header (RFC 5322
// obsolete folding), duplicates accumulate, and the block ends at the
// first empty line.
func TestGoishRef(t *testing.T) {
	cases := []struct{ name, hdrs string }{
		{"plain", "X: a"},
		{"folded", "X: a\r\n b"},
		{"folded-tab", "X: a\r\n\tb"},
		{"duplicate", "X: a\r\nX: b"},
		{"no-space", "X:a"},
		{"mixed-case", "x-Y: a"},
		{"fold-wide", "X: a\r\n     b"},
		{"fold-twice", "X: a\r\n b\r\n c"},
		{"fold-empty", "X: a\r\n "},
		{"fold-first", "X: \r\n b"},
	}
	for _, c := range cases {
		body := "--B\r\n" + c.hdrs + "\r\n\r\ndata\r\n--B--\r\n"
		r := NewReader(strings.NewReader(body), "B")
		p, err := r.NextPart()
		if err != nil {
			fmt.Printf("%-11s err=%v\n", c.name, err)
			continue
		}
		b, _ := io.ReadAll(p)
		fmt.Printf("%-11s x=%q vals=%v y=%q body=%q\n",
			c.name, p.Header.Get("X"), p.Header["X"], p.Header.Get("X-Y"), string(b))
	}
}
