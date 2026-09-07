package multipart

import (
	"fmt"
	"io"
	"strings"
	"testing"
)

// RFC 2046 5.1: the boundary delimiter line is two hyphens, the
// boundary, "optional linear whitespace, and a terminating CRLF".
// Go honours that with skipLWSPChar on both the delimiter line
// (multipart.go:isBoundaryDelimiterLine) and the final one
// (isFinalBoundary). A sender that pads its boundaries is producing
// valid multipart, and a reader that scans for an exact match will
// see no parts at all.
func TestGoishRef(t *testing.T) {
	cases := []struct {
		name, body string
	}{
		{"plain", "--B\r\nX: 1\r\n\r\nhello\r\n--B--\r\n"},
		{"lwsp-delim", "--B \r\nX: 1\r\n\r\nhello\r\n--B--\r\n"},
		{"lwsp-final", "--B\r\nX: 1\r\n\r\nhello\r\n--B-- \r\n"},
		{"lwsp-both", "--B \t\r\nX: 1\r\n\r\nhello\r\n--B-- \t\r\n"},
		// Go: "our lines are ending in \n instead of \r\n ... a
		// violation of the spec, but occurs in practice".
		{"lf-only", "--B\nX: 1\n\nhello\n--B--\n"},
		// RFC 2046: everything before the first boundary is preamble
		// and must be discarded, not returned as a part.
		{"preamble", "ignore me\r\n--B\r\nX: 1\r\n\r\nhello\r\n--B--\r\n"},
		{"no-headers", "--B\r\n\r\nhello\r\n--B--\r\n"},
		{"empty-body", "--B\r\nX: 1\r\n\r\n\r\n--B--\r\n"},
	}
	for _, c := range cases {
		r := NewReader(strings.NewReader(c.body), "B")
		p, err := r.NextPart()
		if err != nil {
			fmt.Printf("%-10s err=%v\n", c.name, err)
			continue
		}
		b, _ := io.ReadAll(p)
		_, err2 := r.NextPart()
		fmt.Printf("%-10s body=%q x=%q next=%v\n", c.name, string(b), p.Header.Get("X"), err2)
	}
}
