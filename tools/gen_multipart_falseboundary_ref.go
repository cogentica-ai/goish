package multipart

import (
	"fmt"
	"io"
	"strings"
	"testing"
)

// matchAfterPrefix (multipart.go:295) decides whether a run of bytes
// that STARTS like a boundary actually is one: the byte after the
// boundary must be space, tab, CR, LF or '-'. Anything else means the
// data merely resembles the boundary and the part continues. A scanner
// that matches the prefix alone truncates the part at the first
// coincidence.
func TestGoishRef(t *testing.T) {
	cases := []struct{ name, body string }{
		// The body contains "--Bxyz", which starts like the boundary
		// and is not one.
		{"false-prefix", "--B\r\nX: 1\r\n\r\nbefore\r\n--Bxyz\r\nafter\r\n--B--\r\n"},
		// Two real parts.
		{"two-parts", "--B\r\nX: 1\r\n\r\none\r\n--B\r\nX: 2\r\n\r\ntwo\r\n--B--\r\n"},
		// A body whose text ends with the boundary chars but no CRLF.
		{"trailing-dash", "--B\r\nX: 1\r\n\r\ndata--B\r\n--B--\r\n"},
	}
	for _, c := range cases {
		r := NewReader(strings.NewReader(c.body), "B")
		var out []string
		for {
			p, err := r.NextPart()
			if err != nil {
				out = append(out, fmt.Sprintf("end=%v", err))
				break
			}
			b, _ := io.ReadAll(p)
			out = append(out, fmt.Sprintf("[x=%q body=%q]", p.Header.Get("X"), string(b)))
		}
		fmt.Printf("%-14s %s\n", c.name, strings.Join(out, " "))
	}
}
