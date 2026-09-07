package multipart

import (
	"fmt"
	"io"
	"strings"
	"testing"
)

// NextPart hides a quoted-printable Content-Transfer-Encoding and
// decodes the body during Read (multipart.go:368-373); NextRawPart
// does neither (multipart.go:375-382). Part itself is an io.Reader
// either way, which is how callers copy a part into a file.
func TestGoishRef(t *testing.T) {
	const body = "--B\r\n" +
		"Content-Disposition: form-data; name=\"f\"\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"\r\n" +
		"a=3Db\r\n" +
		"--B--\r\n"

	r := NewReader(strings.NewReader(body), "B")
	p, err := r.NextPart()
	if err != nil {
		fmt.Printf("NextPart err=%v\n", err)
		return
	}
	b, _ := io.ReadAll(p)
	fmt.Printf("NextPart    body=%q cte=%q\n", string(b), p.Header.Get("Content-Transfer-Encoding"))

	r2 := NewReader(strings.NewReader(body), "B")
	p2, err2 := r2.NextRawPart()
	if err2 != nil {
		fmt.Printf("NextRawPart err=%v\n", err2)
		return
	}
	b2, _ := io.ReadAll(p2)
	fmt.Printf("NextRawPart body=%q cte=%q\n", string(b2), p2.Header.Get("Content-Transfer-Encoding"))

	// Part.Read in small bites, to show it is a reader and not one shot.
	r3 := NewReader(strings.NewReader(body), "B")
	p3, _ := r3.NextRawPart()
	buf := make([]byte, 2)
	n1, e1 := p3.Read(buf)
	s1 := string(buf[:n1]) // capture BEFORE the next Read reuses buf
	n2, e2 := p3.Read(buf)
	s2 := string(buf[:n2])
	fmt.Printf("Part.Read   n1=%d %q e1=%v n2=%d %q e2=%v\n", n1, s1, e1, n2, s2, e2)
}
