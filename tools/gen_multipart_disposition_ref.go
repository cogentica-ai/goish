package multipart

import (
	"fmt"
	"strings"
	"testing"
)

// FormName is empty unless the disposition is exactly "form-data"
// (multipart.go:76), and FileName applies filepath.Base because
// "RFC 7578, Section 4.2 requires that if a filename is provided, the
// directory path information must not be used" (multipart.go:99) —
// the defence against a part named ../../etc/passwd.
func TestGoishRef(t *testing.T) {
	cases := []struct{ name, cd string }{
		{"form-data", `form-data; name="f"; filename="a.txt"`},
		{"attachment", `attachment; name="f"; filename="a.txt"`},
		{"traversal", `form-data; name="f"; filename="../../etc/passwd"`},
		{"abs-path", `form-data; name="f"; filename="/etc/passwd"`},
		{"windows", `form-data; name="f"; filename="C:\dir\a.txt"`},
		{"no-filename", `form-data; name="f"`},
		{"dot-dot", `form-data; name="f"; filename=".."`},
	}
	for _, c := range cases {
		body := "--B\r\nContent-Disposition: " + c.cd + "\r\n\r\nx\r\n--B--\r\n"
		r := NewReader(strings.NewReader(body), "B")
		p, err := r.NextPart()
		if err != nil {
			fmt.Printf("%-12s err=%v\n", c.name, err)
			continue
		}
		fmt.Printf("%-12s form=%q file=%q\n", c.name, p.FormName(), p.FileName())
	}
}
