package multipart_test

import (
	"fmt"
	"mime/multipart"
	"strings"
	"testing"
)

// A single part carrying a huge number of headers. Go bounds it at
// maxMIMEHeaders (10000) and answers "message too large".
func TestGoishRef(t *testing.T) {
	for _, n := range []int{5, 9998, 10001, 50000} {
		var b strings.Builder
		b.WriteString("--B\r\n")
		b.WriteString("Content-Disposition: form-data; name=\"f\"\r\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "X-P%d: v\r\n", i)
		}
		b.WriteString("\r\nBODY\r\n--B--\r\n")

		r := multipart.NewReader(strings.NewReader(b.String()), "B")
		form, err := r.ReadForm(1 << 20)
		if err != nil {
			fmt.Printf("headers=%-6d err=%v\n", n, err)
			continue
		}
		fmt.Printf("headers=%-6d ok values=%d\n", n, len(form.Value["f"]))
	}
}
