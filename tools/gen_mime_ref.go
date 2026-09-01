package mime_test

import (
	"fmt"
	"mime"
	"sort"
	"testing"
)

// ParseMediaType is what reads a Content-Type, and FormatMediaType is
// what writes one. Both have a long tail of RFC 2045/2231 behaviour —
// case folding, quoted strings, continuations, percent-encoded charsets
// — and a port that gets any of it wrong still returns a type and a
// map, so the mistake reaches the handler as a plausible value.
func TestGoishRef(t *testing.T) {
	cases := []string{
		"text/plain",
		"TEXT/PLAIN",
		"text/plain; charset=utf-8",
		"text/plain;charset=utf-8",
		"text/plain ; charset = utf-8",
		"text/plain; CHARSET=UTF-8",
		`text/plain; charset="utf-8"`,
		`form-data; name="file"; filename="a b.txt"`,
		`form-data; name=file; filename=a.txt`,
		"multipart/form-data; boundary=----WebKitFormBoundary",
		`attachment; filename="foo\"bar.txt"`,
		"text/plain; a=1; b=2; a=3",
		"text/plain;",
		"text/plain; ;",
		"text/plain; =v",
		"text/plain; k=",
		"",
		"/",
		"text",
		"text/",
		"/plain",
		"text/plain; charset",
		`text/plain; charset="unterminated`,
		"application/x-Foo+bar",
		"x-token/x-token; a*=us-ascii'en'hello%20world",
		"x-token/x-token; a*0=one; a*1=two",
		"x-token/x-token; a*0*=us-ascii'en'one; a*1=two",
		"text/plain; charset=us-ascii (Plain text)",
		"message/external-body; access-type=URL; URL*0=\"ftp://\"; URL*1=\"cs.utk.edu\"",
	}
	for _, c := range cases {
		mt, params, err := mime.ParseMediaType(c)
		keys := make([]string, 0, len(params))
		for k := range params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := ""
		for _, k := range keys {
			out += fmt.Sprintf(" %s=%q", k, params[k])
		}
		fmt.Printf("pmt %-58q mt=%-24q err=%v params=[%s]\n", c, mt, err, out)
	}

	// FormatMediaType, including the values that force quoting and the
	// ones that force an RFC 2231 continuation.
	fmts := []struct {
		t string
		p map[string]string
	}{
		{"text/plain", nil},
		{"text/plain", map[string]string{"charset": "utf-8"}},
		{"TEXT/PLAIN", map[string]string{"CHARSET": "UTF-8"}},
		{"text/plain", map[string]string{"a": "b c"}},
		{"text/plain", map[string]string{"a": `b"c`}},
		{"text/plain", map[string]string{"a": "b\\c"}},
		{"text/plain", map[string]string{"a": ""}},
		{"form-data", map[string]string{"name": "file", "filename": "a b.txt"}},
		{"text/plain", map[string]string{"a": "1", "b": "2"}},
		{"text/plain", map[string]string{"a": "héllo"}},
		{"bad type", map[string]string{}},
		{"text/plain", map[string]string{"bad key": "v"}},
		{"", map[string]string{"a": "b"}},
	}
	for _, f := range fmts {
		fmt.Printf("fmt %-12q %v -> %q\n", f.t, f.p, mime.FormatMediaType(f.t, f.p))
	}

	// The built-in extension table.
	for _, e := range []string{".html", ".HTML", ".css", ".js", ".json", ".png",
		".txt", ".xml", ".svg", ".pdf", ".nope", "", "html", ".gz", ".wasm", ".mjs"} {
		fmt.Printf("ext %-8q -> %q\n", e, mime.TypeByExtension(e))
	}
	for _, ty := range []string{"text/html", "text/html; charset=utf-8",
		"application/json", "image/png", "nope/nope"} {
		ex, err := mime.ExtensionsByType(ty)
		sort.Strings(ex)
		fmt.Printf("byType %-28q %v err=%v\n", ty, ex, err)
	}
}
