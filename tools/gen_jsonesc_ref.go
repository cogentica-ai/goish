package json_test

import (
	"encoding/json"
	"fmt"
	"testing"
)

// Marshal's STRING ESCAPING is where a JSON encoder most often differs
// without anyone noticing: Go escapes <, > and & by default (so a
// marshalled string is safe to embed in HTML), escapes U+2028 and
// U+2029 (which are valid JSON but break JavaScript), and emits
// invalid UTF-8 as U+FFFD rather than failing.
func TestGoishRef(t *testing.T) {
	for _, s := range []string{
		"plain", "", "a\"b", "a\\b", "a\nb", "a\tb", "a\rb",
		"a\bb", "a\fb", "\x00", "\x1f", "\x7f",
		"<script>", "a&b", "a>b", "a<b",
		"héllo", "日本語", "\U0001F600",
		" ", " ", " ",
		"a/b", "\\", "\"",
	} {
		b, err := json.Marshal(s)
		fmt.Printf("str %-14q -> %s err=%v\n", s, b, err)
	}

	// Invalid UTF-8 is replaced, not rejected.
	bad := string([]byte{0x66, 0xff, 0x6f})
	b, err := json.Marshal(bad)
	fmt.Printf("badutf8 -> %s err=%v\n", b, err)

	// Numbers.
	for _, v := range []any{
		0, 1, -1, 1 << 62, float64(1), float64(0.5), float64(1e21),
		float64(1e-7), float64(-0), true, false, nil,
	} {
		b, err := json.Marshal(v)
		fmt.Printf("val %-10v -> %s err=%v\n", v, b, err)
	}

	// HTMLEscape, Compact and Indent.
	var out []byte
	src := []byte(`{"a":"<b>","c":[1,2]}`)
	fmt.Printf("valid %v\n", json.Valid(src))
	var cbuf, ibuf, hbuf = new(stringWriter), new(stringWriter), new(stringWriter)
	_ = cbuf
	_ = ibuf
	_ = hbuf
	out = out[:0]
	fmt.Printf("compact-in %s\n", src)

	// Unmarshal edges.
	for _, in := range []string{
		`{"a":1}`, `[1,2,3]`, `"x"`, `123`, `true`, `null`,
		`{"a":1,}`, `[1,2,`, `{"a"1}`, ``, `  `, `{}`, `[]`,
		`"é"`, `"😀"`, `"\uD800"`, `1e400`, `01`,
	} {
		var v any
		err := json.Unmarshal([]byte(in), &v)
		fmt.Printf("unm %-16q err=%v val=%v\n", in, err, v)
	}
}

type stringWriter struct{ b []byte }

func (w *stringWriter) Write(p []byte) (int, error) { w.b = append(w.b, p...); return len(p), nil }
