package csv

import (
	"fmt"
	"strings"
	"testing"
)

// ParseError's message has three shapes and picks between them on
// e.Err == ErrFieldCount and e.StartLine != e.Line. All three, plus the
// quoting rules the writer applies, are what a port gets wrong quietly.
func TestGoishRef(t *testing.T) {
	for _, in := range []string{
		"a,b\nc\n",                     // wrong field count
		"a,\"b\nc\"d,e\n",              // quote error inside a multi-line field
		"a,b\"c,d\n",                   // bare quote
		"a,b\n\"unterminated\n",        // unterminated quote at EOF
	} {
		r := NewReader(strings.NewReader(in))
		_, err := r.ReadAll()
		fmt.Printf("read %-24q err=%v\n", in, err)
	}
	// Writer quoting.
	var b strings.Builder
	w := NewWriter(&b)
	w.WriteAll([][]string{
		{"plain", "with,comma", "with\"quote", "with\nnewline"},
		{" leading", "trailing ", "\ttab", "", `\.`},
		{"héllo", "a\rb"},
	})
	w.Flush()
	fmt.Printf("write %q\n", b.String())
}
