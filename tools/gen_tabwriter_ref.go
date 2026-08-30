package tabwriter

import (
	"bytes"
	"fmt"
	"testing"
)

func TestGoishRef(t *testing.T) {
	run := func(name string, minwidth, tabwidth, padding int, padchar byte, flags uint, in string) {
		var buf bytes.Buffer
		w := NewWriter(&buf, minwidth, tabwidth, padding, padchar, flags)
		fmt.Fprint(w, in)
		w.Flush()
		fmt.Printf("%-18s %q\n", name, buf.String())
	}
	in := "a\tbbb\tcc\nddddd\te\tfff\n"
	run("default", 0, 8, 1, ' ', 0, in)
	run("minwidth5", 5, 8, 1, ' ', 0, in)
	run("padding3", 0, 8, 3, ' ', 0, in)
	run("alignright", 0, 8, 1, ' ', AlignRight, in)
	run("tabindent", 0, 8, 1, '\t', TabIndent, in)
	run("debug", 0, 8, 1, ' ', Debug, in)
	run("discardempty", 0, 8, 1, ' ', DiscardEmptyColumns, "a\t\tb\nc\t\td\n")
	run("ragged", 0, 8, 1, ' ', 0, "a\tb\tc\nd\te\n f\n")
	run("trailing-nonl", 0, 8, 1, ' ', 0, "a\tb\tc")
	run("empty", 0, 8, 1, ' ', 0, "")
	run("vertical-tab", 0, 8, 1, ' ', 0, "a\vb\tc\n")
	run("formfeed", 0, 8, 1, ' ', 0, "a\tb\n\fcc\tdd\n")
	run("html", 0, 8, 1, ' ', FilterHTML, "a\t<b>bb</b>\tc\nddd\te\tf\n")
	run("escape", 0, 8, 1, ' ', 0, "a\t\xffb\tb\xff\tc\n1\t2\t3\n")
	run("stripescape", 0, 8, 1, ' ', StripEscape, "a\t\xffb\tb\xff\tc\n1\t2\t3\n")
	run("unicode", 0, 8, 1, ' ', 0, "é\tab\ncdé\tx\n")
}
