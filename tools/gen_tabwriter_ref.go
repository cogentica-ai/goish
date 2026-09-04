package tabwriter_test

import (
	"bytes"
	"fmt"
	"testing"
	"text/tabwriter"
)

// tabwriter aligns columns, and every one of its rules is about where a
// COLUMN ENDS rather than about spacing. That is what makes it easy to
// get subtly wrong while the common case still looks aligned:
//
//   * A "column block" is a run of ADJACENT lines that all have a cell
//     in that position. A line with fewer cells TERMINATES the block,
//     so the lines above and below it are widened independently. A port
//     that widens the whole output to one global width produces
//     something that looks fine until a short line appears in the
//     middle.
//   * The LAST cell of a line is not part of any column — it has no
//     trailing tab, so it never contributes to a width.
//   * Widths are counted in RUNES, not bytes, so a column of CJK text
//     lines up with an ASCII one by character count.
//   * minwidth, tabwidth and padding interact: the width of a column is
//     max(minwidth, widest cell + padding), and with padchar '\t' the
//     output is tab-terminated instead of space-padded, which makes
//     tabwidth the unit.
//   * AlignRight, DiscardEmptyColumns, TabIndent, FilterHTML,
//     StripEscape and Debug each change the answer, and
//     DiscardEmptyColumns only discards a column that is empty in
//     EVERY line of its block — and only for tab-terminated cells.
func TestGoishRef(t *testing.T) {
	inputs := []struct {
		name string
		in   string
	}{
		{"simple", "a\tbb\tccc\n1\t2\t3\n"},
		{"ragged", "a\tbb\tccc\nlonger\tx\n1\t2\t3\n"},
		{"short-line-splits", "aaa\tb\nx\nccccc\td\n"},
		{"trailing-tab", "a\tb\t\nc\td\t\n"},
		{"empty-cells", "a\t\tc\nd\t\tf\n"},
		{"one-column", "a\nbb\nccc\n"},
		{"no-newline", "a\tb"},
		{"empty", ""},
		{"blank-line", "a\tb\n\nc\td\n"},
		{"cjk", "日本\tx\nab\ty\n"},
		{"wide-first", "aaaaaaaa\tb\nc\td\n"},
	}
	configs := []struct {
		name                        string
		minwidth, tabwidth, padding int
		padchar                     byte
		flags                       uint
	}{
		{"default", 0, 8, 1, ' ', 0},
		{"min5", 5, 8, 1, ' ', 0},
		{"pad3", 0, 8, 3, ' ', 0},
		{"dots", 0, 8, 1, '.', 0},
		{"tabpad", 0, 4, 1, '\t', 0},
		{"alignright", 0, 8, 1, ' ', tabwriter.AlignRight},
		{"debug", 0, 8, 1, ' ', tabwriter.Debug},
		{"tabindent", 0, 4, 1, '\t', tabwriter.TabIndent},
		{"discardempty", 0, 8, 1, ' ', tabwriter.DiscardEmptyColumns},
	}
	for _, cfg := range configs {
		for _, in := range inputs {
			var buf bytes.Buffer
			w := tabwriter.NewWriter(&buf, cfg.minwidth, cfg.tabwidth,
				cfg.padding, cfg.padchar, cfg.flags)
			w.Write([]byte(in.in))
			err := w.Flush()
			fmt.Printf("tw %-13s %-18s -> %q err=%v\n",
				cfg.name, in.name, buf.String(), errText(err))
		}
	}

	// Escape and FilterHTML, which change what counts as a cell's width.
	// NOTE: string(tabwriter.Escape) would convert the BYTE 0xff to a
	// RUNE and encode it as two bytes, so the writer would never see an
	// escape at all. The escape must be built as a byte.
	esc := string([]byte{tabwriter.Escape})
	for _, c := range []struct {
		name  string
		in    string
		flags uint
	}{
		{"html-off", "a<b>c\tx\ndd\ty\n", 0},
		{"html-on", "a<b>c\tx\ndd\ty\n", tabwriter.FilterHTML},
		{"entity-on", "a&amp;b\tx\ndd\ty\n", tabwriter.FilterHTML},
		{"escaped", esc + "a\tb" + esc + "\tx\ncc\ty\n", 0},
		{"escaped-strip", esc + "a\tb" + esc + "\tx\ncc\ty\n", tabwriter.StripEscape},
	} {
		var buf bytes.Buffer
		w := tabwriter.NewWriter(&buf, 0, 8, 1, ' ', c.flags)
		w.Write([]byte(c.in))
		err := w.Flush()
		fmt.Printf("esc %-14s -> %q err=%v\n", c.name, buf.String(), errText(err))
	}

	// Incremental writes must produce the same output as one write.
	{
		full := "aaa\tb\nc\tddd\n"
		var one, many bytes.Buffer
		w1 := tabwriter.NewWriter(&one, 0, 8, 1, ' ', 0)
		w1.Write([]byte(full))
		w1.Flush()
		w2 := tabwriter.NewWriter(&many, 0, 8, 1, ' ', 0)
		for i := 0; i < len(full); i++ {
			w2.Write([]byte{full[i]})
		}
		w2.Flush()
		fmt.Printf("incremental same=%v out=%q\n", one.String() == many.String(), many.String())
	}

	// Flush twice, and write after a flush.
	{
		var buf bytes.Buffer
		w := tabwriter.NewWriter(&buf, 0, 8, 1, ' ', 0)
		w.Write([]byte("a\tb\n"))
		w.Flush()
		w.Flush()
		w.Write([]byte("cc\tdd\n"))
		w.Flush()
		fmt.Printf("reflush out=%q\n", buf.String())
	}
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
