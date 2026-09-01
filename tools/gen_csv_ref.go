package csv_test

import (
	"encoding/csv"
	"fmt"
	"strings"
	"testing"
)

// A CSV reader is a parser with a long tail: a quote inside a quoted
// field, a bare quote in a bare field, a record whose field count
// changes, CRLF versus LF, a comment line, and leading space that may
// or may not be significant. Every one of them has a defined answer in
// Go and every wrong one still yields records.
func TestGoishRef(t *testing.T) {
	type C struct {
		in       string
		comma    rune
		comment  rune
		fields   int
		lazy     bool
		trim     bool
		reuse    bool
	}
	cases := []C{
		{in: "a,b,c\n"},
		{in: "a,b,c"},
		{in: "a,b,c\r\n"},
		{in: "a,b,c\nd,e,f\n"},
		{in: ""},
		{in: "\n"},
		{in: "\n\n"},
		{in: "a\n\nb\n"},
		{in: `"a","b"`},
		{in: `"a""b"`},
		{in: `"a
b"`},
		{in: `"a,b",c`},
		{in: `a,"b`},
		{in: `a,b"c`},
		{in: `a,"b"c`},
		{in: `a,"b"c`, lazy: true},
		{in: `a,b"c`, lazy: true},
		{in: `a,"b`, lazy: true},
		{in: "a,b\nc\n"},
		{in: "a,b\nc\n", fields: -1},
		{in: "a,b\nc,d,e\n"},
		{in: "a;b;c\n", comma: ';'},
		{in: "a\tb\n", comma: '\t'},
		{in: "#x\na,b\n", comment: '#'},
		{in: "a,b\n#x\nc,d\n", comment: '#'},
		{in: " a, b\n"},
		{in: " a, b\n", trim: true},
		{in: `a, "b"`},
		{in: `a, "b"`, trim: true},
		{in: "a,,b\n"},
		{in: ",\n"},
		{in: "a,b,\n"},
		{in: "\"\"\n"},
		{in: "a\r\rb\n"},
		{in: "a,b\r\nc,d\r\n"},
		{in: "\xef\xbb\xbfa,b\n"},
	}
	for i, c := range cases {
		r := csv.NewReader(strings.NewReader(c.in))
		if c.comma != 0 {
			r.Comma = c.comma
		}
		if c.comment != 0 {
			r.Comment = c.comment
		}
		if c.fields != 0 {
			r.FieldsPerRecord = c.fields
		}
		r.LazyQuotes = c.lazy
		r.TrimLeadingSpace = c.trim
		recs, err := r.ReadAll()
		fmt.Printf("read %2d %-22q lazy=%-5v trim=%-5v comma=%-3q comment=%-3q fpr=%-3d -> %q err=%v\n",
			i, c.in, c.lazy, c.trim, c.comma, c.comment, c.fields, recs, err)
	}

	// FieldPos and InputOffset after a couple of reads.
	r := csv.NewReader(strings.NewReader("a,b\nccc,d\n"))
	rec, _ := r.Read()
	l0, c0 := r.FieldPos(0)
	l1, c1 := r.FieldPos(1)
	fmt.Printf("pos rec=%q f0=(%d,%d) f1=(%d,%d) off=%d\n", rec, l0, c0, l1, c1, r.InputOffset())
	rec, _ = r.Read()
	l0, c0 = r.FieldPos(0)
	fmt.Printf("pos rec=%q f0=(%d,%d) off=%d\n", rec, l0, c0, r.InputOffset())

	// Writer: the quoting rules.
	for _, rec := range [][]string{
		{"a", "b"}, {"a,b", "c"}, {`a"b`}, {"a\nb"}, {"a\rb"}, {" a"}, {"a "},
		{""}, {"", ""}, {"\\."}, {"a\tb"}, {"héllo"},
	} {
		var sb strings.Builder
		w := csv.NewWriter(&sb)
		w.Write(rec)
		w.Flush()
		fmt.Printf("write %-14q -> %q err=%v\n", rec, sb.String(), w.Error())
	}
	// A non-default Comma, and UseCRLF.
	{
		var sb strings.Builder
		w := csv.NewWriter(&sb)
		w.Comma = ';'
		w.Write([]string{"a", "b;c"})
		w.Flush()
		fmt.Printf("write-semi -> %q\n", sb.String())
	}
	{
		var sb strings.Builder
		w := csv.NewWriter(&sb)
		w.UseCRLF = true
		w.WriteAll([][]string{{"a", "b"}, {"c", "d"}})
		fmt.Printf("write-crlf -> %q\n", sb.String())
	}
	{
		var sb strings.Builder
		w := csv.NewWriter(&sb)
		err := w.Write([]string{"a\nb"})
		w.Comma = '"'
		err2 := w.Write([]string{"x"})
		w.Flush()
		fmt.Printf("write-err %v %v -> %q\n", err, err2, sb.String())
	}
}
