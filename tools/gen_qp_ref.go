package quotedprintable_test

import (
	"fmt"
	"io"
	"mime/quotedprintable"
	"strings"
	"testing"
)

// mime/quotedprintable decodes a transfer encoding that arrives from
// whoever sent the mail or the multipart part. Its decoder is the one
// place in the mail path that turns arbitrary text back into arbitrary
// BYTES, so what it accepts decides what the layer above ever sees.
//
// Go's reader is deliberately LENIENT in specific, enumerated ways —
// it has to be, because real mailers emit malformed quoted-printable
// constantly — and each leniency is a decision rather than an
// oversight:
//
//   * A lone "=" that is not followed by two hex digits is passed
//     THROUGH as a literal "=" rather than refused, so a message is
//     not lost over one bad byte. Which of "=A", "=AZ", "=\n" and "="
//     at EOF are recoverable, and which are hard errors, is the part
//     no reasonable person can derive.
//   * Trailing whitespace before a newline is STRIPPED, because
//     transports add it. That means "a \n" and "a\n" decode
//     identically, and a decoder that preserves the space produces
//     different bytes for a message that hashed the same on the way
//     in.
//   * A bare CR, a lone LF and a CRLF must all end a line the same
//     way.
//   * A soft line break ("=" then newline) joins lines and produces no
//     bytes at all.
//
// The writer half is measured too, because it must wrap at 76
// characters INCLUDING the soft break, and it decides per byte whether
// to encode.
func TestGoishRef(t *testing.T) {
	decs := []struct{ name, in string }{
		{"empty", ""},
		{"plain", "hello world"},
		{"hex-upper", "=41=42=43"},
		{"hex-lower", "=61=62=63"},
		{"hex-mixed-case", "=aB=Cd"},
		{"equals-eof", "abc="},
		{"equals-one-hex-eof", "abc=4"},
		{"equals-bad-hex", "=ZZ"},
		{"equals-half-bad", "=4Z"},
		{"equals-space", "= 41"},
		{"equals-equals", "=="},
		{"soft-break-lf", "abc=\ndef"},
		{"soft-break-crlf", "abc=\r\ndef"},
		{"soft-break-eof", "abc=\n"},
		{"soft-break-cr", "abc=\rdef"},
		{"hard-break-lf", "abc\ndef"},
		{"hard-break-crlf", "abc\r\ndef"},
		{"hard-break-cr", "abc\rdef"},
		{"trailing-space", "abc   \ndef"},
		{"trailing-tab", "abc\t\t\ndef"},
		{"trailing-space-eof", "abc   "},
		{"trailing-space-crlf", "abc \r\ndef"},
		{"encoded-space-kept", "abc=20\ndef"},
		{"nul", "=00"},
		{"high-byte", "=FF=FE"},
		{"raw-high-byte", "caf\xc3\xa9"},
		{"crlf-only", "\r\n"},
		{"lf-only", "\n"},
		{"cr-only", "\r"},
		{"many-blank-lines", "a\n\n\nb"},
		{"long-line", strings.Repeat("x", 200)},
		{"equals-newline-only", "=\n"},
		{"equals-at-line-end-then-eof", "a=\r\n"},
		{"underscore", "a_b"},
		{"lowercase-hex-sep", "=3d"},
	}
	for _, c := range decs {
		r := quotedprintable.NewReader(strings.NewReader(c.in))
		out, err := io.ReadAll(r)
		fmt.Printf("dec %-28s in=%-24q -> out=%-24q err=%s\n",
			c.name, c.in, string(out), errText(err))
	}

	// One byte at a time: the reader must not depend on how the input
	// is chunked.
	for _, c := range []string{"abc=\ndef", "a=41b", "abc   \ndef", "=4"} {
		r := quotedprintable.NewReader(&iterReader{s: c})
		out, err := io.ReadAll(r)
		fmt.Printf("dec1 %-14q -> out=%-16q err=%s\n", c, string(out), errText(err))
	}

	encs := []struct{ name, in string }{
		{"empty", ""},
		{"plain", "hello world"},
		{"equals", "a=b"},
		{"high-bytes", "caf\xc3\xa9"},
		{"nul", "\x00"},
		{"tab", "a\tb"},
		{"trailing-space", "abc "},
		{"trailing-tab", "abc\t"},
		{"space-then-newline", "abc \nxyz"},
		{"newline", "a\nb"},
		{"crlf", "a\r\nb"},
		{"cr", "a\rb"},
		{"exactly-75", strings.Repeat("a", 75)},
		{"exactly-76", strings.Repeat("a", 76)},
		{"exactly-77", strings.Repeat("a", 77)},
		{"long", strings.Repeat("a", 200)},
		{"long-encoded", strings.Repeat("\xff", 40)},
		{"boundary-encoded", strings.Repeat("a", 74) + "\xff"},
		{"all-bytes", allBytes()},
	}
	for _, c := range encs {
		var sb strings.Builder
		w := quotedprintable.NewWriter(&sb)
		n, werr := w.Write([]byte(c.in))
		cerr := w.Close()
		fmt.Printf("enc %-18s -> n=%-4d out=%-40q werr=%s cerr=%s\n",
			c.name, n, sb.String(), errText(werr), errText(cerr))
		// Round trip.
		out, rerr := io.ReadAll(quotedprintable.NewReader(strings.NewReader(sb.String())))
		fmt.Printf("rt  %-18s -> same=%-5v err=%s\n",
			c.name, string(out) == c.in, errText(rerr))
	}
	// Binary mode writes bytes without any line wrapping.
	{
		var sb strings.Builder
		w := quotedprintable.NewWriter(&sb)
		w.Binary = true
		w.Write([]byte(strings.Repeat("a", 200)))
		w.Close()
		fmt.Printf("enc binary-200 -> len=%d out=%q\n", sb.Len(), sb.String()[:40])
	}
}

type iterReader struct {
	s string
	i int
}

func (r *iterReader) Read(p []byte) (int, error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	p[0] = r.s[r.i]
	r.i++
	return 1, nil
}

func allBytes() string {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return string(b)
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
