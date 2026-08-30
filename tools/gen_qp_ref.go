package quotedprintable

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
)

// The reader's four documented deviations from RFC 2045 are all about
// what it *tolerates*, so the interesting cases are the malformed ones:
// a bare '=' at end of message, an '=' not followed by two hex digits,
// trailing whitespace before a soft line break, and a raw control byte.
// Each has its own error text, and the text is the part a name-only
// port cannot get right by accident.
func TestGoishRef(t *testing.T) {
	readCases := []string{
		"",
		"foo bar",
		"foo bar=3D",
		"foo bar=\n",
		"foo bar\n",
		"foo bar=0",
		"foo bar=0D=0A",
		" A B        \r\n C ",
		"foo=\r\nbar",
		"foo=\rbar",
		"foo=\n\nbar",
		"foo\r\n",
		"foo\r\n\r\n",
		"=0good=1",
		"=00",
		"=0",
		"=",
		"=A",
		"=at",
		"=\r\n",
		"=\n",
		"a=b",
		"a=0\n",
		"=3D=3D",
		"foo\x00bar",
		"foo\x7fbar",
		"foo\x80bar",
		"foo bar\r\nbaz\r\n",
		"foo   \r\nbar",
		"foo=  \r\nbar",
		"foo=  x\r\nbar",
		"foo=\t\r\nbar",
		"\n\n",
		"=e1=e2=E3=E4=e5",
		"Warum ist es t=?",
	}
	for _, in := range readCases {
		out, err := io.ReadAll(NewReader(strings.NewReader(in)))
		fmt.Printf("read %-24q -> %-24q err=%v\n", in, string(out), err)
	}

	writeCases := []struct {
		in     string
		binary bool
	}{
		{"", false},
		{"foo bar", false},
		{"foo bar\r\n", false},
		{"foo bar ", false},
		{"foo bar\t", false},
		{"=", false},
		{"\x00\x01\x02", false},
		{"foo\r\nbar", false},
		{"foo\rbar", false},
		{"foo\nbar", false},
		{"foo\r\nbar", true},
		{"foo\rbar", true},
		{"foo\nbar", true},
		{strings.Repeat("a", 75), false},
		{strings.Repeat("a", 76), false},
		{strings.Repeat("a", 77), false},
		{strings.Repeat("a", 100), false},
		{strings.Repeat("=", 20), false},
		{strings.Repeat("é", 10), false},
		{"a" + strings.Repeat(" ", 80) + "b", false},
		{"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed feugiat.", false},
		{"foo \r\nbar", false},
		{"foo \t\r\nbar", false},
		{"foo\r\n bar", false},
	}
	for _, wc := range writeCases {
		var buf bytes.Buffer
		w := NewWriter(&buf)
		w.Binary = wc.binary
		w.Write([]byte(wc.in))
		err := w.Close()
		label := wc.in
		if len(label) > 20 {
			label = label[:17] + "..."
		}
		fmt.Printf("write bin=%-5v %-24q -> %q err=%v\n", wc.binary, label, buf.String(), err)
	}

	// Byte-at-a-time writes must give the same result as one Write.
	for _, wc := range writeCases {
		var buf bytes.Buffer
		w := NewWriter(&buf)
		w.Binary = wc.binary
		for i := 0; i < len(wc.in); i++ {
			w.Write([]byte(wc.in[i : i+1]))
		}
		w.Close()
		label := wc.in
		if len(label) > 20 {
			label = label[:17] + "..."
		}
		fmt.Printf("write1 bin=%-5v %-24q -> %q\n", wc.binary, label, buf.String())
	}

	// Round-trip: everything the writer emits, the reader must accept.
	for _, wc := range writeCases {
		var buf bytes.Buffer
		w := NewWriter(&buf)
		w.Binary = wc.binary
		w.Write([]byte(wc.in))
		w.Close()
		out, err := io.ReadAll(NewReader(bytes.NewReader(buf.Bytes())))
		fmt.Printf("roundtrip bin=%-5v ok=%-5v err=%v\n", wc.binary, string(out) == strings.ReplaceAll(strings.ReplaceAll(wc.in, "\r\n", "\r\n"), "", ""), err)
		_ = out
	}

	// The exact error texts.
	_, e1 := fromHex('z')
	fmt.Printf("fromHex-err %v\n", e1)
	_, e2 := readHexByte([]byte("a"))
	fmt.Printf("readHexByte-short %v\n", e2)
	_, e3 := readHexByte([]byte("zz"))
	fmt.Printf("readHexByte-bad %v\n", e3)
}
