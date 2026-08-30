package multipart

import (
	"bytes"
	"fmt"
	"net/textproto"
	"testing"
)

// The writer's output is fully determined once SetBoundary fixes the
// boundary, so everything below is byte-exact. The parts worth pinning
// are the ones a reimplementation gets subtly wrong: headers are
// emitted in sorted key order, the *first* part has no leading CRLF but
// every later one does, Close always writes the terminating line even
// with no parts at all, and a field name containing a quote or a
// backslash is escaped inside the Content-Disposition value.
func TestGoishRef(t *testing.T) {
	// SetBoundary's accept/reject table.
	boundaries := []string{
		"",
		"x",
		"abcDEF012",
		"'()+_,-./:=?",
		"has space",
		"trailing ",
		" leading",
		"has\ttab",
		"has\"quote",
		"has@at",
		"0123456789012345678901234567890123456789012345678901234567890123456789",  // 70
		"01234567890123456789012345678901234567890123456789012345678901234567890", // 71
	}
	for _, b := range boundaries {
		w := NewWriter(&bytes.Buffer{})
		err := w.SetBoundary(b)
		fmt.Printf("setboundary %-72q err=%v\n", b, err)
	}

	// SetBoundary after a part has been created.
	{
		w := NewWriter(&bytes.Buffer{})
		w.SetBoundary("B")
		w.CreateFormField("f")
		fmt.Printf("setboundary-late err=%v\n", w.SetBoundary("C"))
	}

	// FormDataContentType quoting.
	for _, b := range []string{"simple", "has space", "has=eq", "has(paren", "abcDEF012"} {
		w := NewWriter(&bytes.Buffer{})
		if err := w.SetBoundary(b); err != nil {
			fmt.Printf("contenttype %-12q setboundary-err=%v\n", b, err)
			continue
		}
		fmt.Printf("contenttype %-12q -> %q\n", b, w.FormDataContentType())
	}

	// A full message: two fields, a file, and a raw part with several
	// headers given out of order.
	{
		var buf bytes.Buffer
		w := NewWriter(&buf)
		w.SetBoundary("BOUNDARY")
		w.WriteField("alpha", "one")
		w.WriteField(`we"ird\name`, "two")
		fw, _ := w.CreateFormFile("upload", `my"file\.txt`)
		fw.Write([]byte("FILE BODY"))
		h := make(textproto.MIMEHeader)
		h.Set("Z-Last", "z")
		h.Set("A-First", "a")
		h.Add("A-First", "a2")
		h.Set("M-Middle", "m")
		pw, _ := w.CreatePart(h)
		pw.Write([]byte("raw body"))
		err := w.Close()
		fmt.Printf("message err=%v\n%q\n", err, buf.String())
	}

	// Close with no parts at all.
	{
		var buf bytes.Buffer
		w := NewWriter(&buf)
		w.SetBoundary("B")
		err := w.Close()
		fmt.Printf("empty-close err=%v %q\n", err, buf.String())
	}

	// Writing to a part after the next one starts.
	{
		var buf bytes.Buffer
		w := NewWriter(&buf)
		w.SetBoundary("B")
		p1, _ := w.CreateFormField("one")
		p1.Write([]byte("first"))
		_, _ = w.CreateFormField("two")
		n, err := p1.Write([]byte("late"))
		fmt.Printf("write-after-next n=%d err=%v\n", n, err)
	}

	// FileContentDisposition on its own.
	fmt.Printf("filecd %q\n", FileContentDisposition("field", "name.txt"))
	fmt.Printf("filecd-esc %q\n", FileContentDisposition(`a"b`, `c\d`))

	// randomBoundary shape: 60 lower-hex characters, and two calls differ.
	{
		a, b := randomBoundary(), randomBoundary()
		fmt.Printf("randomboundary len=%d distinct=%v\n", len(a), a != b)
	}
}
