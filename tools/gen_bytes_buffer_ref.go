package bytes_test

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
)

// Buffer's growth is three steps and only the last allocates: reset
// when the buffer is logically empty but off has walked forward, try a
// reslice into capacity already owned, then either slide the live bytes
// down over the consumed prefix or double. The observable consequences
// are Len/Cap/Available after a write-drain-write cycle, and the fact
// that Grow(n) leaves Len alone while guaranteeing n bytes of headroom.
func TestGoishRef(t *testing.T) {
	// Lengths and capacities through a write / read / write cycle.
	{
		var b bytes.Buffer
		fmt.Printf("zero len=%d cap=%d avail=%d str=%q\n", b.Len(), b.Cap(), b.Available(), b.String())
		b.WriteString("hello")
		fmt.Printf("w1 len=%d str=%q bytes=%q\n", b.Len(), b.String(), b.Bytes())
		p := make([]byte, 3)
		n, err := b.Read(p)
		fmt.Printf("r1 n=%d p=%q err=%v len=%d str=%q\n", n, p[:n], err, b.Len(), b.String())
		b.WriteString(" world")
		fmt.Printf("w2 len=%d str=%q\n", b.Len(), b.String())
		out, err := io.ReadAll(&b)
		fmt.Printf("drain %q err=%v len=%d\n", out, err, b.Len())
		n, err = b.Read(p)
		fmt.Printf("r-empty n=%d err=%v\n", n, err)
	}

	// Grow leaves Len alone and guarantees headroom.
	{
		var b bytes.Buffer
		b.WriteString("abc")
		b.Grow(100)
		fmt.Printf("grow len=%d avail>=100 %v str=%q\n", b.Len(), b.Available() >= 100, b.String())
		var c bytes.Buffer
		c.Grow(0)
		fmt.Printf("grow0 len=%d\n", c.Len())
	}

	// Truncate and Reset.
	{
		b := bytes.NewBufferString("abcdef")
		b.Truncate(3)
		fmt.Printf("trunc len=%d str=%q\n", b.Len(), b.String())
		b.Truncate(0)
		fmt.Printf("trunc0 len=%d str=%q\n", b.Len(), b.String())
		b2 := bytes.NewBufferString("abcdef")
		b2.Read(make([]byte, 2))
		b2.Truncate(1)
		fmt.Printf("trunc-after-read len=%d str=%q\n", b2.Len(), b2.String())
		b2.Reset()
		fmt.Printf("reset len=%d str=%q\n", b2.Len(), b2.String())
	}

	// Next, and asking for more than there is.
	{
		b := bytes.NewBufferString("abcdef")
		fmt.Printf("next3 %q len=%d\n", b.Next(3), b.Len())
		fmt.Printf("next99 %q len=%d\n", b.Next(99), b.Len())
		fmt.Printf("next-empty %q\n", b.Next(1))
	}

	// ReadByte / UnreadByte / ReadRune / UnreadRune, with the error arms.
	{
		b := bytes.NewBufferString("héllo")
		fmt.Printf("unread-first %v\n", b.UnreadByte())
		c, err := b.ReadByte()
		fmt.Printf("byte %q %v unread=%v\n", c, err, b.UnreadByte())
		r, size, err := b.ReadRune()
		fmt.Printf("rune %q size=%d err=%v\n", r, size, err)
		r, size, _ = b.ReadRune()
		fmt.Printf("rune2 %q size=%d\n", r, size)
		fmt.Printf("unreadrune %v\n", b.UnreadRune())
		r, size, _ = b.ReadRune()
		fmt.Printf("rerune %q size=%d\n", r, size)
		// A ReadByte between them invalidates the unread.
		b.ReadRune()
		b.ReadByte()
		fmt.Printf("unreadrune-after-byte %v\n", b.UnreadRune())
		// Drain, then the EOF arms.
		io.ReadAll(b)
		_, err = b.ReadByte()
		fmt.Printf("byte-eof %v\n", err)
		_, _, err = b.ReadRune()
		fmt.Printf("rune-eof %v\n", err)
	}

	// ReadBytes / ReadString, including the no-delimiter arm.
	{
		b := bytes.NewBufferString("one\ntwo\nthree")
		for i := 0; i < 4; i++ {
			line, err := b.ReadBytes('\n')
			fmt.Printf("readbytes %d %q err=%v\n", i, line, err)
		}
		c := bytes.NewBufferString("a,b")
		s, err := c.ReadString(',')
		fmt.Printf("readstring1 %q err=%v\n", s, err)
		s, err = c.ReadString(',')
		fmt.Printf("readstring2 %q err=%v\n", s, err)
	}

	// WriteTo drains; WriteRune writes the encoded width.
	{
		b := bytes.NewBufferString("abcdef")
		b.Read(make([]byte, 2))
		var sb strings.Builder
		n, err := b.WriteTo(&sb)
		fmt.Printf("writeto n=%d out=%q err=%v len=%d\n", n, sb.String(), err, b.Len())
		var c bytes.Buffer
		nr, _ := c.WriteRune('世')
		nr2, _ := c.WriteRune('a')
		fmt.Printf("writerune %d %d str=%q len=%d\n", nr, nr2, c.String(), c.Len())
	}

	// ReadFrom appends and reports the count.
	{
		b := bytes.NewBufferString("pre-")
		n, err := b.ReadFrom(strings.NewReader("body"))
		fmt.Printf("readfrom n=%d str=%q err=%v\n", n, b.String(), err)
		n, err = b.ReadFrom(strings.NewReader(""))
		fmt.Printf("readfrom-empty n=%d err=%v\n", n, err)
	}

	// NewBuffer takes ownership of the slice it is given.
	{
		b := bytes.NewBuffer([]byte("seed"))
		fmt.Printf("newbuffer len=%d str=%q\n", b.Len(), b.String())
		b.WriteString("+more")
		fmt.Printf("newbuffer2 str=%q\n", b.String())
		c := bytes.NewBuffer(nil)
		fmt.Printf("newbuffer-nil len=%d str=%q\n", c.Len(), c.String())
	}
}
