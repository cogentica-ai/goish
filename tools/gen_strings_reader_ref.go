package strings_test

import (
	"fmt"
	"io"
	"strings"
	"testing"
)

// Reader's interesting behaviour is all in the edges: UnreadByte and
// UnreadRune are errors unless they directly follow the matching read,
// prevRune is invalidated by every other operation, Seek accepts a
// negative absolute position only as an error, and ReadAt does not move
// the read cursor at all. None of that shows up in a
// read-the-whole-thing test.
func TestGoishRef(t *testing.T) {
	const s = "héllo, 世界"

	// Len and Size as the cursor advances.
	{
		r := strings.NewReader(s)
		fmt.Printf("size %d len0 %d\n", r.Size(), r.Len())
		buf := make([]byte, 3)
		n, err := r.Read(buf)
		fmt.Printf("read n=%d buf=%q err=%v len=%d\n", n, buf[:n], err, r.Len())
		n, err = r.Read(buf)
		fmt.Printf("read n=%d buf=%q err=%v len=%d\n", n, buf[:n], err, r.Len())
	}

	// Read to exhaustion, then past it.
	{
		r := strings.NewReader("abc")
		buf := make([]byte, 2)
		for i := 0; i < 3; i++ {
			n, err := r.Read(buf)
			fmt.Printf("drain %d n=%d buf=%q err=%v\n", i, n, buf[:n], err)
		}
		// A zero-length read at EOF.
		n, err := r.Read(nil)
		fmt.Printf("drain-empty n=%d err=%v\n", n, err)
	}

	// An empty Reader.
	{
		r := strings.NewReader("")
		buf := make([]byte, 4)
		n, err := r.Read(buf)
		fmt.Printf("empty n=%d err=%v len=%d size=%d\n", n, err, r.Len(), r.Size())
	}

	// ReadByte / UnreadByte, including the error arms.
	{
		r := strings.NewReader("ab")
		fmt.Printf("unread-first %v\n", r.UnreadByte())
		c, err := r.ReadByte()
		fmt.Printf("byte %q %v\n", c, err)
		fmt.Printf("unread %v\n", r.UnreadByte())
		c, err = r.ReadByte()
		fmt.Printf("reread %q %v\n", c, err)
		c, _ = r.ReadByte()
		fmt.Printf("byte2 %q\n", c)
		_, err = r.ReadByte()
		fmt.Printf("byte-eof %v\n", err)
	}

	// ReadRune / UnreadRune, and the invalidation rule.
	{
		r := strings.NewReader("héllo")
		fmt.Printf("unreadrune-first %v\n", r.UnreadRune())
		for i := 0; i < 3; i++ {
			ch, size, err := r.ReadRune()
			fmt.Printf("rune %q size=%d err=%v\n", ch, size, err)
		}
		fmt.Printf("unreadrune %v\n", r.UnreadRune())
		ch, size, _ := r.ReadRune()
		fmt.Printf("rerune %q size=%d\n", ch, size)
		// A ReadByte between them invalidates prevRune.
		r.ReadRune()
		r.ReadByte()
		fmt.Printf("unreadrune-after-byte %v\n", r.UnreadRune())
	}

	// Invalid UTF-8 decodes to one U+FFFD of width 1.
	{
		r := strings.NewReader("\xff\xfe")
		ch, size, err := r.ReadRune()
		fmt.Printf("badrune %q size=%d err=%v\n", ch, size, err)
	}

	// Seek: all three whences, and the error arm.
	{
		type sk struct {
			off    int64
			whence int
		}
		for _, c := range []sk{
			{0, io.SeekStart}, {3, io.SeekStart}, {100, io.SeekStart}, {-1, io.SeekStart},
			{0, io.SeekEnd}, {-3, io.SeekEnd}, {-100, io.SeekEnd},
			{2, io.SeekCurrent}, {-1, io.SeekCurrent},
		} {
			r := strings.NewReader("abcdef")
			r.Read(make([]byte, 2)) // cursor at 2
			pos, err := r.Seek(c.off, c.whence)
			fmt.Printf("seek off=%-5d whence=%d -> pos=%-4d err=%v len=%d\n",
				c.off, c.whence, pos, err, r.Len())
		}
		// An unknown whence.
		r := strings.NewReader("abc")
		pos, err := r.Seek(0, 99)
		fmt.Printf("seek-bad -> pos=%d err=%v\n", pos, err)
		// Seek past the end, then read.
		r2 := strings.NewReader("abc")
		r2.Seek(10, io.SeekStart)
		n, err := r2.Read(make([]byte, 4))
		fmt.Printf("seek-past-read n=%d err=%v len=%d\n", n, err, r2.Len())
	}

	// ReadAt does not move the cursor, and reports io.EOF on a short read.
	{
		r := strings.NewReader("abcdef")
		r.Read(make([]byte, 2))
		for _, off := range []int64{0, 4, 5, 6, 7, -1} {
			buf := make([]byte, 3)
			n, err := r.ReadAt(buf, off)
			fmt.Printf("readat off=%-3d n=%d buf=%q err=%v cursor-len=%d\n",
				off, n, buf[:n], err, r.Len())
		}
	}

	// WriteTo drains from the cursor and reports how much it wrote.
	{
		r := strings.NewReader("abcdef")
		r.Read(make([]byte, 2))
		var sb strings.Builder
		n, err := r.WriteTo(&sb)
		fmt.Printf("writeto n=%d out=%q err=%v len=%d\n", n, sb.String(), err, r.Len())
		// A second WriteTo has nothing left.
		var sb2 strings.Builder
		n, err = r.WriteTo(&sb2)
		fmt.Printf("writeto2 n=%d out=%q err=%v\n", n, sb2.String(), err)
	}

	// Reset re-arms the Reader, including prevRune.
	{
		r := strings.NewReader("abc")
		r.ReadRune()
		r.Reset("xyz")
		fmt.Printf("reset len=%d size=%d unreadrune=%v\n", r.Len(), r.Size(), r.UnreadRune())
		b, _ := r.ReadByte()
		fmt.Printf("reset-read %q\n", b)
	}

	// Builder: Len and Cap as it grows, and the four writers.
	{
		var b strings.Builder
		fmt.Printf("builder empty len=%d str=%q\n", b.Len(), b.String())
		b.WriteString("hé")
		n, _ := b.Write([]byte("llo"))
		fmt.Printf("builder write n=%d len=%d str=%q\n", n, b.Len(), b.String())
		b.WriteByte('!')
		nr, _ := b.WriteRune('世')
		fmt.Printf("builder rune n=%d len=%d str=%q\n", nr, b.Len(), b.String())
		// An invalid rune writes U+FFFD.
		nr, _ = b.WriteRune(0x110000)
		fmt.Printf("builder badrune n=%d str=%q\n", nr, b.String())
		b.Reset()
		fmt.Printf("builder reset len=%d str=%q\n", b.Len(), b.String())
	}
	{
		var b strings.Builder
		b.Grow(64)
		fmt.Printf("builder grow len=%d cap>=64 %v\n", b.Len(), b.Cap() >= 64)
	}
}
