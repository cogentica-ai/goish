package bytes_test

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
)

// Reader's behaviour is all in the edges: UnreadByte and UnreadRune are
// errors unless they directly follow the matching read, prevRune is
// invalidated by every other operation, Seek accepts a position past
// the end but not a negative one, and ReadAt never moves the cursor.
// The rest of the tree only ever reads a bytes.Reader to exhaustion.
func TestGoishRef(t *testing.T) {
	const s = "héllo, 世界"

	{
		r := bytes.NewReader([]byte(s))
		fmt.Printf("size %d len0 %d\n", r.Size(), r.Len())
		buf := make([]byte, 3)
		n, err := r.Read(buf)
		fmt.Printf("read n=%d buf=%q err=%v len=%d\n", n, buf[:n], err, r.Len())
		n, err = r.Read(buf)
		fmt.Printf("read n=%d buf=%q err=%v len=%d\n", n, buf[:n], err, r.Len())
	}

	{
		r := bytes.NewReader([]byte("abc"))
		buf := make([]byte, 2)
		for i := 0; i < 3; i++ {
			n, err := r.Read(buf)
			fmt.Printf("drain %d n=%d buf=%q err=%v\n", i, n, buf[:n], err)
		}
	}

	{
		r := bytes.NewReader(nil)
		buf := make([]byte, 4)
		n, err := r.Read(buf)
		fmt.Printf("empty n=%d err=%v len=%d size=%d\n", n, err, r.Len(), r.Size())
	}

	{
		r := bytes.NewReader([]byte("ab"))
		fmt.Printf("unread-first %v\n", r.UnreadByte())
		c, err := r.ReadByte()
		fmt.Printf("byte %q %v\n", c, err)
		fmt.Printf("unread %v\n", r.UnreadByte())
		c, _ = r.ReadByte()
		fmt.Printf("reread %q\n", c)
		c, _ = r.ReadByte()
		fmt.Printf("byte2 %q\n", c)
		_, err = r.ReadByte()
		fmt.Printf("byte-eof %v\n", err)
	}

	{
		r := bytes.NewReader([]byte("héllo"))
		fmt.Printf("unreadrune-first %v\n", r.UnreadRune())
		for i := 0; i < 3; i++ {
			ch, size, err := r.ReadRune()
			fmt.Printf("rune %q size=%d err=%v\n", ch, size, err)
		}
		fmt.Printf("unreadrune %v\n", r.UnreadRune())
		ch, size, _ := r.ReadRune()
		fmt.Printf("rerune %q size=%d\n", ch, size)
		r.ReadRune()
		r.ReadByte()
		fmt.Printf("unreadrune-after-byte %v\n", r.UnreadRune())
	}

	{
		r := bytes.NewReader([]byte("\xff\xfe"))
		ch, size, err := r.ReadRune()
		fmt.Printf("badrune %q size=%d err=%v\n", ch, size, err)
	}

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
			r := bytes.NewReader([]byte("abcdef"))
			r.Read(make([]byte, 2))
			pos, err := r.Seek(c.off, c.whence)
			fmt.Printf("seek off=%-5d whence=%d -> pos=%-4d err=%v len=%d\n",
				c.off, c.whence, pos, err, r.Len())
		}
		r := bytes.NewReader([]byte("abc"))
		pos, err := r.Seek(0, 99)
		fmt.Printf("seek-bad -> pos=%d err=%v\n", pos, err)
		r2 := bytes.NewReader([]byte("abc"))
		r2.Seek(10, io.SeekStart)
		n, err := r2.Read(make([]byte, 4))
		fmt.Printf("seek-past-read n=%d err=%v len=%d\n", n, err, r2.Len())
	}

	{
		r := bytes.NewReader([]byte("abcdef"))
		r.Read(make([]byte, 2))
		for _, off := range []int64{0, 4, 5, 6, 7, -1} {
			buf := make([]byte, 3)
			n, err := r.ReadAt(buf, off)
			fmt.Printf("readat off=%-3d n=%d buf=%q err=%v cursor-len=%d\n",
				off, n, buf[:n], err, r.Len())
		}
	}

	{
		r := bytes.NewReader([]byte("abcdef"))
		r.Read(make([]byte, 2))
		var sb strings.Builder
		n, err := r.WriteTo(&sb)
		fmt.Printf("writeto n=%d out=%q err=%v len=%d\n", n, sb.String(), err, r.Len())
		var sb2 strings.Builder
		n, err = r.WriteTo(&sb2)
		fmt.Printf("writeto2 n=%d out=%q err=%v\n", n, sb2.String(), err)
	}

	{
		r := bytes.NewReader([]byte("abc"))
		r.ReadRune()
		r.Reset([]byte("xyz"))
		fmt.Printf("reset len=%d size=%d unreadrune=%v\n", r.Len(), r.Size(), r.UnreadRune())
		b, _ := r.ReadByte()
		fmt.Printf("reset-read %q\n", b)
	}
}
