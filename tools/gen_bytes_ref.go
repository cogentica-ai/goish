package bytes_test

import (
	"bytes"
	"fmt"
	"io"
	"testing"
	"unicode"
)

// bytes mirrors strings, but on a type that CAN hold invalid UTF-8 —
// which is the whole reason it exists separately, and the half a port
// is least likely to have exercised. Every rune-oriented function here
// has defined behaviour on a malformed encoding, and it is never "skip
// it": a bad byte decodes as RuneError with width 1, so it participates
// in Map, in the Trim cutsets, in EqualFold and in Runes as a real
// element. Getting that wrong turns a byte slice from the network into
// a different slice, silently.
//
// Buffer is the other half. It is a Reader and a Writer at once, with a
// read cursor that Truncate and Reset move and that Next and UnreadByte
// step, and Go pins several behaviours that look like implementation
// detail until something depends on them: Read on an empty buffer
// returns io.EOF only when the caller asked for bytes, an empty
// buffer's String() is "" and not "<nil>", and Truncate panics rather
// than clamping.
func TestGoishRef(t *testing.T) {
	bad := []byte{'a', 0xff, 'b'}
	badSeq := []byte{0xe6, 0x97, 0xa5, 0xff, 0xe8, 0xaa, 0x9e} // 日 <bad> 語

	// 1. The rune-oriented functions over invalid UTF-8.
	fmt.Printf("runes bad=%q -> %q\n", bad, bytes.Runes(bad))
	fmt.Printf("runes badseq=%q -> %q\n", badSeq, bytes.Runes(badSeq))
	fmt.Printf("tovalid bad=%q -> %q %q\n", bad,
		bytes.ToValidUTF8(bad, []byte("?")), bytes.ToValidUTF8(bad, nil))
	fmt.Printf("tovalid badseq=%q -> %q\n", badSeq, bytes.ToValidUTF8(badSeq, []byte("!")))
	fmt.Printf("map upper bad=%q -> %q\n", bad, bytes.Map(unicode.ToUpper, bad))
	fmt.Printf("map drop bad=%q -> %q\n", bad, bytes.Map(func(r rune) rune {
		if r == 0xFFFD {
			return -1
		}
		return r
	}, bad))
	fmt.Printf("case bad lower=%q upper=%q title=%q\n",
		bytes.ToLower(bad), bytes.ToUpper(bad), bytes.Title(bad))
	fmt.Printf("valid bad=%v badseq=%v good=%v\n",
		bytes.ContainsRune(bad, 0xFFFD), bytes.ContainsRune(badSeq, 0xFFFD),
		bytes.ContainsRune([]byte("日本"), '本'))

	// 2. Index family over invalid UTF-8 and multi-byte cutsets.
	for _, c := range []struct{ s, sub []byte }{
		{bad, []byte{0xff}}, {bad, []byte("b")}, {badSeq, []byte("日")},
		{badSeq, []byte{0xff}}, {[]byte("日本語"), []byte("本")},
		{[]byte(""), []byte("")}, {[]byte("abc"), []byte("")},
	} {
		fmt.Printf("index %-12q %-8q -> idx=%-3d last=%-3d count=%d\n",
			c.s, c.sub, bytes.Index(c.s, c.sub), bytes.LastIndex(c.s, c.sub),
			bytes.Count(c.s, c.sub))
	}
	for _, c := range []struct{ s, chars []byte }{
		{[]byte("日本語"), []byte("本語")}, {bad, []byte("ab")},
		{bad, []byte("�")}, {badSeq, []byte("語")}, {[]byte("abc"), []byte("")},
	} {
		fmt.Printf("indexany %-12q %-10q -> any=%-3d lastany=%d\n",
			c.s, c.chars, bytes.IndexAny(c.s, string(c.chars)), bytes.LastIndexAny(c.s, string(c.chars)))
	}
	for _, r := range []rune{'b', 0xFFFD, '日', 0x110000} {
		fmt.Printf("indexrune bad=%q r=%-9q -> %d  badseq -> %d\n",
			bad, r, bytes.IndexRune(bad, r), bytes.IndexRune(badSeq, r))
	}

	// 3. Split family, including the empty separator over invalid input.
	for _, c := range []struct{ s, sep []byte }{
		{[]byte("a,b,c"), []byte(",")}, {bad, nil}, {badSeq, nil},
		{[]byte(""), []byte(",")}, {[]byte(""), nil}, {[]byte("日本"), nil},
	} {
		fmt.Printf("split %-14q %-4q -> %q  after=%q\n", c.s, c.sep,
			bytes.Split(c.s, c.sep), bytes.SplitAfter(c.s, c.sep))
	}
	for _, n := range []int{-1, 0, 1, 2, 10} {
		fmt.Printf("splitn n=%-3d -> %q  after=%q\n", n,
			bytes.SplitN([]byte("a,b,c,d"), []byte(","), n),
			bytes.SplitAfterN([]byte("a,b,c,d"), []byte(","), n))
	}

	// 4. Trim and Fields over invalid UTF-8.
	for _, c := range []struct{ s, cut []byte }{
		{bad, []byte("ab")}, {bad, []byte("�")}, {badSeq, []byte("日語")},
		{[]byte("xxhixx"), []byte("x")}, {[]byte("  hi  "), nil},
	} {
		fmt.Printf("trim %-12q %-10q -> t=%-12q l=%-12q r=%-12q\n",
			c.s, c.cut, bytes.Trim(c.s, string(c.cut)),
			bytes.TrimLeft(c.s, string(c.cut)), bytes.TrimRight(c.s, string(c.cut)))
	}
	fmt.Printf("trimspace bad=%q badseq=%q sp=%q\n",
		bytes.TrimSpace(bad), bytes.TrimSpace(badSeq),
		bytes.TrimSpace([]byte(" \t hi \n ")))
	for _, s := range [][]byte{bad, badSeq, []byte("  a b  "), []byte(""), nil} {
		fmt.Printf("fields %-14q -> %q\n", s, bytes.Fields(s))
	}

	// 5. Equal / EqualFold / Compare, with nil against empty.
	for _, p := range [][2][]byte{
		{nil, {}}, {nil, nil}, {{}, {}}, {[]byte("a"), []byte("A")},
		{bad, bad}, {bad, []byte{'a', 0xfe, 'b'}}, {[]byte("K"), []byte("K")},
		{[]byte("ß"), []byte("ss")},
	} {
		fmt.Printf("eq %-12q %-12q -> equal=%-5v fold=%-5v cmp=%d\n",
			p[0], p[1], bytes.Equal(p[0], p[1]), bytes.EqualFold(p[0], p[1]),
			bytes.Compare(p[0], p[1]))
	}

	// 6. Buffer: the read cursor, and what Read reports at the end.
	{
		var b bytes.Buffer
		fmt.Printf("buf zero len=%d cap=%d str=%q\n", b.Len(), b.Cap(), b.String())
		b.WriteString("hello world")
		fmt.Printf("buf write len=%d str=%q\n", b.Len(), b.String())
		p := make([]byte, 5)
		n, err := b.Read(p)
		fmt.Printf("buf read n=%d err=%v p=%q rest=%q len=%d\n",
			n, err, p[:n], b.String(), b.Len())
		fmt.Printf("buf next3=%q rest=%q\n", b.Next(3), b.String())
		c, err := b.ReadByte()
		fmt.Printf("buf readbyte=%q err=%v rest=%q\n", c, err, b.String())
		err = b.UnreadByte()
		fmt.Printf("buf unread err=%v rest=%q\n", err, b.String())
		// Drain, then read again: n=0 with io.EOF, but only for len(p)>0.
		rest := make([]byte, 64)
		n, err = b.Read(rest)
		fmt.Printf("buf drain n=%d err=%v empty=%q\n", n, err, b.String())
		n, err = b.Read(rest)
		fmt.Printf("buf read-empty n=%d err=%v\n", n, err)
		n, err = b.Read(nil)
		fmt.Printf("buf read-nil n=%d err=%v\n", n, err)
		_, err = b.ReadByte()
		fmt.Printf("buf readbyte-empty err=%v\n", err)
	}
	{
		var b bytes.Buffer
		b.WriteString("abcdefghij")
		b.Truncate(4)
		fmt.Printf("trunc4 %q len=%d\n", b.String(), b.Len())
		b.Truncate(0)
		fmt.Printf("trunc0 %q len=%d\n", b.String(), b.Len())
		b.WriteString("xyz")
		b.Reset()
		fmt.Printf("reset %q len=%d\n", b.String(), b.Len())
	}
	{
		var b bytes.Buffer
		b.WriteString("line1\nline2\nline3")
		for i := 0; i < 4; i++ {
			s, err := b.ReadString('\n')
			fmt.Printf("readstring %d -> %q err=%v\n", i, s, err)
			if err != nil {
				break
			}
		}
	}
	{
		var b bytes.Buffer
		n, err := b.ReadFrom(bytes.NewReader([]byte("from-reader")))
		fmt.Printf("readfrom n=%d err=%v s=%q\n", n, err, b.String())
		var out bytes.Buffer
		m, err := b.WriteTo(&out)
		fmt.Printf("writeto m=%d err=%v out=%q src=%q\n", m, err, out.String(), b.String())
	}
	{
		var b bytes.Buffer
		b.WriteRune('日')
		b.WriteByte('!')
		b.Write([]byte{0xff})
		fmt.Printf("buf mixed %q bytes=%q\n", b.String(), b.Bytes())
	}

	// 7. Reader: the seek-and-read behaviour Go pins.
	{
		r := bytes.NewReader([]byte("0123456789"))
		fmt.Printf("reader len=%d size=%d\n", r.Len(), r.Size())
		p := make([]byte, 4)
		n, err := r.Read(p)
		fmt.Printf("reader read n=%d err=%v p=%q len=%d\n", n, err, p[:n], r.Len())
		off, err := r.Seek(2, io.SeekStart)
		fmt.Printf("reader seek off=%d err=%v len=%d\n", off, err, r.Len())
		n, err = r.ReadAt(p, 6)
		fmt.Printf("reader readat n=%d err=%v p=%q\n", n, err, p[:n])
		n, err = r.ReadAt(p, 8)
		fmt.Printf("reader readat-short n=%d err=%v p=%q\n", n, err, p[:n])
		_, err = r.ReadAt(p, 20)
		fmt.Printf("reader readat-past err=%v\n", err)
		c, err := r.ReadByte()
		fmt.Printf("reader readbyte=%q err=%v\n", c, err)
		err = r.UnreadByte()
		fmt.Printf("reader unread err=%v\n", err)
		rr, size, err := r.ReadRune()
		fmt.Printf("reader readrune=%q size=%d err=%v\n", rr, size, err)
		_, err = r.Seek(-1, io.SeekStart)
		fmt.Printf("reader seek-neg err=%v\n", err)
		r.Reset([]byte("xy"))
		fmt.Printf("reader reset len=%d size=%d\n", r.Len(), r.Size())
	}
}
