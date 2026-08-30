package bufio_test

import (
	"bufio"
	"fmt"
	"strings"
	"testing"
)

// bufio.ScanWords steps by rune width, not by byte, and its notion of space is
// scan.go's own table -- which includes NBSP, NEL, the U+2000..U+200A
// run and the ideographic space. A byte-wise ASCII-only version gets
// every one of those wrong, and none of them shows up in an ASCII test.
func TestGoishRef(t *testing.T) {
	inputs := []string{
		"",
		"   ",
		"one",
		"one two three",
		"  leading and trailing  ",
		"a\tb\nc\rd\ve\ff",
		"tab\tsep",
		"nbsp sep",
		"nelsep",
		"enquad sep",
		"hairsp sep",
		"ogham sep",
		"lsep sep",
		"psep sep",
		"nnbsp sep",
		"mmsp sep",
		"ideo　sep",
		"　　lead",
		"trail　　",
		"日本 語 テ",
		"a  b",
	}
	for _, in := range inputs {
		s := bufio.NewScanner(strings.NewReader(in))
		s.Split(bufio.ScanWords)
		var toks []string
		for s.Scan() {
			toks = append(toks, s.Text())
		}
		fmt.Printf("words %-28q -> %q err=%v\n", in, toks, s.Err())
	}

	lineInputs := []string{
		"",
		"a",
		"a\n",
		"a\nb",
		"a\r\nb",
		"a\r\n",
		"\n",
		"\r\n",
		"a\n\nb",
		"a\rb",
		"a\r",
		"line1\r\nline2\nline3\r\n",
	}
	for _, in := range lineInputs {
		s := bufio.NewScanner(strings.NewReader(in))
		var toks []string
		for s.Scan() {
			toks = append(toks, s.Text())
		}
		fmt.Printf("lines %-24q -> %q err=%v\n", in, toks, s.Err())
	}

	for _, in := range []string{"", "abc", "aéb", "\xff\xfe", "a\xffb"} {
		s := bufio.NewScanner(strings.NewReader(in))
		s.Split(bufio.ScanRunes)
		var toks []string
		for s.Scan() {
			toks = append(toks, s.Text())
		}
		fmt.Printf("runes %-12q -> %q\n", in, toks)

		b := bufio.NewScanner(strings.NewReader(in))
		b.Split(bufio.ScanBytes)
		var bs []string
		for b.Scan() {
			bs = append(bs, b.Text())
		}
		fmt.Printf("bytes %-12q -> %q\n", in, bs)
	}

	{
		long := strings.Repeat("x", 40) + "\n" + "short\n"
		r := bufio.NewReaderSize(strings.NewReader(long), 16)
		for {
			line, err := r.ReadBytes('\n')
			fmt.Printf("readbytes %q err=%v\n", string(line), err)
			if err != nil {
				break
			}
		}
	}
	{
		r := bufio.NewReaderSize(strings.NewReader(strings.Repeat("y", 40)+"\n"), 16)
		line, err := r.ReadSlice('\n')
		fmt.Printf("readslice-1 %q err=%v\n", string(line), err)
		line, err = r.ReadSlice('\n')
		fmt.Printf("readslice-2 %q err=%v\n", string(line), err)
	}
	{
		r := bufio.NewReaderSize(strings.NewReader("hello\nworld"), 16)
		s, err := r.ReadString('\n')
		fmt.Printf("readstring-1 %q err=%v\n", s, err)
		s, err = r.ReadString('\n')
		fmt.Printf("readstring-2 %q err=%v\n", s, err)
	}
	{
		r := bufio.NewReader(strings.NewReader("abcdef"))
		p, err := r.Peek(3)
		fmt.Printf("peek %q err=%v buffered=%d\n", string(p), err, r.Buffered())
		n, err := r.Discard(2)
		fmt.Printf("discard n=%d err=%v\n", n, err)
		b, _ := r.ReadByte()
		fmt.Printf("readbyte %q unread=%v\n", string(b), r.UnreadByte())
		b, _ = r.ReadByte()
		fmt.Printf("reread %q\n", string(b))
	}
	{
		r := bufio.NewReader(strings.NewReader("aé日"))
		for {
			ru, size, err := r.ReadRune()
			if err != nil {
				break
			}
			fmt.Printf("readrune %q size=%d\n", ru, size)
		}
	}
	{
		var sb strings.Builder
		w := bufio.NewWriterSize(&sb, 8)
		n, _ := w.WriteString("hello ")
		fmt.Printf("write n=%d buffered=%d available=%d\n", n, w.Buffered(), w.Available())
		w.WriteRune('é')
		w.WriteByte('!')
		w.Write([]byte(" world"))
		w.Flush()
		fmt.Printf("writer -> %q size=%d\n", sb.String(), w.Size())
	}
	fmt.Printf("consts bufio.MaxScanTokenSize=%d\n", bufio.MaxScanTokenSize)
}
