package io_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// io is where the reader/writer contracts are DEFINED, so its edge
// cases are not niceties — every other package's behaviour is quoted
// from here. Four of them are easy to get subtly wrong while every
// ordinary copy still works:
//
//   * ReadFull and ReadAtLeast distinguish THREE outcomes: nothing read
//     is io.EOF, something-but-not-enough is io.ErrUnexpectedEOF, and
//     enough is nil. Collapsing the middle case into EOF loses the
//     difference between "the stream ended cleanly" and "the stream was
//     cut off mid-record", which is exactly the difference a framed
//     protocol cares about.
//   * CopyN returns io.EOF when it copied FEWER than n bytes, and nil
//     when it copied exactly n — even though it hit the end either way.
//   * A Copy from a reader that returns (n>0, io.EOF) in one call must
//     keep those n bytes and report success. Treating a non-nil error
//     as "discard the read" silently truncates.
//   * LimitReader is not a slice: it reports io.EOF at the limit, and a
//     LimitedReader with a non-positive N reads nothing at all.
//
// The errors themselves are sentinels, so identity is what callers test
// with errors.Is — a look-alike message is not the same value.
func TestGoishRef(t *testing.T) {
	// 1. ReadFull / ReadAtLeast: the three outcomes.
	for _, c := range []struct {
		src  string
		size int
		min  int
	}{
		{"hello", 5, 5}, {"hello", 3, 3}, {"hello", 8, 8}, {"", 4, 4},
		{"ab", 4, 4}, {"hello", 5, 3}, {"ab", 5, 2}, {"ab", 5, 3},
		{"hello", 0, 0}, {"", 0, 0}, {"hello", 3, 5},
	} {
		p := make([]byte, c.size)
		n, err := io.ReadFull(strings.NewReader(c.src), p)
		fmt.Printf("readfull src=%-7q size=%-2d -> n=%-2d err=%-20v isEOF=%-5v isUnexp=%v\n",
			c.src, c.size, n, err, errors.Is(err, io.EOF),
			errors.Is(err, io.ErrUnexpectedEOF))
		p2 := make([]byte, c.size)
		n2, err2 := io.ReadAtLeast(strings.NewReader(c.src), p2, c.min)
		fmt.Printf("readatleast src=%-7q size=%-2d min=%-2d -> n=%-2d err=%v\n",
			c.src, c.size, c.min, n2, err2)
	}

	// 2. Copy and CopyN, including the exactly-n boundary.
	for _, c := range []struct {
		src string
		n   int64
	}{{"hello world", 5}, {"hello", 5}, {"hello", 6}, {"", 3}, {"abc", 0},
		{"abc", -1}} {
		var dst bytes.Buffer
		n, err := io.CopyN(&dst, strings.NewReader(c.src), c.n)
		fmt.Printf("copyn src=%-13q n=%-3d -> wrote=%-2d err=%-8v isEOF=%-5v dst=%q\n",
			c.src, c.n, n, err, errors.Is(err, io.EOF), dst.String())
	}
	{
		var dst bytes.Buffer
		n, err := io.Copy(&dst, strings.NewReader("copy me"))
		fmt.Printf("copy n=%d err=%v dst=%q\n", n, err, dst.String())
		var empty bytes.Buffer
		n, err = io.Copy(&empty, strings.NewReader(""))
		fmt.Printf("copy-empty n=%d err=%v dst=%q\n", n, err, empty.String())
	}
	// A reader that returns data AND io.EOF in the same call: the bytes
	// must survive.
	{
		var dst bytes.Buffer
		n, err := io.Copy(&dst, &dataThenEOF{data: []byte("payload")})
		fmt.Printf("copy-data-with-eof n=%d err=%v dst=%q\n", n, err, dst.String())
		p := make([]byte, 16)
		rn, rerr := io.ReadFull(&dataThenEOF{data: []byte("xy")}, p[:2])
		fmt.Printf("readfull-data-with-eof n=%d err=%v p=%q\n", rn, rerr, p[:rn])
	}
	// A writer that reports a short write: Copy must surface
	// io.ErrShortWrite rather than looping.
	{
		n, err := io.Copy(shortWriter{}, strings.NewReader("abcdef"))
		fmt.Printf("copy-shortwrite n=%d err=%v isShort=%v\n",
			n, err, errors.Is(err, io.ErrShortWrite))
	}
	// An erroring reader: the error reaches the caller unchanged.
	{
		var dst bytes.Buffer
		boom := errors.New("boom")
		n, err := io.Copy(&dst, &errReader{err: boom})
		fmt.Printf("copy-err n=%d err=%v same=%v dst=%q\n", n, err, errors.Is(err, boom), dst.String())
	}

	// 3. LimitReader.
	for _, lim := range []int64{0, 3, 5, 9, -1} {
		b, err := io.ReadAll(io.LimitReader(strings.NewReader("abcde"), lim))
		fmt.Printf("limit n=%-3d -> %q err=%v\n", lim, b, err)
	}
	{
		lr := &io.LimitedReader{R: strings.NewReader("abcde"), N: 2}
		p := make([]byte, 4)
		n, err := lr.Read(p)
		fmt.Printf("limited read n=%d err=%v p=%q remaining=%d\n", n, err, p[:n], lr.N)
		n, err = lr.Read(p)
		fmt.Printf("limited read2 n=%d err=%v remaining=%d\n", n, err, lr.N)
	}

	// 4. MultiReader / MultiWriter / TeeReader.
	{
		mr := io.MultiReader(strings.NewReader("abc"), strings.NewReader(""),
			strings.NewReader("de"))
		b, err := io.ReadAll(mr)
		fmt.Printf("multireader %q err=%v\n", b, err)
		empty := io.MultiReader()
		b, err = io.ReadAll(empty)
		fmt.Printf("multireader-empty %q err=%v\n", b, err)
		// Reading past the end keeps reporting EOF.
		p := make([]byte, 4)
		n, err := empty.Read(p)
		fmt.Printf("multireader-empty-read n=%d err=%v\n", n, err)
	}
	{
		var a, b bytes.Buffer
		mw := io.MultiWriter(&a, &b)
		n, err := mw.Write([]byte("dup"))
		fmt.Printf("multiwriter n=%d err=%v\n", n, err)
		n, err = io.WriteString(mw, "!")
		fmt.Printf("multiwriter-ws n=%d err=%v\n", n, err)
		fmt.Printf("multiwriter-dst a=%q b=%q\n", a.String(), b.String())
	}
	{
		var side bytes.Buffer
		tr := io.TeeReader(strings.NewReader("teed"), &side)
		b, err := io.ReadAll(tr)
		fmt.Printf("teereader %q err=%v\n", b, err)
		fmt.Printf("teereader-side %q\n", side.String())
	}

	// 5. SectionReader — the offsets and the ends.
	{
		sr := io.NewSectionReader(strings.NewReader("0123456789"), 2, 5)
		fmt.Printf("section size=%d\n", sr.Size())
		b, err := io.ReadAll(sr)
		fmt.Printf("section read %q err=%v\n", b, err)
		sr2 := io.NewSectionReader(strings.NewReader("0123456789"), 2, 5)
		p := make([]byte, 3)
		n, err := sr2.ReadAt(p, 1)
		fmt.Printf("section readat n=%d err=%v p=%q\n", n, err, p[:n])
		n, err = sr2.ReadAt(p, 4)
		fmt.Printf("section readat-end n=%d err=%v p=%q\n", n, err, p[:n])
		_, err = sr2.ReadAt(p, 9)
		fmt.Printf("section readat-past err=%v\n", err)
		off, err := sr2.Seek(-1, io.SeekEnd)
		fmt.Printf("section seek-end off=%d err=%v\n", off, err)
	}

	// 6. ReadAll on an erroring reader keeps what it read.
	{
		b, err := io.ReadAll(&partialThenErr{data: []byte("partial")})
		fmt.Printf("readall-err %q err=%v\n", b, err)
		b, err = io.ReadAll(strings.NewReader(""))
		fmt.Printf("readall-empty %q err=%v\n", b, err)
		rc := io.NopCloser(strings.NewReader("nop"))
		nb, _ := io.ReadAll(rc)
		fmt.Printf("nopcloser %q close=%v\n", nb, rc.Close())
	}

	// 7. The sentinels themselves — identity and text.
	for _, c := range []struct {
		name string
		err  error
	}{
		{"EOF", io.EOF}, {"ErrUnexpectedEOF", io.ErrUnexpectedEOF},
		{"ErrShortWrite", io.ErrShortWrite}, {"ErrShortBuffer", io.ErrShortBuffer},
		{"ErrClosedPipe", io.ErrClosedPipe}, {"ErrNoProgress", io.ErrNoProgress},
	} {
		fmt.Printf("sentinel %-18s %q selfIs=%v isEOF=%v\n",
			c.name, c.err.Error(), errors.Is(c.err, c.err), errors.Is(c.err, io.EOF))
	}

	// 8. Discard and NopCloser.
	{
		n, err := io.Copy(io.Discard, strings.NewReader("thrown away"))
		fmt.Printf("discard n=%d err=%v\n", n, err)
		n2, err2 := io.WriteString(io.Discard, "x")
		fmt.Printf("discard-ws n=%d err=%v\n", n2, err2)
	}
}

// dataThenEOF returns all of its data and io.EOF in the SAME call,
// which the io.Reader docs explicitly permit and which a caller must
// handle by keeping the bytes.
type dataThenEOF struct {
	data []byte
	done bool
}

func (r *dataThenEOF) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	n := copy(p, r.data)
	return n, io.EOF
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

type errReader struct{ err error }

func (r *errReader) Read(p []byte) (int, error) { return 0, r.err }

type partialThenErr struct {
	data []byte
	done bool
}

func (r *partialThenErr) Read(p []byte) (int, error) {
	if r.done {
		return 0, errors.New("read failed")
	}
	r.done = true
	return copy(p, r.data), nil
}
