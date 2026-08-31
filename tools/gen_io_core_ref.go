package io_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// refShortWriter accepts at most n bytes per Write and reports the
// truncated count with a nil error — the shape that makes Copy return
// ErrShortWrite.
type refShortWriter struct {
	n   int
	buf bytes.Buffer
}

func (w *refShortWriter) Write(p []byte) (int, error) {
	if len(p) > w.n {
		p = p[:w.n]
	}
	return w.buf.Write(p)
}

// refLiarWriter claims to have written more than it was handed. Copy must
// not believe it: the count is discarded and errInvalidWrite surfaces.
type refLiarWriter struct{ over int }

func (w *refLiarWriter) Write(p []byte) (int, error) { return len(p) + w.over, nil }

// refErrWriter fails after letting n bytes through.
type refErrWriter struct {
	left int
	err  error
}

func (w *refErrWriter) Write(p []byte) (int, error) {
	if w.left <= 0 {
		return 0, w.err
	}
	if len(p) > w.left {
		n := w.left
		w.left = 0
		return n, w.err
	}
	w.left -= len(p)
	return len(p), nil
}

// refOneByteReader hands back a single byte per Read, so the copy loop
// runs many times over a short input.
type refOneByteReader struct{ s string }

func (r *refOneByteReader) Read(p []byte) (int, error) {
	if len(r.s) == 0 {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = r.s[0]
	r.s = r.s[1:]
	return 1, nil
}

// refDataErrReader returns its data and io.EOF in the SAME call, which a
// reader is allowed to do and which a naive loop mishandles.
type refDataErrReader struct{ s string }

func (r *refDataErrReader) Read(p []byte) (int, error) {
	n := copy(p, r.s)
	r.s = r.s[n:]
	if len(r.s) == 0 {
		return n, io.EOF
	}
	return n, nil
}

// A writer that also implements StringWriter, so MultiWriter's
// WriteString takes the string path for it and the []byte path for the
// plain one beside it.
type refStringSink struct {
	sb    strings.Builder
	calls []string
}

func (s *refStringSink) Write(p []byte) (int, error) {
	s.calls = append(s.calls, "Write")
	return s.sb.Write(p)
}

func (s *refStringSink) WriteString(str string) (int, error) {
	s.calls = append(s.calls, "WriteString")
	return s.sb.WriteString(str)
}

type refPlainSink struct {
	sb    strings.Builder
	calls []string
}

func (s *refPlainSink) Write(p []byte) (int, error) {
	s.calls = append(s.calls, "Write")
	return s.sb.Write(p)
}

func TestGoishRef(t *testing.T) {
	// Copy: the ordinary case, the short write, the lying writer, and
	// the reader that reports data and EOF together.
	{
		var dst bytes.Buffer
		n, err := io.Copy(&dst, strings.NewReader("hello, world"))
		fmt.Printf("copy n=%d out=%q err=%v\n", n, dst.String(), err)

		var d2 bytes.Buffer
		n, err = io.Copy(&d2, strings.NewReader(""))
		fmt.Printf("copy-empty n=%d out=%q err=%v\n", n, d2.String(), err)

		var d3 bytes.Buffer
		n, err = io.Copy(&d3, &refOneByteReader{"abcdef"})
		fmt.Printf("copy-1byte n=%d out=%q err=%v\n", n, d3.String(), err)

		var d4 bytes.Buffer
		n, err = io.Copy(&d4, &refDataErrReader{"tail-eof"})
		fmt.Printf("copy-dataerr n=%d out=%q err=%v\n", n, d4.String(), err)

		sw := &refShortWriter{n: 3}
		n, err = io.Copy(sw, &refOneByteReader{"abcdefgh"})
		fmt.Printf("copy-short n=%d out=%q err=%v short=%v\n",
			n, sw.buf.String(), err, errors.Is(err, io.ErrShortWrite))

		// The source must NOT be a WriterTo, or Copy takes the fast
		// path and never reaches the guard — strings.Reader.WriteTo
		// panics on a lying writer instead.
		lw := &refLiarWriter{over: 1}
		n, err = io.Copy(lw, &refOneByteReader{"abc"})
		fmt.Printf("copy-liar n=%d err=%v\n", n, err)

		boom := errors.New("boom")
		ew := &refErrWriter{left: 0, err: boom}
		n, err = io.Copy(ew, &refOneByteReader{"abc"})
		fmt.Printf("copy-err n=%d err=%v same=%v\n", n, err, errors.Is(err, boom))
	}

	// CopyN stops at n, and reports EOF when the source runs out first.
	{
		for _, n := range []int64{0, 3, 12, 13, 100} {
			var dst bytes.Buffer
			got, err := io.CopyN(&dst, strings.NewReader("hello, world"), n)
			fmt.Printf("copyn n=%-4d got=%-3d out=%-14q err=%v\n", n, got, dst.String(), err)
		}
	}

	// CopyBuffer with buffers smaller than the payload.
	{
		for _, size := range []int{1, 2, 7, 64} {
			var dst bytes.Buffer
			n, err := io.CopyBuffer(&dst, strings.NewReader("hello, world"), make([]byte, size))
			fmt.Printf("copybuf size=%-3d n=%-3d out=%q err=%v\n", size, n, dst.String(), err)
		}
	}

	// WriteString goes through StringWriter when the writer has one.
	{
		var b bytes.Buffer
		n, err := io.WriteString(&b, "héllo")
		fmt.Printf("writestring n=%d out=%q err=%v\n", n, b.String(), err)
	}

	// ReadAll, ReadFull, ReadAtLeast — and the three errors they can
	// return, which are NOT the same error.
	{
		for _, s := range []string{"", "a", "hello, world"} {
			b, err := io.ReadAll(strings.NewReader(s))
			fmt.Printf("readall %-14q -> %q err=%v\n", s, b, err)
		}
		b, err := io.ReadAll(&refDataErrReader{"data+eof"})
		fmt.Printf("readall-dataerr %q err=%v\n", b, err)

		for _, s := range []string{"", "ab", "abcd", "abcdef"} {
			buf := make([]byte, 4)
			n, err := io.ReadFull(strings.NewReader(s), buf)
			fmt.Printf("readfull %-8q n=%d buf=%q err=%v eof=%v unexpected=%v\n",
				s, n, buf[:n], err,
				errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF))
		}
		for _, min := range []int{0, 1, 3, 4, 5} {
			buf := make([]byte, 4)
			n, err := io.ReadAtLeast(strings.NewReader("abc"), buf, min)
			fmt.Printf("readatleast min=%d n=%d buf=%q err=%v short=%v\n",
				min, n, buf[:n], err, errors.Is(err, io.ErrShortBuffer))
		}
	}

	// LimitReader: n <= 0 is immediately EOF, and the limit is a byte
	// budget shared across reads.
	{
		for _, n := range []int64{-1, 0, 1, 5, 12, 100} {
			b, err := io.ReadAll(io.LimitReader(strings.NewReader("hello, world"), n))
			fmt.Printf("limit n=%-4d -> %-14q err=%v\n", n, b, err)
		}
		lr := io.LimitReader(strings.NewReader("abcdef"), 4).(*io.LimitedReader)
		buf := make([]byte, 3)
		for i := 0; i < 3; i++ {
			k, err := lr.Read(buf)
			fmt.Printf("limit-step %d n=%d buf=%q left=%d err=%v\n", i, k, buf[:k], lr.N, err)
		}
	}

	// TeeReader mirrors every byte read, including the final short one.
	{
		var mirror bytes.Buffer
		tr := io.TeeReader(strings.NewReader("hello"), &mirror)
		buf := make([]byte, 2)
		for i := 0; i < 4; i++ {
			n, err := tr.Read(buf)
			fmt.Printf("tee %d n=%d buf=%q mirror=%q err=%v\n", i, n, buf[:n], mirror.String(), err)
		}
	}

	// SectionReader: Read, ReadAt, Seek, Size and Outer.
	{
		base := strings.NewReader("0123456789")
		sr := io.NewSectionReader(base, 2, 5)
		fmt.Printf("section size=%d\n", sr.Size())
		buf := make([]byte, 3)
		for i := 0; i < 3; i++ {
			n, err := sr.Read(buf)
			fmt.Printf("section-read %d n=%d buf=%q err=%v\n", i, n, buf[:n], err)
		}
		for _, off := range []int64{0, 3, 4, 5, 6, -1} {
			b := make([]byte, 3)
			n, err := sr.ReadAt(b, off)
			fmt.Printf("section-readat off=%-3d n=%d buf=%q err=%v\n", off, n, b[:n], err)
		}
		for _, c := range []struct {
			off    int64
			whence int
		}{{0, io.SeekStart}, {2, io.SeekStart}, {-1, io.SeekStart},
			{0, io.SeekEnd}, {-2, io.SeekEnd}, {1, io.SeekCurrent}, {0, 99}} {
			s2 := io.NewSectionReader(strings.NewReader("0123456789"), 2, 5)
			pos, err := s2.Seek(c.off, c.whence)
			fmt.Printf("section-seek off=%-3d whence=%d pos=%-3d err=%v\n", c.off, c.whence, pos, err)
		}
		_, off, n := sr.Outer()
		fmt.Printf("section-outer off=%d n=%d\n", off, n)
	}

	// OffsetWriter maps writes at base+off.
	{
		var under bytes.Buffer
		under.WriteString("..........")
		ow := io.NewOffsetWriter(&refWriterAtBuf{b: []byte("..........")}, 3)
		n, err := ow.Write([]byte("abc"))
		fmt.Printf("offsetwriter n=%d err=%v\n", n, err)
		n2, err := ow.Write([]byte("de"))
		fmt.Printf("offsetwriter2 n=%d err=%v\n", n2, err)
		pos, err := ow.Seek(0, io.SeekStart)
		fmt.Printf("offsetwriter-seek pos=%d err=%v\n", pos, err)
		n3, err := ow.Write([]byte("XY"))
		fmt.Printf("offsetwriter3 n=%d err=%v\n", n3, err)
		pos, err = ow.Seek(-1, io.SeekStart)
		fmt.Printf("offsetwriter-badseek pos=%d err=%v\n", pos, err)
		pos, err = ow.Seek(0, 99)
		fmt.Printf("offsetwriter-badwhence pos=%d err=%v\n", pos, err)
	}

	// MultiReader concatenates, and reports EOF only once past the last.
	{
		mr := io.MultiReader(
			strings.NewReader("one "),
			strings.NewReader(""),
			strings.NewReader("two "),
			strings.NewReader("three"),
		)
		b, err := io.ReadAll(mr)
		fmt.Printf("multireader %q err=%v\n", b, err)

		mr2 := io.MultiReader()
		b, err = io.ReadAll(mr2)
		fmt.Printf("multireader-none %q err=%v\n", b, err)

		mr3 := io.MultiReader(strings.NewReader("ab"), strings.NewReader("cd"))
		buf := make([]byte, 3)
		for i := 0; i < 4; i++ {
			n, err := mr3.Read(buf)
			fmt.Printf("multireader-step %d n=%d buf=%q err=%v\n", i, n, buf[:n], err)
		}

		// WriteTo drains every reader through one buffer.
		mr4 := io.MultiReader(strings.NewReader("alpha"), strings.NewReader("-beta"))
		var dst bytes.Buffer
		n, err := mr4.(io.WriterTo).WriteTo(&dst)
		fmt.Printf("multireader-writeto n=%d out=%q err=%v\n", n, dst.String(), err)
		// Drained: a second WriteTo moves nothing.
		var dst2 bytes.Buffer
		n, err = mr4.(io.WriterTo).WriteTo(&dst2)
		fmt.Printf("multireader-writeto2 n=%d out=%q err=%v\n", n, dst2.String(), err)

		// An error part-way leaves the remaining readers in place.
		boom := errors.New("boom")
		mr5 := io.MultiReader(strings.NewReader("aaa"), strings.NewReader("bbb"))
		n, err = mr5.(io.WriterTo).WriteTo(&refErrWriter{left: 3, err: boom})
		fmt.Printf("multireader-writeto-err n=%d err=%v\n", n, err)
	}

	// MultiWriter fans out, stops at the first error, and prefers
	// WriteString where the writer offers one.
	{
		var a, b bytes.Buffer
		mw := io.MultiWriter(&a, &b)
		n, err := mw.Write([]byte("dup"))
		fmt.Printf("multiwriter n=%d a=%q b=%q err=%v\n", n, a.String(), b.String(), err)

		mw2 := io.MultiWriter()
		n, err = mw2.Write([]byte("nowhere"))
		fmt.Printf("multiwriter-none n=%d err=%v\n", n, err)

		var c bytes.Buffer
		sw := &refShortWriter{n: 1}
		mw3 := io.MultiWriter(&c, sw)
		n, err = mw3.Write([]byte("abc"))
		fmt.Printf("multiwriter-short n=%d c=%q sw=%q err=%v\n",
			n, c.String(), sw.buf.String(), err)

		boom := errors.New("boom")
		var d bytes.Buffer
		mw4 := io.MultiWriter(&d, &refErrWriter{left: 0, err: boom})
		n, err = mw4.Write([]byte("abc"))
		fmt.Printf("multiwriter-err n=%d d=%q err=%v\n", n, d.String(), err)

		ss, ps := &refStringSink{}, &refPlainSink{}
		mw5 := io.MultiWriter(ss, ps)
		n, err = mw5.(io.StringWriter).WriteString("héllo")
		fmt.Printf("multiwriter-writestring n=%d ss=%q(%v) ps=%q(%v) err=%v\n",
			n, ss.sb.String(), ss.calls, ps.sb.String(), ps.calls, err)
	}

	// Discard swallows everything, and its ReadFrom drains a reader.
	{
		n, err := io.Discard.Write([]byte("gone"))
		fmt.Printf("discard n=%d err=%v\n", n, err)
		m, err := io.Copy(io.Discard, strings.NewReader(strings.Repeat("x", 20000)))
		fmt.Printf("discard-copy n=%d err=%v\n", m, err)
		m, err = io.Discard.(io.ReaderFrom).ReadFrom(strings.NewReader(""))
		fmt.Printf("discard-readfrom-empty n=%d err=%v\n", m, err)
		boom := errors.New("boom")
		m, err = io.Discard.(io.ReaderFrom).ReadFrom(&refErrReader{n: 3, err: boom})
		fmt.Printf("discard-readfrom-err n=%d err=%v\n", m, err)
	}

	// NopCloser: Close is nil, and a WriterTo source keeps its WriteTo.
	{
		nc := io.NopCloser(strings.NewReader("wrapped"))
		b, err := io.ReadAll(nc)
		fmt.Printf("nopcloser %q err=%v close=%v\n", b, err, nc.Close())
		_, isWriterTo := nc.(io.WriterTo)
		fmt.Printf("nopcloser-writerto %v\n", isWriterTo)

		// bytes.Reader is a WriterTo, so the wrapper keeps it.
		nc2 := io.NopCloser(bytes.NewReader([]byte("wt")))
		wt, ok := nc2.(io.WriterTo)
		fmt.Printf("nopcloser-wt ok=%v\n", ok)
		if ok {
			var dst bytes.Buffer
			n, err := wt.WriteTo(&dst)
			fmt.Printf("nopcloser-wt-writeto n=%d out=%q err=%v close=%v\n",
				n, dst.String(), err, nc2.Close())
		}
	}

	// The sentinel errors are distinct values with stable texts.
	{
		for _, e := range []error{io.EOF, io.ErrShortWrite, io.ErrUnexpectedEOF,
			io.ErrShortBuffer, io.ErrNoProgress, io.ErrClosedPipe} {
			fmt.Printf("sentinel %q\n", e.Error())
		}
		fmt.Printf("distinct %v %v\n",
			errors.Is(io.EOF, io.ErrUnexpectedEOF), errors.Is(io.EOF, io.EOF))
	}
}

// refErrReader yields n bytes then fails.
type refErrReader struct {
	n   int
	err error
}

func (r *refErrReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, r.err
	}
	k := len(p)
	if k > r.n {
		k = r.n
	}
	for i := 0; i < k; i++ {
		p[i] = 'z'
	}
	r.n -= k
	return k, nil
}

// refWriterAtBuf is the minimum io.WriterAt an OffsetWriter needs.
type refWriterAtBuf struct{ b []byte }

func (w *refWriterAtBuf) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	for int64(len(w.b)) < off+int64(len(p)) {
		w.b = append(w.b, '.')
	}
	copy(w.b[off:], p)
	return len(p), nil
}
