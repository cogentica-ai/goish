// io_core_smoke — io.go and multi.go against a running Go.
// (io/io.go, io/multi.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_io_core_ref.go` run in `package io_test`
// by `scripts/goref.sh`.
//
// The free functions here lived unanchored in the module root, matched
// by name, until the split. What that hid: `Copy` believed a `Write`
// that claimed more bytes than it was handed, `Seek` minted a fresh
// error value at every return site instead of comparing against one,
// `SectionReader` had no `Outer`, `Discard` had no `ReadFrom`,
// `MultiReader` had no `WriteTo` and `MultiWriter` no `WriteString`.
//
// The cases are picked where a plausible implementation and Go's part
// company: a reader that returns data and EOF in the SAME call, a
// writer that accepts less than it is given, one that lies about the
// count, `ReadFull` on a short source (unexpected EOF, not EOF),
// `ReadAtLeast` with min > len(buf) (short buffer, a third error
// again), a `LimitReader` with a negative budget, and a `MultiWriter`
// holding one writer that implements `StringWriter` beside one that
// does not.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::boxed::Box;
use alloc::vec::Vec;

use goish::bytes;
use goish::errors;
use goish::fmt;
use goish::goslice::slice;
use goish::io::{self, Closer, Reader, ReaderFrom, StringWriter, Writer, WriterAt, WriterTo};
use goish::strings;
use goish::types::{byte, int};
use goish::{error, string, syscall};

// go: none — goish idiom: the smokes print one PASS/FAIL line per
//     numbered check; this is that line, hoisted.
fn report(failed: &mut int, ok: bool, n: &str, what: &str) {
    if ok {
        fmt::Println!("[", n, "]", what, "PASS");
    } else {
        fmt::Println!("[", n, "]", what, "FAIL");
        *failed += 1;
    }
}

fn buf0() -> bytes::Buffer {
    return bytes::NewBuffer(goish::make!([]byte, 0));
}

// go: none — goish idiom: the Go reference's `refOneByteReader`. A
//     source that hands back one byte per Read keeps `Copy` off any
//     `WriterTo` fast path, which is the only way to reach the guards
//     the copy loop itself carries.
struct OneByteReader {
    s: Vec<byte>,
}

impl Reader for OneByteReader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        if self.s.is_empty() {
            return (0, io::EOF.into());
        }
        if p.Len() == 0 {
            return (0, goish::errors::nil);
        }
        p[0] = self.s.remove(0);
        return (1, goish::errors::nil);
    }
}

// go: none — goish idiom: the Go reference's `refDataErrReader`. A
//     reader is allowed to return its last bytes AND EOF in one call,
//     and a loop that checks the error before the count loses them.
struct DataErrReader {
    s: Vec<byte>,
}

impl Reader for DataErrReader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        let n = if p.Len() as usize > self.s.len() {
            self.s.len()
        } else {
            p.Len() as usize
        };
        for i in 0..n {
            p[i] = self.s[i];
        }
        self.s.drain(..n);
        if self.s.is_empty() {
            return (goish::convert::int(n), io::EOF.into());
        }
        return (goish::convert::int(n), goish::errors::nil);
    }
}

// go: none — goish idiom: the Go reference's `refLiarWriter`. Claims to
//     have written more than it was handed.
struct LiarWriter {
    over: int,
}

impl Writer for LiarWriter {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return (p.Len() + self.over, goish::errors::nil);
    }
}

// go: none — goish idiom: the Go reference's `refShortWriter`. Accepts
//     at most `n` bytes and reports the truncated count with no error.
struct ShortWriter {
    n: int,
    log: Log,
}

impl Writer for ShortWriter {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        let take = if p.Len() > self.n { self.n } else { p.Len() };
        let head = p.slice(0, take);
        let b: &[byte] = &head;
        self.log.record("Write", b);
        return (take, goish::errors::nil);
    }
}

// go: none — goish idiom: the Go reference's `refErrWriter`. Fails once
//     `left` bytes have gone through.
struct ErrWriter {
    left: int,
    err: error,
}

impl Writer for ErrWriter {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        if self.left <= 0 {
            return (0, self.err.clone());
        }
        if p.Len() > self.left {
            let n = self.left;
            self.left = 0;
            return (n, self.err.clone());
        }
        self.left -= p.Len();
        return (p.Len(), goish::errors::nil);
    }
}

// go: none — goish idiom: the Go reference's `refErrReader`. Yields `n`
//     bytes of 'z' and then fails.
struct ErrReader {
    n: int,
    err: error,
}

impl Reader for ErrReader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        if self.n <= 0 {
            return (0, self.err.clone());
        }
        let k = if p.Len() > self.n { self.n } else { p.Len() };
        for i in 0..k as usize {
            p[i] = b'z';
        }
        self.n -= k;
        return (k, goish::errors::nil);
    }
}

// go: none — goish idiom: `io::MultiWriter` takes owned
//     `Box<dyn Writer>`s, where Go's takes interface values that the
//     caller still holds. So the sinks below write into a shared log
//     the test keeps a handle on, and it is the log — not the sink —
//     that is read back afterwards.
#[derive(Clone)]
struct Log(alloc::sync::Arc<goish::sync::Mutex<LogState>>);

struct LogState {
    out: Vec<byte>,
    calls: Vec<&'static str>,
}

impl Log {
    fn new() -> Log {
        return Log(alloc::sync::Arc::new(goish::sync::Mutex::new(LogState {
            out: Vec::new(),
            calls: Vec::new(),
        })));
    }
    fn text(&self) -> string {
        return string::from_bytes(&self.0.Lock().out);
    }
    fn calls(&self) -> Vec<&'static str> {
        return self.0.Lock().calls.clone();
    }
    fn record(&self, how: &'static str, p: &[byte]) {
        let mut g = self.0.Lock();
        g.calls.push(how);
        g.out.extend_from_slice(p);
    }
}

// go: none — goish idiom: the Go reference's `refStringSink` — a writer
//     that also implements `StringWriter`, so `MultiWriter::WriteString`
//     takes the string path for it. It records which path was taken.
struct StringSink {
    log: Log,
}

impl Writer for StringSink {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        let b: &[byte] = &p;
        self.log.record("Write", b);
        return (p.Len(), goish::errors::nil);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides so a type
    //     assertion can reach this type. Go's itabs make it
    //     unnecessary. Without it `MultiWriter::WriteString` cannot see
    //     that this sink has a `WriteString`.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: see `__goish_as_dyn_any`.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl StringWriter for StringSink {
    fn WriteString(&mut self, s: string) -> (int, error) {
        self.log.record("WriteString", s.as_bytes());
        return (s.Len(), goish::errors::nil);
    }
}

// go: none — goish idiom: the Go reference's `refPlainSink` — a writer
//     with no `WriteString`, so `MultiWriter` must encode the string
//     once and hand it the bytes.
struct PlainSink {
    log: Log,
}

impl Writer for PlainSink {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        let b: &[byte] = &p;
        self.log.record("Write", b);
        return (p.Len(), goish::errors::nil);
    }
}

// go: none — goish idiom: the Go reference's `refWriterAtBuf` — the
//     minimum `io.WriterAt` an `OffsetWriter` needs.
struct WriterAtBuf {
    b: Vec<byte>,
}

impl WriterAt for WriterAtBuf {
    fn WriteAt(&mut self, p: slice<byte>, off: i64) -> (int, error) {
        if off < 0 {
            return (0, errors::New("negative offset"));
        }
        while (self.b.len() as i64) < off + p.Len() as i64 {
            self.b.push(b'.');
        }
        for i in 0..p.Len() as usize {
            self.b[off as usize + i] = p[i];
        }
        return (p.Len(), goish::errors::nil);
    }
}

fn sr(s: &'static str) -> strings::Reader {
    return strings::NewReader(string(s));
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // `cast!` resolves through the per-trait downcast registry, which
    // nothing fills for a type declared outside goish. Go's linker
    // builds the equivalent itab; here it is one call. See AGENTS.md §9b.
    goish::io::__goish_register_StringWriter_impl::<StringSink>();

    // 1. Copy: the ordinary case, an empty source, a one-byte-at-a-time
    //    source, and a reader that returns its data and EOF together.
    {
        let mut ok = true;
        let mut d = buf0();
        let (n, err) = io::Copy(&mut d, &mut sr("hello, world"));
        if n != 12 || d.String() != "hello, world" || !err.IsNil() {
            ok = false;
        }
        let mut d2 = buf0();
        let (n2, err2) = io::Copy(&mut d2, &mut sr(""));
        if n2 != 0 || d2.String() != "" || !err2.IsNil() {
            ok = false;
        }
        let mut d3 = buf0();
        let mut src3 = OneByteReader {
            s: b"abcdef".to_vec(),
        };
        let (n3, err3) = io::Copy(&mut d3, &mut src3);
        if n3 != 6 || d3.String() != "abcdef" || !err3.IsNil() {
            ok = false;
        }
        // Go: copy-dataerr n=8 out="tail-eof" err=<nil>
        let mut d4 = buf0();
        let mut src4 = DataErrReader {
            s: b"tail-eof".to_vec(),
        };
        let (n4, err4) = io::Copy(&mut d4, &mut src4);
        if n4 != 8 || d4.String() != "tail-eof" || !err4.IsNil() {
            ok = false;
        }
        report(&mut failed, ok, " 1", "Copy (data+EOF in one Read)");
    }

    // 2. A Writer that claims more bytes than it was handed. Go
    //    discards the count and reports errInvalidWrite; the port used
    //    to believe it and report success.
    {
        let mut lw = LiarWriter { over: 1 };
        let mut src = OneByteReader { s: b"abc".to_vec() };
        let (n, err) = io::Copy(&mut lw, &mut src);
        // Go: copy-liar n=0 err=invalid write result
        let ok = n == 0 && !err.IsNil() && err.Error() == "invalid write result";
        report(&mut failed, ok, " 2", "Copy rejects a lying Write");
    }

    // 3. A Writer that fails outright: the error is the writer's own,
    //    not a wrapper.
    {
        let boom = errors::New("boom");
        let mut ew = ErrWriter {
            left: 0,
            err: boom.clone(),
        };
        let mut src = OneByteReader { s: b"abc".to_vec() };
        let (n, err) = io::Copy(&mut ew, &mut src);
        let ok = n == 0 && errors::Is(err, boom);
        report(&mut failed, ok, " 3", "Copy surfaces the write error");
    }

    // 4. CopyN. Asking for more than there is copies what there is and
    //    reports EOF; asking for exactly what there is does not.
    {
        let mut ok = true;
        // (n, want_got, want_out, want_eof)
        let cases: [(i64, i64, &str, bool); 5] = [
            (0, 0, "", false),
            (3, 3, "hel", false),
            (12, 12, "hello, world", false),
            (13, 12, "hello, world", true),
            (100, 12, "hello, world", true),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (n, want, out, want_eof) = cases[i];
            let mut d = buf0();
            let (got, err) = io::CopyN(&mut d, &mut sr("hello, world"), n);
            if got != want || d.String() != string(out) {
                ok = false;
            }
            if want_eof != errors::Is(err, io::EOF) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 4", "CopyN (EOF only when short)");
    }

    // 5. CopyBuffer with buffers smaller than the payload.
    {
        let mut ok = true;
        for size in [1, 2, 7, 64] {
            let mut d = buf0();
            let (n, err) =
                io::CopyBuffer(&mut d, &mut sr("hello, world"), goish::make!([]byte, size));
            if n != 12 || d.String() != "hello, world" || !err.IsNil() {
                ok = false;
            }
        }
        report(&mut failed, ok, " 5", "CopyBuffer (tiny buffers)");
    }

    // 6. WriteString counts BYTES, not runes: "héllo" is 6.
    {
        let mut b = buf0();
        let (n, err) = io::WriteString(&mut b, "héllo");
        let ok = n == 6 && b.String() == "héllo" && err.IsNil();
        report(&mut failed, ok, " 6", "WriteString counts bytes");
    }

    // 7. ReadAll, including the reader that ends with data and EOF in
    //    one call. EOF is normal termination and is never reported.
    {
        let mut ok = true;
        for s in ["", "a", "hello, world"] {
            let (b, err) = io::ReadAll(&mut sr(s));
            if string::from_bytes(&b) != string(s) || !err.IsNil() {
                ok = false;
            }
        }
        let mut src = DataErrReader {
            s: b"data+eof".to_vec(),
        };
        let (b, err) = io::ReadAll(&mut src);
        if string::from_bytes(&b) != "data+eof" || !err.IsNil() {
            ok = false;
        }
        report(&mut failed, ok, " 7", "ReadAll (EOF is not an error)");
    }

    // 8. ReadFull. An empty source is EOF; a short one is
    //    ErrUnexpectedEOF. These are different errors, and code that
    //    collapses them cannot tell "nothing there" from "truncated".
    {
        let mut ok = true;
        // (input, want_n, want_eof, want_unexpected)
        let cases: [(&str, int, bool, bool); 4] = [
            ("", 0, true, false),
            ("ab", 2, false, true),
            ("abcd", 4, false, false),
            ("abcdef", 4, false, false),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (input, want_n, want_eof, want_unexpected) = cases[i];
            let mut buf = goish::make!([]byte, 4);
            let (n, err) = io::ReadFull(&mut sr(input), &mut buf);
            if n != want_n {
                ok = false;
            }
            if errors::Is(err.clone(), io::EOF) != want_eof {
                ok = false;
            }
            if errors::Is(err, io::ErrUnexpectedEOF) != want_unexpected {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 8", "ReadFull: EOF vs unexpected EOF");
    }

    // 9. ReadAtLeast. min > len(buf) is ErrShortBuffer and reads
    //    NOTHING — a third error again, and the buffer stays untouched.
    {
        let mut ok = true;
        // (min, want_n, want_short_buffer, want_unexpected)
        let cases: [(int, int, bool, bool); 5] = [
            (0, 0, false, false),
            (1, 3, false, false),
            (3, 3, false, false),
            (4, 3, false, true),
            (5, 0, true, false),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (min, want_n, want_short, want_unexpected) = cases[i];
            let mut buf = goish::make!([]byte, 4);
            let (n, err) = io::ReadAtLeast(&mut sr("abc"), &mut buf, min);
            if n != want_n {
                ok = false;
            }
            if errors::Is(err.clone(), io::ErrShortBuffer) != want_short {
                ok = false;
            }
            if errors::Is(err, io::ErrUnexpectedEOF) != want_unexpected {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 9", "ReadAtLeast: ErrShortBuffer");
    }

    // 10. LimitReader. A negative or zero budget is immediately EOF —
    //     not "unlimited" — and N is a running remainder.
    {
        let mut ok = true;
        let cases: [(int, &str); 6] = [
            (-1, ""),
            (0, ""),
            (1, "h"),
            (5, "hello"),
            (12, "hello, world"),
            (100, "hello, world"),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (n, want) = cases[i];
            let mut lr = io::LimitReader(sr("hello, world"), n);
            let (b, err) = io::ReadAll(&mut lr);
            if string::from_bytes(&b) != string(want) || !err.IsNil() {
                ok = false;
            }
            i += 1;
        }
        // Go: limit-step 0 n=3 left=1 / 1 n=1 left=0 / 2 n=0 err=EOF
        let mut lr = io::LimitReader(sr("abcdef"), 4);
        let mut p = goish::make!([]byte, 3);
        let (n0, _) = lr.Read(&mut p);
        if n0 != 3 || lr.N != 1 {
            ok = false;
        }
        let (n1, _) = lr.Read(&mut p);
        if n1 != 1 || lr.N != 0 {
            ok = false;
        }
        let (n2, err2) = lr.Read(&mut p);
        if n2 != 0 || !errors::Is(err2, io::EOF) {
            ok = false;
        }
        report(&mut failed, ok, "10", "LimitReader (n<=0 is EOF)");
    }

    // 11. TeeReader mirrors every byte that is read, and the mirror is
    //     complete before the final EOF read.
    {
        let mut ok = true;
        let mut mirror = buf0();
        let mut tr = io::TeeReader(sr("hello"), &mut mirror);
        let mut p = goish::make!([]byte, 2);
        let (a, _) = tr.Read(&mut p);
        let (b, _) = tr.Read(&mut p);
        let (c, _) = tr.Read(&mut p);
        let (d, errd) = tr.Read(&mut p);
        if a != 2 || b != 2 || c != 1 || d != 0 || !errors::Is(errd, io::EOF) {
            ok = false;
        }
        drop(tr);
        if mirror.String() != "hello" {
            ok = false;
        }
        report(&mut failed, ok, "11", "TeeReader mirrors every byte");
    }

    // 12. SectionReader. ReadAt does not move the cursor, an offset at
    //     or past the section end is EOF, and Outer hands back the
    //     three values NewSectionReader was given.
    {
        let mut ok = true;
        let mut s = io::NewSectionReader(Box::new(sr("0123456789")), 2, 5);
        if s.Size() != 5 {
            ok = false;
        }
        let mut p = goish::make!([]byte, 3);
        let (n0, _) = s.Read(&mut p);
        if n0 != 3 || string::from_bytes(&p.slice(0, n0)) != "234" {
            ok = false;
        }
        let (n1, _) = s.Read(&mut p);
        if n1 != 2 || string::from_bytes(&p.slice(0, n1)) != "56" {
            ok = false;
        }
        let (n2, err2) = s.Read(&mut p);
        if n2 != 0 || !errors::Is(err2, io::EOF) {
            ok = false;
        }
        // Go: section-readat off=0 n=3 "234"; off=3 n=2 "56" EOF; off>=5 n=0 EOF.
        let readat: [(i64, int, &str, bool); 6] = [
            (0, 3, "234", false),
            (3, 2, "56", true),
            (4, 1, "6", true),
            (5, 0, "", true),
            (6, 0, "", true),
            (-1, 0, "", true),
        ];
        let mut i = 0;
        while i < readat.len() {
            let (off, want_n, want, want_eof) = readat[i];
            let mut b = goish::make!([]byte, 3);
            let (n, err) = s.ReadAt(&mut b, off);
            if n != want_n || string::from_bytes(&b.slice(0, n)) != string(want) {
                ok = false;
            }
            if errors::Is(err, io::EOF) != want_eof {
                ok = false;
            }
            i += 1;
        }
        // Go: the three whences, plus the two error arms.
        let seeks: [(i64, int, i64, &str); 7] = [
            (0, io::SeekStart, 0, ""),
            (2, io::SeekStart, 2, ""),
            (-1, io::SeekStart, 0, "Seek: invalid offset"),
            (0, io::SeekEnd, 5, ""),
            (-2, io::SeekEnd, 3, ""),
            (1, io::SeekCurrent, 1, ""),
            (0, 99, 0, "Seek: invalid whence"),
        ];
        let mut j = 0;
        while j < seeks.len() {
            let (off, whence, want_pos, want_err) = seeks[j];
            let mut s2 = io::NewSectionReader(Box::new(sr("0123456789")), 2, 5);
            let (pos, err) = s2.Seek(off, whence);
            if pos != want_pos {
                ok = false;
            }
            if want_err == "" {
                if !err.IsNil() {
                    ok = false;
                }
            } else if err.IsNil() || err.Error() != string(want_err) {
                ok = false;
            }
            j += 1;
        }
        let (_, off, n) = s.Outer();
        if off != 2 || n != 5 {
            ok = false;
        }
        report(&mut failed, ok, "12", "SectionReader (+ Outer)");
    }

    // 13. OffsetWriter maps writes to base+off and rejects a negative
    //     seek. Both error values are the shared sentinels, so their
    //     text is stable across calls.
    {
        let mut ok = true;
        let mut w = io::NewOffsetWriter(
            Box::new(WriterAtBuf {
                b: b"..........".to_vec(),
            }),
            3,
        );
        let (n, err) = w.Write(slice::__from_vec(b"abc".to_vec()));
        if n != 3 || !err.IsNil() {
            ok = false;
        }
        let (n2, err2) = w.Write(slice::__from_vec(b"de".to_vec()));
        if n2 != 2 || !err2.IsNil() {
            ok = false;
        }
        let (pos, err3) = w.Seek(0, io::SeekStart);
        if pos != 0 || !err3.IsNil() {
            ok = false;
        }
        let (n3, err4) = w.Write(slice::__from_vec(b"XY".to_vec()));
        if n3 != 2 || !err4.IsNil() {
            ok = false;
        }
        let (p5, err5) = w.Seek(-1, io::SeekStart);
        if p5 != 0 || err5.IsNil() || err5.Error() != "Seek: invalid offset" {
            ok = false;
        }
        let (p6, err6) = w.Seek(0, 99);
        if p6 != 0 || err6.IsNil() || err6.Error() != "Seek: invalid whence" {
            ok = false;
        }
        report(&mut failed, ok, "13", "OffsetWriter (+ seek errors)");
    }

    // 14. MultiReader concatenates, skips an empty member without
    //     reporting EOF, and keeps returning EOF once drained.
    {
        let mut ok = true;
        let mut v: Vec<Box<dyn Reader>> = Vec::new();
        v.push(Box::new(sr("one ")));
        v.push(Box::new(sr("")));
        v.push(Box::new(sr("two ")));
        v.push(Box::new(sr("three")));
        let mut mr = io::MultiReader(slice::__from_vec(v));
        let (b, err) = io::ReadAll(&mut mr);
        if string::from_bytes(&b) != "one two three" || !err.IsNil() {
            ok = false;
        }

        let empty: Vec<Box<dyn Reader>> = Vec::new();
        let mut mr2 = io::MultiReader(slice::__from_vec(empty));
        let (b2, err2) = io::ReadAll(&mut mr2);
        if b2.Len() != 0 || !err2.IsNil() {
            ok = false;
        }

        // Go: each member is read on its own; the boundary is visible.
        let mut v3: Vec<Box<dyn Reader>> = Vec::new();
        v3.push(Box::new(sr("ab")));
        v3.push(Box::new(sr("cd")));
        let mut mr3 = io::MultiReader(slice::__from_vec(v3));
        let mut p = goish::make!([]byte, 3);
        let (a, _) = mr3.Read(&mut p);
        let (c, _) = mr3.Read(&mut p);
        let (e, erre) = mr3.Read(&mut p);
        let (f, errf) = mr3.Read(&mut p);
        if a != 2 || c != 2 || e != 0 || f != 0 {
            ok = false;
        }
        if !errors::Is(erre, io::EOF) || !errors::Is(errf, io::EOF) {
            ok = false;
        }
        report(&mut failed, ok, "14", "MultiReader concatenates");
    }

    // 15. MultiReader::WriteTo — dropped from the port until now. It
    //     drains every member through one buffer, leaves nothing behind
    //     for a second call, and on error keeps the members it has not
    //     reached so a retry does not replay what was already written.
    {
        let mut ok = true;
        let mut v: Vec<Box<dyn Reader>> = Vec::new();
        v.push(Box::new(sr("alpha")));
        v.push(Box::new(sr("-beta")));
        let mut mr = io::MultiReader(slice::__from_vec(v));
        let mut d = buf0();
        let (n, err) = mr.WriteTo(&mut d);
        if n != 10 || d.String() != "alpha-beta" || !err.IsNil() {
            ok = false;
        }
        let mut d2 = buf0();
        let (n2, err2) = mr.WriteTo(&mut d2);
        if n2 != 0 || d2.String() != "" || !err2.IsNil() {
            ok = false;
        }

        let boom = errors::New("boom");
        let mut v5: Vec<Box<dyn Reader>> = Vec::new();
        v5.push(Box::new(sr("aaa")));
        v5.push(Box::new(sr("bbb")));
        let mut mr5 = io::MultiReader(slice::__from_vec(v5));
        let mut ew = ErrWriter {
            left: 3,
            err: boom.clone(),
        };
        let (n5, err5) = mr5.WriteTo(&mut ew);
        if n5 != 3 || !errors::Is(err5, boom) {
            ok = false;
        }
        report(&mut failed, ok, "15", "MultiReader::WriteTo");
    }

    // 16. MultiWriter fans out, treats an empty list as a success of
    //     len(p), and stops at the first writer that falls short.
    {
        let mut ok = true;
        let (la, lb) = (Log::new(), Log::new());
        {
            let mut v: Vec<Box<dyn Writer>> = Vec::new();
            v.push(Box::new(PlainSink { log: la.clone() }));
            v.push(Box::new(PlainSink { log: lb.clone() }));
            let mut mw = io::MultiWriter(slice::__from_vec(v));
            let (n, err) = mw.Write(slice::__from_vec(b"dup".to_vec()));
            if n != 3 || !err.IsNil() {
                ok = false;
            }
        }
        if la.text() != "dup" || lb.text() != "dup" {
            ok = false;
        }

        let none: Vec<Box<dyn Writer>> = Vec::new();
        let mut mw2 = io::MultiWriter(slice::__from_vec(none));
        let (n2, err2) = mw2.Write(slice::__from_vec(b"nowhere".to_vec()));
        if n2 != 7 || !err2.IsNil() {
            ok = false;
        }

        // Go: multiwriter-short n=1 c="abc" sw="a" err=short write —
        // the earlier writer got everything, the short one stopped it.
        let (lc, lsw) = (Log::new(), Log::new());
        {
            let mut v: Vec<Box<dyn Writer>> = Vec::new();
            v.push(Box::new(PlainSink { log: lc.clone() }));
            v.push(Box::new(ShortWriter {
                n: 1,
                log: lsw.clone(),
            }));
            let mut mw3 = io::MultiWriter(slice::__from_vec(v));
            let (n3, err3) = mw3.Write(slice::__from_vec(b"abc".to_vec()));
            if n3 != 1 || !errors::Is(err3, io::ErrShortWrite) {
                ok = false;
            }
        }
        if lc.text() != "abc" || lsw.text() != "a" {
            ok = false;
        }

        let boom = errors::New("boom");
        let ld = Log::new();
        {
            let mut v: Vec<Box<dyn Writer>> = Vec::new();
            v.push(Box::new(PlainSink { log: ld.clone() }));
            v.push(Box::new(ErrWriter {
                left: 0,
                err: boom.clone(),
            }));
            let mut mw4 = io::MultiWriter(slice::__from_vec(v));
            let (n4, err4) = mw4.Write(slice::__from_vec(b"abc".to_vec()));
            if n4 != 0 || !errors::Is(err4, boom) {
                ok = false;
            }
        }
        if ld.text() != "abc" {
            ok = false;
        }
        report(&mut failed, ok, "16", "MultiWriter fans out");
    }

    // 17. MultiWriter::WriteString — dropped from the port until now.
    //     A member that implements StringWriter gets the string; the
    //     rest get the bytes, encoded once.
    {
        let mut ok = true;
        let (lss, lps) = (Log::new(), Log::new());
        {
            let mut v: Vec<Box<dyn Writer>> = Vec::new();
            v.push(Box::new(StringSink { log: lss.clone() }));
            v.push(Box::new(PlainSink { log: lps.clone() }));
            let mut mw = io::MultiWriter(slice::__from_vec(v));
            let (n, err) = mw.WriteString(string("héllo"));
            if n != 6 || !err.IsNil() {
                ok = false;
            }
        }
        fmt::Println!(
            "DBG sscalls=",
            lss.calls().len() as int,
            " pscalls=",
            lps.calls().len() as int
        );
        if lss.calls().len() > 0 {}
        if lps.calls().len() > 0 {}
        if lss.text() != "héllo" || lps.text() != "héllo" {
            ok = false;
        }
        // Go: ss=[WriteString] ps=[Write] — the assertion picked the
        // string path for the one that has it, and only that one.
        if lss.calls() != alloc::vec!["WriteString"] || lps.calls() != alloc::vec!["Write"] {
            ok = false;
        }
        report(&mut failed, ok, "17", "MultiWriter::WriteString");
    }

    // 18. Discard swallows everything, and its ReadFrom — also dropped
    //     until now — drains a reader and reports the count. EOF is the
    //     normal end; any other error surfaces with the bytes so far.
    {
        let mut ok = true;
        let mut d = io::DiscardWriter();
        let (n, err) = d.Write(slice::__from_vec(b"gone".to_vec()));
        if n != 4 || !err.IsNil() {
            ok = false;
        }
        let mut big = strings::NewReader(strings::Repeat(string("x"), 20000));
        let (m, err2) = io::Copy(&mut d, &mut big);
        if m != 20000 || !err2.IsNil() {
            ok = false;
        }
        let (m2, err3) = d.ReadFrom(&mut sr(""));
        if m2 != 0 || !err3.IsNil() {
            ok = false;
        }
        let boom = errors::New("boom");
        let mut er = ErrReader {
            n: 3,
            err: boom.clone(),
        };
        let (m3, err4) = d.ReadFrom(&mut er);
        if m3 != 3 || !errors::Is(err4, boom) {
            ok = false;
        }
        report(&mut failed, ok, "18", "Discard (+ ReadFrom)");
    }

    // 19. NopCloser reads through and closes to nil; the WriterTo half
    //     forwards WriteTo to the reader it wraps.
    {
        let mut ok = true;
        let mut nc = io::NopCloser(sr("wrapped"));
        let (b, err) = io::ReadAll(&mut nc);
        if string::from_bytes(&b) != "wrapped" || !err.IsNil() {
            ok = false;
        }
        if !nc.Close().IsNil() {
            ok = false;
        }
        let mut nc2 = io::NopCloserWriterTo(bytes::NewReader(slice::__from_vec(b"wt".to_vec())));
        let mut dst = buf0();
        let (n, err2) = nc2.WriteTo(&mut dst);
        if n != 2 || dst.String() != "wt" || !err2.IsNil() {
            ok = false;
        }
        if !nc2.Close().IsNil() {
            ok = false;
        }
        report(&mut failed, ok, "19", "NopCloser (+ WriterTo half)");
    }

    // 20. The sentinels are distinct values with the texts Go prints.
    {
        let mut ok = true;
        let want: [(error, &str); 6] = [
            (io::EOF.into(), "EOF"),
            (io::ErrShortWrite.into(), "short write"),
            (io::ErrUnexpectedEOF.into(), "unexpected EOF"),
            (io::ErrShortBuffer.into(), "short buffer"),
            (
                io::ErrNoProgress.into(),
                "multiple Read calls return no data or error",
            ),
            (io::ErrClosedPipe.into(), "io: read/write on closed pipe"),
        ];
        let mut i = 0;
        while i < want.len() {
            let (e, text) = &want[i];
            if e.Error() != string(*text) {
                ok = false;
            }
            i += 1;
        }
        // Distinct: EOF is not ErrUnexpectedEOF, and is itself.
        if errors::Is(io::EOF.into(), io::ErrUnexpectedEOF) {
            ok = false;
        }
        if !errors::Is(io::EOF.into(), io::EOF) {
            ok = false;
        }
        report(&mut failed, ok, "20", "sentinels are distinct values");
    }

    if failed == 0 {
        fmt::Println!("ok 20/20");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 20");
        syscall::Exit(1);
    }
}
