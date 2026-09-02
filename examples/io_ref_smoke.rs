// io_ref_smoke — the io package against a running Go.
// (io/io.go, io/multi.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_io_ref.go` run in
// `package io_test` by `scripts/goref.sh`.
//
// io is where the reader and writer CONTRACTS are defined, so its edge
// cases are not niceties — every other package's behaviour is quoted
// from here, and goish had 1717 lines of it with no reference test.
// Four rules are easy to get subtly wrong while every ordinary copy
// still works:
//
//   * ReadFull and ReadAtLeast distinguish THREE outcomes: nothing read
//     is io.EOF, something-but-not-enough is io.ErrUnexpectedEOF, and
//     enough is nil. Collapsing the middle case into EOF loses the
//     difference between "the stream ended cleanly" and "the stream was
//     cut off mid-record" — exactly the difference a framed protocol
//     exists to detect.
//   * CopyN returns io.EOF when it copied FEWER than n bytes and nil
//     when it copied exactly n, even though it reached the end either
//     way.
//   * A Copy from a reader that returns (n>0, io.EOF) in ONE call must
//     keep those n bytes and report success. The io.Reader docs permit
//     that shape explicitly; treating a non-nil error as "discard the
//     read" truncates silently.
//   * LimitReader is not a slice: it reports io.EOF at the limit, and a
//     LimitedReader with a non-positive N reads nothing at all.
//
// The errors are sentinels, so identity is what callers test with
// errors.Is — a look-alike message is not the same value. Every one is
// checked for self-identity and against io.EOF here.
//
// goish matched Go on all 66 lines, which is worth recording as
// plainly as a defect would be: the contracts that bytes.Buffer got
// wrong in 83b9969 are right at their source.
//
// Two goish shape differences show up in the harness rather than the
// results. Go passes &buf straight to MultiWriter and TeeReader;
// goish's take owned boxes, so the destinations are shared explicitly
// through an Arc<Mutex<...>> and printed on their own line. And Go
// prints whether ReadAll's result is nil (it never is on success);
// goish's slice has no nil form to distinguish.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::boxed::Box;
use alloc::sync::Arc;
use goish::errors;
use goish::errors::error;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io::{Closer, Reader, Writer};
use goish::sync::Mutex;
use goish::types::{byte, int};
use goish::{bytes, fmt, io, strings, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn buf(n: usize) -> slice<byte> {
    return slice::__from_vec(alloc::vec![0u8; n]);
}
fn head(p: &slice<byte>, n: int) -> slice<byte> {
    let pv: &[u8] = p;
    return slice::__from_vec(pv[..n as usize].to_vec());
}

// A reader that returns all of its data and io.EOF in the SAME call,
// which the io.Reader docs explicitly permit.
struct DataThenEOF {
    data: alloc::vec::Vec<u8>,
    done: bool,
}
impl Reader for DataThenEOF {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        if self.done {
            return (0, io::EOF.into());
        }
        self.done = true;
        let n = core::cmp::min(p.Len() as usize, self.data.len());
        for i in 0..n {
            p[i as int] = self.data[i];
        }
        return (n as int, io::EOF.into());
    }
}
// A Writer that appends into a buffer the caller still holds, so the
// destination can be inspected after the MultiWriter that owns the
// writer is gone. Go passes &buf directly; goish's MultiWriter takes
// owned boxes, so the sharing is explicit.
struct TapWriter {
    into: Arc<Mutex<alloc::vec::Vec<u8>>>,
}
impl Writer for TapWriter {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        let pv: &[u8] = &p;
        self.into.Lock().extend_from_slice(pv);
        return (p.Len(), errors::nil);
    }
}

struct ShortWriter;
impl Writer for ShortWriter {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return (p.Len() / 2, errors::nil);
    }
}
struct ErrReader {
    err: error,
}
impl Reader for ErrReader {
    fn Read(&mut self, _p: &mut slice<byte>) -> (int, error) {
        return (0, self.err.clone());
    }
}
struct PartialThenErr {
    data: alloc::vec::Vec<u8>,
    done: bool,
}
impl Reader for PartialThenErr {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        if self.done {
            return (0, errors::New(s("read failed")));
        }
        self.done = true;
        let n = core::cmp::min(p.Len() as usize, self.data.len());
        for i in 0..n {
            p[i as int] = self.data[i];
        }
        return (n as int, errors::nil);
    }
}

// go: none — goish idiom: the reference lines, in the order Go printed
//     them. Comparing whole rendered lines keeps this smoke and the
//     generator in lockstep: a case added to one is a mismatch in the
//     other, never a silent pass.
const GO: [&str; 66] = [
    "readfull src=\"hello\" size=5  -> n=5  err=<nil>                isEOF=false isUnexp=false",
    "readatleast src=\"hello\" size=5  min=5  -> n=5  err=<nil>",
    "readfull src=\"hello\" size=3  -> n=3  err=<nil>                isEOF=false isUnexp=false",
    "readatleast src=\"hello\" size=3  min=3  -> n=3  err=<nil>",
    "readfull src=\"hello\" size=8  -> n=5  err=unexpected EOF       isEOF=false isUnexp=true",
    "readatleast src=\"hello\" size=8  min=8  -> n=5  err=unexpected EOF",
    "readfull src=\"\"      size=4  -> n=0  err=EOF                  isEOF=true  isUnexp=false",
    "readatleast src=\"\"      size=4  min=4  -> n=0  err=EOF",
    "readfull src=\"ab\"    size=4  -> n=2  err=unexpected EOF       isEOF=false isUnexp=true",
    "readatleast src=\"ab\"    size=4  min=4  -> n=2  err=unexpected EOF",
    "readfull src=\"hello\" size=5  -> n=5  err=<nil>                isEOF=false isUnexp=false",
    "readatleast src=\"hello\" size=5  min=3  -> n=5  err=<nil>",
    "readfull src=\"ab\"    size=5  -> n=2  err=unexpected EOF       isEOF=false isUnexp=true",
    "readatleast src=\"ab\"    size=5  min=2  -> n=2  err=<nil>",
    "readfull src=\"ab\"    size=5  -> n=2  err=unexpected EOF       isEOF=false isUnexp=true",
    "readatleast src=\"ab\"    size=5  min=3  -> n=2  err=unexpected EOF",
    "readfull src=\"hello\" size=0  -> n=0  err=<nil>                isEOF=false isUnexp=false",
    "readatleast src=\"hello\" size=0  min=0  -> n=0  err=<nil>",
    "readfull src=\"\"      size=0  -> n=0  err=<nil>                isEOF=false isUnexp=false",
    "readatleast src=\"\"      size=0  min=0  -> n=0  err=<nil>",
    "readfull src=\"hello\" size=3  -> n=3  err=<nil>                isEOF=false isUnexp=false",
    "readatleast src=\"hello\" size=3  min=5  -> n=0  err=short buffer",
    "copyn src=\"hello world\" n=5   -> wrote=5  err=<nil>    isEOF=false dst=\"hello\"",
    "copyn src=\"hello\"       n=5   -> wrote=5  err=<nil>    isEOF=false dst=\"hello\"",
    "copyn src=\"hello\"       n=6   -> wrote=5  err=EOF      isEOF=true  dst=\"hello\"",
    "copyn src=\"\"            n=3   -> wrote=0  err=EOF      isEOF=true  dst=\"\"",
    "copyn src=\"abc\"         n=0   -> wrote=0  err=<nil>    isEOF=false dst=\"\"",
    "copyn src=\"abc\"         n=-1  -> wrote=0  err=<nil>    isEOF=false dst=\"\"",
    "copy n=7 err=<nil> dst=\"copy me\"",
    "copy-empty n=0 err=<nil> dst=\"\"",
    "copy-data-with-eof n=7 err=<nil> dst=\"payload\"",
    "readfull-data-with-eof n=2 err=<nil> p=\"xy\"",
    "copy-shortwrite n=3 err=short write isShort=true",
    "copy-err n=0 err=boom same=true dst=\"\"",
    "limit n=0   -> \"\" err=<nil>",
    "limit n=3   -> \"abc\" err=<nil>",
    "limit n=5   -> \"abcde\" err=<nil>",
    "limit n=9   -> \"abcde\" err=<nil>",
    "limit n=-1  -> \"\" err=<nil>",
    "limited read n=2 err=<nil> p=\"ab\" remaining=0",
    "limited read2 n=0 err=EOF remaining=0",
    "multireader \"abcde\" err=<nil>",
    "multireader-empty \"\" err=<nil>",
    "multireader-empty-read n=0 err=EOF",
    "multiwriter n=3 err=<nil>",
    "multiwriter-ws n=1 err=<nil>",
    "multiwriter-dst a=\"dup!\" b=\"dup!\"",
    "teereader \"teed\" err=<nil>",
    "teereader-side \"teed\"",
    "section size=5",
    "section read \"23456\" err=<nil>",
    "section readat n=3 err=<nil> p=\"345\"",
    "section readat-end n=1 err=EOF p=\"6\"",
    "section readat-past err=EOF",
    "section seek-end off=4 err=<nil>",
    "readall-err \"partial\" err=read failed",
    "readall-empty \"\" err=<nil>",
    "nopcloser \"nop\" close=<nil>",
    "sentinel EOF                \"EOF\" selfIs=true isEOF=true",
    "sentinel ErrUnexpectedEOF   \"unexpected EOF\" selfIs=true isEOF=false",
    "sentinel ErrShortWrite      \"short write\" selfIs=true isEOF=false",
    "sentinel ErrShortBuffer     \"short buffer\" selfIs=true isEOF=false",
    "sentinel ErrClosedPipe      \"io: read/write on closed pipe\" selfIs=true isEOF=false",
    "sentinel ErrNoProgress      \"multiple Read calls return no data or error\" selfIs=true isEOF=false",
    "discard n=11 err=<nil>",
    "discard-ws n=1 err=<nil>",
];

// go: none — goish idiom: one comparison, printing the divergence when
//     it is one, so a FAIL says what it got and not just that it did.
fn chk(failed: &mut int, ln: &mut int, got: string) {
    if *ln >= GO.len() as int {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln + 1, got);
        *failed += 1;
        *ln += 1;
        return;
    }
    let want = s(GO[*ln as usize]);
    *ln += 1;
    if got == want {
        return;
    }
    fmt::Printf!("[!!] line %d FAIL\n  got  %q\n  want %q\n", *ln, got, want);
    *failed += 1;
}

#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;

    // 1
    let rf: [(&str, usize, int); 11] = [
        ("hello", 5, 5),
        ("hello", 3, 3),
        ("hello", 8, 8),
        ("", 4, 4),
        ("ab", 4, 4),
        ("hello", 5, 3),
        ("ab", 5, 2),
        ("ab", 5, 3),
        ("hello", 0, 0),
        ("", 0, 0),
        ("hello", 3, 5),
    ];
    for (src, size, min) in rf.iter() {
        let mut p = buf(*size);
        let mut r = strings::NewReader(s(src));
        let (n, err) = io::ReadFull(&mut r, &mut p);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "readfull src=%-7q size=%-2d -> n=%-2d err=%-20v isEOF=%-5v isUnexp=%v",
                s(src),
                *size as int,
                n,
                err,
                errors::Is(err.clone(), io::EOF),
                errors::Is(err.clone(), io::ErrUnexpectedEOF)
            ),
        );
        let mut p2 = buf(*size);
        let mut r2 = strings::NewReader(s(src));
        let (n2, err2) = io::ReadAtLeast(&mut r2, &mut p2, *min);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "readatleast src=%-7q size=%-2d min=%-2d -> n=%-2d err=%v",
                s(src),
                *size as int,
                *min,
                n2,
                err2
            ),
        );
    }
    // 2
    for (src, n) in [
        ("hello world", 5i64),
        ("hello", 5),
        ("hello", 6),
        ("", 3),
        ("abc", 0),
        ("abc", -1),
    ]
    .iter()
    {
        let mut dst = bytes::Buffer::new();
        let mut r = strings::NewReader(s(src));
        let (wrote, err) = io::CopyN(&mut dst, &mut r, *n);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "copyn src=%-13q n=%-3d -> wrote=%-2d err=%-8v isEOF=%-5v dst=%q",
                s(src),
                *n,
                wrote,
                err,
                errors::Is(err.clone(), io::EOF),
                dst.String()
            ),
        );
    }
    {
        let mut dst = bytes::Buffer::new();
        let mut r = strings::NewReader(s("copy me"));
        let (n, err) = io::Copy(&mut dst, &mut r);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("copy n=%d err=%v dst=%q", n, err, dst.String()),
        );
        let mut empty = bytes::Buffer::new();
        let mut r2 = strings::NewReader(s(""));
        let (n, err) = io::Copy(&mut empty, &mut r2);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("copy-empty n=%d err=%v dst=%q", n, err, empty.String()),
        );
    }
    {
        let mut dst = bytes::Buffer::new();
        let mut r = DataThenEOF {
            data: b"payload".to_vec(),
            done: false,
        };
        let (n, err) = io::Copy(&mut dst, &mut r);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "copy-data-with-eof n=%d err=%v dst=%q",
                n,
                err,
                dst.String()
            ),
        );
        let mut r2 = DataThenEOF {
            data: b"xy".to_vec(),
            done: false,
        };
        let mut p = buf(2);
        let (rn, rerr) = io::ReadFull(&mut r2, &mut p);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "readfull-data-with-eof n=%d err=%v p=%q",
                rn,
                rerr,
                head(&p, rn)
            ),
        );
    }
    {
        let mut w = ShortWriter;
        let mut r = strings::NewReader(s("abcdef"));
        let (n, err) = io::Copy(&mut w, &mut r);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "copy-shortwrite n=%d err=%v isShort=%v",
                n,
                err,
                errors::Is(err.clone(), io::ErrShortWrite)
            ),
        );
    }
    {
        let mut dst = bytes::Buffer::new();
        let boom = errors::New(s("boom"));
        let mut r = ErrReader { err: boom.clone() };
        let (n, err) = io::Copy(&mut dst, &mut r);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "copy-err n=%d err=%v same=%v dst=%q",
                n,
                err,
                errors::Is(err.clone(), boom.clone()),
                dst.String()
            ),
        );
    }
    // 3
    for lim in [0i64, 3, 5, 9, -1] {
        let mut lr = io::LimitReader(strings::NewReader(s("abcde")), lim as int);
        let (b, err) = io::ReadAll(&mut lr);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("limit n=%-3d -> %q err=%v", lim, b, err),
        );
    }
    {
        let mut lr = io::LimitReader(strings::NewReader(s("abcde")), 2);
        let mut p = buf(4);
        let (n, err) = lr.Read(&mut p);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "limited read n=%d err=%v p=%q remaining=%d",
                n,
                err,
                head(&p, n),
                lr.N
            ),
        );
        let (n, err) = lr.Read(&mut p);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("limited read2 n=%d err=%v remaining=%d", n, err, lr.N),
        );
    }
    // 4
    {
        let rs: slice<Box<dyn Reader>> = slice::__from_vec(alloc::vec![
            Box::new(strings::NewReader(s("abc"))) as Box<dyn Reader>,
            Box::new(strings::NewReader(s(""))) as Box<dyn Reader>,
            Box::new(strings::NewReader(s("de"))) as Box<dyn Reader>,
        ]);
        let mut mr = io::MultiReader(rs);
        let (b, err) = io::ReadAll(&mut mr);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("multireader %q err=%v", b, err),
        );
        let none: slice<Box<dyn Reader>> = slice::__from_vec(alloc::vec![]);
        let mut empty = io::MultiReader(none);
        let (b, err) = io::ReadAll(&mut empty);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("multireader-empty %q err=%v", b, err),
        );
        let mut p = buf(4);
        let (n, err) = empty.Read(&mut p);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("multireader-empty-read n=%d err=%v", n, err),
        );
    }
    {
        let a = Arc::new(Mutex::new(alloc::vec::Vec::new()));
        let bb = Arc::new(Mutex::new(alloc::vec::Vec::new()));
        {
            let ws: slice<Box<dyn Writer>> = slice::__from_vec(alloc::vec![
                Box::new(TapWriter { into: a.clone() }) as Box<dyn Writer>,
                Box::new(TapWriter { into: bb.clone() }) as Box<dyn Writer>,
            ]);
            let mut mw = io::MultiWriter(ws);
            let (n, err) = mw.Write(slice::__from_vec(b"dup".to_vec()));
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("multiwriter n=%d err=%v", n, err),
            );
            let (n, err) = io::WriteString(&mut mw, s("!"));
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("multiwriter-ws n=%d err=%v", n, err),
            );
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "multiwriter-dst a=%q b=%q",
                string::from_bytes(&a.Lock()),
                string::from_bytes(&bb.Lock())
            ),
        );
    }
    {
        let side = Arc::new(Mutex::new(alloc::vec::Vec::new()));
        {
            let mut tr = io::TeeReader(
                strings::NewReader(s("teed")),
                TapWriter { into: side.clone() },
            );
            let (b, err) = io::ReadAll(&mut tr);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("teereader %q err=%v", b, err),
            );
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("teereader-side %q", string::from_bytes(&side.Lock())),
        );
    }
    // 5
    {
        let mut sr = io::NewSectionReader(
            Box::new(bytes::NewReader(slice::__from_vec(b"0123456789".to_vec()))),
            2,
            5,
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("section size=%d", sr.Size()),
        );
        let (b, err) = io::ReadAll(&mut sr);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("section read %q err=%v", b, err),
        );
        let mut sr2 = io::NewSectionReader(
            Box::new(bytes::NewReader(slice::__from_vec(b"0123456789".to_vec()))),
            2,
            5,
        );
        let mut p = buf(3);
        let (n, err) = sr2.ReadAt(&mut p, 1);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("section readat n=%d err=%v p=%q", n, err, head(&p, n)),
        );
        let (n, err) = sr2.ReadAt(&mut p, 4);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("section readat-end n=%d err=%v p=%q", n, err, head(&p, n)),
        );
        let (_, err) = sr2.ReadAt(&mut p, 9);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("section readat-past err=%v", err),
        );
        let (off, err) = sr2.Seek(-1, io::SeekEnd);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("section seek-end off=%d err=%v", off, err),
        );
    }
    // 6
    {
        let mut r = PartialThenErr {
            data: b"partial".to_vec(),
            done: false,
        };
        let (b, err) = io::ReadAll(&mut r);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("readall-err %q err=%v", b, err),
        );
        let mut r2 = strings::NewReader(s(""));
        let (b, err) = io::ReadAll(&mut r2);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("readall-empty %q err=%v", b, err),
        );
    }
    {
        let mut rc = io::NopCloser(strings::NewReader(s("nop")));
        let (b, _) = io::ReadAll(&mut rc);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("nopcloser %q close=%v", b, rc.Close()),
        );
    }
    // 7
    let sentinels: [(&str, error); 6] = [
        ("EOF", io::EOF.into()),
        ("ErrUnexpectedEOF", io::ErrUnexpectedEOF.into()),
        ("ErrShortWrite", io::ErrShortWrite.into()),
        ("ErrShortBuffer", io::ErrShortBuffer.into()),
        ("ErrClosedPipe", io::ErrClosedPipe.into()),
        ("ErrNoProgress", io::ErrNoProgress.into()),
    ];
    for (name, e) in sentinels.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "sentinel %-18s %q selfIs=%v isEOF=%v",
                s(name),
                e.Error(),
                errors::Is(e.clone(), e.clone()),
                errors::Is(e.clone(), io::EOF)
            ),
        );
    }
    // 8
    {
        let mut d = io::DiscardWriter();
        let mut r = strings::NewReader(s("thrown away"));
        let (n, err) = io::Copy(&mut d, &mut r);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("discard n=%d err=%v", n, err),
        );
        let (n2, err2) = io::WriteString(&mut d, s("x"));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("discard-ws n=%d err=%v", n2, err2),
        );
    }
    if ln != GO.len() as int {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln, GO.len() as int);
        failed += 1;
    }
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", ln, ln);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, ln);
    syscall::Exit(1);
}
