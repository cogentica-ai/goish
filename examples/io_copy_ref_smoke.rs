// io_copy_ref_smoke — that `Copy` takes Go's WriterTo fast path.
//
// Go's `copyBuffer` begins with `src.(WriterTo)`, then
// `dst.(ReaderFrom)`, and returns through whichever hits. goish ran its
// 32 KiB loop unconditionally: the traits were real and the
// implementors registered, but the assertion could not see through a
// `&mut dyn Reader`, so copying 100 KiB out of a `strings.Reader` was
// four `Write` calls where Go makes one.
//
// The bytes were never in question — this is a count of write calls,
// not correctness — but the same miss is what keeps `archive/tar`'s
// sparse `WriteTo` unreachable, and that one is a real behaviour
// difference: Go seeks over holes and writes a sparse file to disk.
//
// Two things had to be true at once. The assertion goes through
// `core::any`, so `src` must be `'static`; that costs one call site,
// `CopyN`, which limits through a borrowing `LimitedReader` and now
// uses the loop directly. And the concrete types need
// `__goish_as_dyn_any_mut`, the `&mut` twin of a hook this tree
// overrides 162 times in its immutable form and had almost nowhere in
// its mutable one — which is why the assertion missed even for
// `strings::Reader`, a type that IS registered for `WriterTo`.
//
// `dst.(ReaderFrom)` is deliberately NOT taken: the same `'static`
// requirement on a destination would refuse a writer that borrows, and
// `http::AsWriter(w)` over a `&dyn ResponseWriter` is exactly that.
// Refusing writers Go accepts is not worth a count of write calls. So
// the last row is not a fast path — it checks that a destination with
// ReadFrom still receives every byte through the loop.
//
// The fourth row is the control that did not move: a reader with no
// WriteTo puts Go in the same loop goish uses.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::errors::{error, nil};
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io;
use goish::strings;
use goish::types::{byte, int};

// (Go 1.25.5, goish)
const ROWS: [(&str, &str); 5] = [
    ("strings.Reader             n=102400 writes=1 bytes=102400",
     "strings.Reader             n=102400 writes=1 bytes=102400"),
    ("bytes.Reader               n=102400 writes=1 bytes=102400",
     "bytes.Reader               n=102400 writes=1 bytes=102400"),
    ("bytes.Buffer               n=102400 writes=1 bytes=102400",
     "bytes.Buffer               n=102400 writes=1 bytes=102400"),
    ("plain (no WriteTo)         n=102400 writes=4 bytes=102400",
     "plain (no WriteTo)         n=102400 writes=4 bytes=102400"),
    ("dst bytes.Buffer           n=102400 len=102400",
     "dst bytes.Buffer           n=102400 len=102400"),
];

struct countWriter {
    writes: int,
    bytes: int,
}

impl io::Writer for countWriter {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        self.writes += 1;
        self.bytes += p.Len();
        return (p.Len(), nil);
    }
}

// A Reader with no WriteTo of its own — the control.
struct plainReader {
    r: strings::Reader,
}

impl io::Reader for plainReader {
    fn Read(&mut self, b: &mut slice<byte>) -> (int, error) {
        return self.r.Read(b);
    }
}

fn chk(ln: &mut usize, got: &string) {
    if *ln >= ROWS.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        *ln += 1;
        return;
    }
    let (go, want) = ROWS[*ln];
    if got == want {
        if want == go {
            fmt::Printf!("[ok] %s\n", got);
        } else {
            fmt::Printf!("[DIVERGENT] %s\n           Go: %s\n", got, go);
        }
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, want);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;
    let big = strings::Repeat("x", 100 * 1024);

    // strings.Reader implements WriterTo and is registered for it.
    let mut cw = countWriter { writes: 0, bytes: 0 };
    let mut sr = strings::NewReader(&big);
    let (n, _) = io::Copy(&mut cw, &mut sr);
    chk(&mut ln, &fmt::Sprintf!("%-26s n=%d writes=%d bytes=%d",
        "strings.Reader", n, cw.writes, cw.bytes));

    let mut cw = countWriter { writes: 0, bytes: 0 };
    let mut br = bytes::NewReader(goish::convert::bytes(big.clone()));
    let (n, _) = io::Copy(&mut cw, &mut br);
    chk(&mut ln, &fmt::Sprintf!("%-26s n=%d writes=%d bytes=%d",
        "bytes.Reader", n, cw.writes, cw.bytes));

    let mut cw = countWriter { writes: 0, bytes: 0 };
    let mut bb = bytes::NewBufferString(&big);
    let (n, _) = io::Copy(&mut cw, &mut bb);
    chk(&mut ln, &fmt::Sprintf!("%-26s n=%d writes=%d bytes=%d",
        "bytes.Buffer", n, cw.writes, cw.bytes));

    // No WriteTo: Go falls into the same loop goish always uses, so
    // this row AGREES. That is the control — it says the divergence
    // above is the missing assertion, not a different buffer size.
    let mut cw = countWriter { writes: 0, bytes: 0 };
    let mut pr = plainReader { r: strings::NewReader(&big) };
    let (n, _) = io::Copy(&mut cw, &mut pr);
    chk(&mut ln, &fmt::Sprintf!("%-26s n=%d writes=%d bytes=%d",
        "plain (no WriteTo)", n, cw.writes, cw.bytes));

    // Destination with ReadFrom: same bytes arrive either way.
    let mut dst = bytes::NewBuffer(slice::new());
    let mut pr = plainReader { r: strings::NewReader(&big) };
    let (n, _) = io::Copy(&mut dst, &mut pr);
    chk(&mut ln, &fmt::Sprintf!("%-26s n=%d len=%d",
        "dst bytes.Buffer", n, dst.Len() as int));

    if ln != ROWS.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, ROWS.len() as int);
    }
}
