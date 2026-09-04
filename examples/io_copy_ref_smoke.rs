// io_copy_ref_smoke — which of Go's two `Copy` fast paths goish takes.
//
// Go's `copyBuffer` begins with `src.(WriterTo)`, then
// `dst.(ReaderFrom)`, and returns through whichever hits. goish always
// runs its 32 KiB loop. The BYTES are identical either way, so nothing
// here is a correctness bug — but the difference is observable to a
// writer that counts calls, and this pins it rather than leaving it to
// be discovered.
//
// The traits are real and the implementors ARE registered; `Copy`
// cannot ask. goish resolves an interface-on-interface assertion
// through a registry keyed on the concrete type, reached via
// `core::any`, which requires `'static`. `Copy` takes `&mut dyn
// Reader`, whose object lifetime is the borrow's. Requiring `'static`
// does not stay local — it breaks `CopyN`, which limits through a
// `LimitedReader<&mut dyn Reader>`, and cascades to every caller
// holding a reader by reference. Measured, not guessed: nine errors in
// this crate alone before reaching the examples.
//
// Each row is (Go, goish). Rows where they differ are marked
// DIVERGENT, and the last two — a reader with no WriteTo, and a
// destination with ReadFrom — agree, which is what says the gap is
// the assertion and not the loop.
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
     "strings.Reader             n=102400 writes=4 bytes=102400"),
    ("bytes.Reader               n=102400 writes=1 bytes=102400",
     "bytes.Reader               n=102400 writes=4 bytes=102400"),
    ("bytes.Buffer               n=102400 writes=1 bytes=102400",
     "bytes.Buffer               n=102400 writes=4 bytes=102400"),
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
