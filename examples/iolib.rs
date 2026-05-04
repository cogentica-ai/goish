// Milestone 6 smoke test: io package.
//
// Tests Reader/Writer traits via in-memory implementations, EOF
// sentinel pointer-stability, io::Copy, io::WriteString.

#![no_std]
#![no_main]

use goish::errors;
use goish::io;
use goish::{append, byte, error, int, make, nil, slice, string, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

// ─── In-memory Writer that appends to a buffer ──────────────────────

struct BufWriter {
    buf: slice<byte>,
}

impl io::Writer for BufWriter {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        let n = p.Len();
        let mut tmp = core::mem::take(&mut self.buf);
        for (_, b) in goish::range!(p) {
            tmp = append!(tmp, *b);
        }
        self.buf = tmp;
        (n, nil.into())
    }
}

// ─── In-memory Reader that yields a buffer slice once, then EOF ─────

struct BufReader {
    buf: slice<byte>,
    pos: int,
}

impl io::Reader for BufReader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        if self.pos >= self.buf.Len() {
            return (0, io::EOF.into());
        }
        let mut written: int = 0;
        let cap_p = p.Len();
        for i in 0..cap_p {
            let src_idx = self.pos + i;
            if src_idx >= self.buf.Len() {
                break;
            }
            // Mutate p in place.
            (*p)[i] = self.buf[src_idx];
            written += 1;
        }
        self.pos += written;
        (written, nil.into())
    }
}

#[goish::main]
fn main() {
    // (1) Writer trait — in-memory append.
    let mut w = BufWriter {
        buf: make!([]byte, 0, 8),
    };
    let payload = goish::bytes(string("hello"));
    let (n, err) = io::Writer::Write(&mut w, payload);
    check(n == 5, b"io: BufWriter wrote wrong count\n");
    check(err == nil, b"io: BufWriter err non-nil\n");
    check(w.buf.Len() == 5, b"io: BufWriter buf len wrong\n");
    check(w.buf[0] == b'h' && w.buf[4] == b'o', b"io: BufWriter bytes wrong\n");

    // (2) WriteString convenience.
    let mut w2 = BufWriter {
        buf: make!([]byte, 0, 8),
    };
    let (n, err) = io::WriteString(&mut w2, string("world"));
    check(n == 5, b"io: WriteString count\n");
    check(err == nil, b"io: WriteString err\n");
    check(w2.buf.Len() == 5, b"io: WriteString len\n");

    // (3) EOF is pointer-stable across calls.
    let e1: error = io::EOF.into();
    let e2: error = io::EOF.into();
    check(e1 == e2, b"io: EOF.into() must be ptr-stable across calls\n");
    check(errors::Is(e1.clone(), e2.clone()), b"io: EOF.into() errors::Is failed\n");

    // (4) Other sentinels are also stable. With Doctrine 2 markers,
    // bare `==` works directly (no `.into()` needed at compare positions).
    let sw1: errors::error = io::ErrShortWrite.into();
    let sw2: errors::error = io::ErrShortWrite.into();
    check(sw1 == sw2, b"io: ErrShortWrite stable\n");
    let uf1: errors::error = io::ErrUnexpectedEOF.into();
    let uf2: errors::error = io::ErrUnexpectedEOF.into();
    check(uf1 == uf2, b"io: ErrUnexpectedEOF stable\n");
    check(e1 != io::ErrShortWrite, b"io: distinct sentinels distinct\n");

    // (5) Reader trait — read until EOF.
    let mut r = BufReader {
        buf: goish::bytes(string("abcdefghij")),
        pos: 0,
    };
    let mut out = make!([]byte, 4);
    let (n, err) = io::Reader::Read(&mut r, &mut out);
    check(n == 4 && err == nil, b"io: first Read wrong\n");
    check(out[0] == b'a' && out[3] == b'd', b"io: first Read bytes wrong\n");

    let (n, err) = io::Reader::Read(&mut r, &mut out);
    check(n == 4 && err == nil, b"io: second Read wrong\n");
    check(out[0] == b'e' && out[3] == b'h', b"io: second Read bytes wrong\n");

    let (n, err) = io::Reader::Read(&mut r, &mut out);
    check(n == 2 && err == nil, b"io: third Read short\n");

    let (n, err) = io::Reader::Read(&mut r, &mut out);
    check(n == 0 && err == io::EOF, b"io: fourth Read should EOF\n");

    // (6) io::Copy — Reader → Writer round-trip.
    let mut src = BufReader {
        buf: goish::bytes(string("the quick brown fox")),
        pos: 0,
    };
    let mut dst = BufWriter {
        buf: make!([]byte, 0, 32),
    };
    let (copied, err) = io::Copy(&mut dst, &mut src);
    check(err == nil, b"io: Copy err\n");
    check(copied == 19, b"io: Copy bytes count\n");
    check(dst.buf.Len() == 19, b"io: Copy dst length\n");
    check(dst.buf[0] == b't' && dst.buf[18] == b'x', b"io: Copy dst contents\n");

    const OK: &[u8] = b"io: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
