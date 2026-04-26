// Milestone 12.5 smoke test: bufio Scanner.
//
// Covers ScanLines (CRLF, missing trailing newline, empty lines),
// ScanWords (whitespace runs), ScanBytes (one byte per token),
// custom split via Split(), and Err() returning nil at EOF.

#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec::Vec;

use goish::{bufio, byte, int, io, nil, slice, string, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

// In-memory `io::Reader` over a byte buffer. Returns EOF when exhausted.
struct ByteReader {
    data: Vec<byte>,
    pos: usize,
}

impl ByteReader {
    fn new(s: &[u8]) -> Self {
        Self {
            data: s.to_vec(),
            pos: 0,
        }
    }
}

impl io::Reader for ByteReader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, goish::error) {
        if self.pos >= self.data.len() {
            return (0, io::EOF());
        }
        let want = (p.Len() as usize).min(self.data.len() - self.pos);
        for i in 0..want {
            p[i as int] = self.data[self.pos + i];
        }
        self.pos += want;
        (want as int, nil)
    }
}

fn collect_lines(input: &[u8]) -> slice<string> {
    let r = ByteReader::new(input);
    let mut sc = bufio::NewScanner(r);
    let mut out = goish::make!([]string, 0, 4);
    while sc.Scan() {
        out = goish::append!(out, sc.Text());
    }
    check(sc.Err() == nil, b"bufio: Err must be nil at EOF\n");
    out
}

#[goish::main]
fn main() {
    use goish::slices;

    // (1) Two simple lines, '\n' terminated.
    let lines = collect_lines(b"hello\nworld\n");
    let want: slice<string> = goish::slice!([]string{ "hello", "world" });
    check(slices::Equal(&lines, &want), b"bufio: simple two-line wrong\n");

    // (2) Trailing newline missing — last line still returned.
    let lines = collect_lines(b"hello\nworld");
    check(slices::Equal(&lines, &want), b"bufio: missing-newline last-line wrong\n");

    // (3) CRLF line endings stripped.
    let lines = collect_lines(b"hello\r\nworld\r\n");
    check(slices::Equal(&lines, &want), b"bufio: CRLF strip wrong\n");

    // (4) Empty input → no lines, no error.
    let lines = collect_lines(b"");
    check(lines.Len() == 0, b"bufio: empty input must yield 0 lines\n");

    // (5) Empty lines preserved.
    let lines = collect_lines(b"a\n\nb\n");
    let want: slice<string> = goish::slice!([]string{ "a", "", "b" });
    check(slices::Equal(&lines, &want), b"bufio: empty-line preservation wrong\n");

    // (6) ScanWords — split on whitespace runs.
    let r = ByteReader::new(b"  foo \t bar\n  baz  ");
    let mut sc = bufio::NewScanner(r);
    sc.Split(bufio::ScanWords);
    let mut words = goish::make!([]string, 0, 4);
    while sc.Scan() {
        words = goish::append!(words, sc.Text());
    }
    check(sc.Err() == nil, b"bufio: ScanWords Err must be nil\n");
    let want: slice<string> = goish::slice!([]string{ "foo", "bar", "baz" });
    check(slices::Equal(&words, &want), b"bufio: ScanWords wrong\n");

    // (7) ScanBytes — one byte per token over "abc".
    let r = ByteReader::new(b"abc");
    let mut sc = bufio::NewScanner(r);
    sc.Split(bufio::ScanBytes);
    let mut count = 0;
    let mut last = 0u8;
    while sc.Scan() {
        let b = sc.Bytes();
        check(b.Len() == 1, b"bufio: ScanBytes token must be 1 byte\n");
        last = b[0 as int];
        count += 1;
    }
    check(count == 3, b"bufio: ScanBytes count must be 3\n");
    check(last == b'c', b"bufio: ScanBytes last byte must be 'c'\n");

    // (8) Custom split function — split on ';' separator.
    let r = ByteReader::new(b"alpha;beta;gamma");
    let mut sc = bufio::NewScanner(r);
    sc.Split(|data: &[byte], at_eof: bool| {
        let mut i = 0usize;
        while i < data.len() {
            if data[i] == b';' {
                return (
                    (i + 1) as int,
                    Some(slice::__from_vec(data[..i].to_vec())),
                    nil,
                );
            }
            i += 1;
        }
        if at_eof && !data.is_empty() {
            return (data.len() as int, Some(slice::__from_vec(data.to_vec())), nil);
        }
        (0, None, nil)
    });
    let mut out = goish::make!([]string, 0, 3);
    while sc.Scan() {
        out = goish::append!(out, sc.Text());
    }
    let want: slice<string> = goish::slice!([]string{ "alpha", "beta", "gamma" });
    check(slices::Equal(&out, &want), b"bufio: custom split wrong\n");

    const OK: &[u8] = b"bufio: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
