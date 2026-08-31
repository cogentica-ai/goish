// qp_smoke — exercise mime/quotedprintable.
// (mime/quotedprintable/{reader.go, writer.go})
//
// Every expectation below is what a real Go 1.25.5 prints: the tables
// are the output of `tools/gen_qp_ref.go` run inside
// mime/quotedprintable by `scripts/goref.sh`. The decoder is defined as
// much by what it tolerates as by what it decodes, so most of the read
// table is malformed input — a bare '=' at end of message, an '=' not
// followed by two hex digits, whitespace before a soft line break, a
// raw control byte — and the error text is checked, not just its
// presence.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::bytes;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io::Reader;
use goish::mime::quotedprintable::{NewReader, NewWriter};
use goish::syscall;
use goish::types::byte;

/// Drain a reader, keeping the error it stops on.
fn read_all<R: Reader>(r: &mut R) -> (Vec<byte>, goish::errors::error) {
    let mut out: Vec<byte> = Vec::new();
    let mut buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; 7]);
    loop {
        let (n, e) = r.Read(&mut buf);
        let mut i = 0i64;
        while i < n {
            out.push(buf[i]);
            i += 1;
        }
        if !e.IsNil() {
            return (out, e);
        }
    }
}

fn err_text(e: &goish::errors::error) -> Vec<byte> {
    let s = e.Error();
    let c = goish::convert::bytes(s);
    let r: &[byte] = &c;
    return r.to_vec();
}

fn gbytes(s: &string) -> Vec<byte> {
    let c = goish::convert::bytes(s.clone());
    let r: &[byte] = &c;
    return r.to_vec();
}

fn repeat(b: &[u8], n: usize) -> Vec<byte> {
    let mut v: Vec<byte> = Vec::new();
    let mut i = 0;
    while i < n {
        v.extend_from_slice(b);
        i += 1;
    }
    return v;
}

/// Decode `src`, returning the bytes and the error text ("" when nil).
fn decode(src: &[u8]) -> (Vec<byte>, Vec<byte>) {
    let mut buf = bytes::NewBuffer(slice::__from_vec(src.to_vec()));
    let mut r = NewReader(&mut buf);
    let (out, e) = read_all(&mut r);
    if goish::errors::Is(e.clone(), goish::io::EOF) || e.IsNil() {
        return (out, Vec::new());
    }
    return (out, err_text(&e));
}

/// Encode `src`, one `Write` for the whole input.
fn encode(src: &[u8], binary: bool) -> Vec<byte> {
    let mut buf = bytes::NewBuffer(slice::__from_vec(alloc::vec![]));
    {
        let mut w = NewWriter(&mut buf);
        w.Binary = binary;
        let _ = w.Write(slice::__from_vec(src.to_vec()));
        let _ = w.Close();
    }
    return gbytes(&buf.String());
}

/// Encode `src` one byte per `Write`, which crosses every line and
/// escape boundary mid-call.
fn encode1(src: &[u8], binary: bool) -> Vec<byte> {
    let mut buf = bytes::NewBuffer(slice::__from_vec(alloc::vec![]));
    {
        let mut w = NewWriter(&mut buf);
        w.Binary = binary;
        let mut i = 0usize;
        while i < src.len() {
            let one: Vec<byte> = alloc::vec![src[i]];
            let _ = w.Write(slice::__from_vec(one));
            i += 1;
        }
        let _ = w.Close();
    }
    return gbytes(&buf.String());
}

// Go's read table: (input, decoded output, error text — "" for nil).
const READ_CASES: [(&[u8], &[u8], &str); 35] = [
    (b"", b"", ""),
    (b"foo bar", b"foo bar", ""),
    (b"foo bar=3D", b"foo bar=", ""),
    (b"foo bar=\n", b"foo bar", ""),
    (b"foo bar\n", b"foo bar\n", ""),
    (b"foo bar=0", b"foo bar=0", ""),
    (b"foo bar=0D=0A", b"foo bar\r\n", ""),
    (b" A B        \r\n C ", b" A B\r\n C", ""),
    (b"foo=\r\nbar", b"foobar", ""),
    (
        b"foo=\rbar",
        b"foo",
        "quotedprintable: invalid hex byte 0x0d",
    ),
    (b"foo=\n\nbar", b"foo\nbar", ""),
    (b"foo\r\n", b"foo\r\n", ""),
    (b"foo\r\n\r\n", b"foo\r\n\r\n", ""),
    (b"=0good=1", b"=0good=1", ""),
    (b"=00", b"\x00", ""),
    (b"=0", b"=0", ""),
    (b"=", b"", "quotedprintable: invalid bytes after =: \"\""),
    (b"=A", b"=A", ""),
    (b"=at", b"=at", ""),
    (b"=\r\n", b"", ""),
    (b"=\n", b"", ""),
    (b"a=b", b"a=b", ""),
    (b"a=0\n", b"a=0\n", ""),
    (b"=3D=3D", b"==", ""),
    (
        b"foo\x00bar",
        b"foo",
        "quotedprintable: invalid unescaped byte 0x00 in body",
    ),
    (
        b"foo\x7fbar",
        b"foo",
        "quotedprintable: invalid unescaped byte 0x7f in body",
    ),
    (b"foo\x80bar", b"foo\x80bar", ""),
    (b"foo bar\r\nbaz\r\n", b"foo bar\r\nbaz\r\n", ""),
    (b"foo   \r\nbar", b"foo\r\nbar", ""),
    (b"foo=  \r\nbar", b"foobar", ""),
    (b"foo=  x\r\nbar", b"foo=  x\r\nbar", ""),
    (b"foo=\t\r\nbar", b"foobar", ""),
    (b"\n\n", b"\n\n", ""),
    (b"=e1=e2=E3=E4=e5", b"\xe1\xe2\xe3\xe4\xe5", ""),
    (b"Warum ist es t=?", b"Warum ist es t=?", ""),
];

// Go's write table for the short, literal cases: (input, Binary, out).
const WRITE_CASES: [(&[u8], bool, &[u8]); 13] = [
    (b"", false, b""),
    (b"foo bar", false, b"foo bar"),
    (b"foo bar\r\n", false, b"foo bar\r\n"),
    (b"foo bar ", false, b"foo bar=20"),
    (b"foo bar\t", false, b"foo bar=09"),
    (b"=", false, b"=3D"),
    (b"\x00\x01\x02", false, b"=00=01=02"),
    (b"foo\r\nbar", false, b"foo\r\nbar"),
    (b"foo\rbar", false, b"foo\r\nbar"),
    (b"foo\nbar", false, b"foo\r\nbar"),
    (b"foo\r\nbar", true, b"foo=0D=0Abar"),
    (b"foo\rbar", true, b"foo=0Dbar"),
    (b"foo\nbar", true, b"foo=0Abar"),
];

const LOREM: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed feugiat.";

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. The decoder against Go, output only.
    {
        let mut ok = true;
        let mut i = 0;
        while i < READ_CASES.len() {
            let (input, want, _) = READ_CASES[i];
            let (got, _) = decode(input);
            if &got[..] != want {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 1] decode 35 Go vectors     PASS");
        } else {
            fmt::Println!("[ 1] decode 35 Go vectors     FAIL");
            failed += 1;
        }
    }

    // 2. The same table's error texts, verbatim. Go formats the offending
    //    byte with %02x and the bytes after a bad '=' with %q, and a
    //    port that only matches names gets neither.
    {
        let mut ok = true;
        let mut i = 0;
        while i < READ_CASES.len() {
            let (input, _, want_err) = READ_CASES[i];
            let (_, got_err) = decode(input);
            if &got_err[..] != want_err.as_bytes() {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 2] decode error texts       PASS");
        } else {
            fmt::Println!("[ 2] decode error texts       FAIL");
            failed += 1;
        }
    }

    // 3. The encoder against Go, one Write per input.
    {
        let mut ok = true;
        let mut i = 0;
        while i < WRITE_CASES.len() {
            let (input, binary, want) = WRITE_CASES[i];
            if &encode(input, binary)[..] != want {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 3] encode 13 Go vectors     PASS");
        } else {
            fmt::Println!("[ 3] encode 13 Go vectors     FAIL");
            failed += 1;
        }
    }

    // 4. The same table, one Write per byte. `Write` batches runs of
    //    literal bytes, so splitting the input exercises a different
    //    path through it and must still agree.
    {
        let mut ok = true;
        let mut i = 0;
        while i < WRITE_CASES.len() {
            let (input, binary, want) = WRITE_CASES[i];
            if &encode1(input, binary)[..] != want {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 4] encode byte-at-a-time    PASS");
        } else {
            fmt::Println!("[ 4] encode byte-at-a-time    FAIL");
            failed += 1;
        }
    }

    // 5. The 76-column rule at its three interesting lengths. 75 fits;
    //    76 breaks after 75 with "=\r\n"; 100 leaves 25 on the next line.
    {
        let a75 = repeat(b"a", 75);
        let mut ok = true;

        if encode(&repeat(b"a", 75), false) != a75 {
            ok = false;
        }
        let mut want76: Vec<byte> = a75.clone();
        want76.extend_from_slice(b"=\r\na");
        if encode(&repeat(b"a", 76), false) != want76 {
            ok = false;
        }
        let mut want77: Vec<byte> = a75.clone();
        want77.extend_from_slice(b"=\r\naa");
        if encode(&repeat(b"a", 77), false) != want77 {
            ok = false;
        }
        let mut want100: Vec<byte> = a75.clone();
        want100.extend_from_slice(b"=\r\n");
        want100.extend_from_slice(&repeat(b"a", 25));
        if encode(&repeat(b"a", 100), false) != want100 {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 5] soft line break at 76    PASS");
        } else {
            fmt::Println!("[ 5] soft line break at 76    FAIL");
            failed += 1;
        }
    }

    // 6. `encode` reserves three columns before it starts an "=XX", so a
    //    run of escapes never splits one across a line break.
    {
        let mut ok = true;
        if encode(&repeat(b"=", 20), false) != repeat(b"=3D", 20) {
            ok = false;
        }
        // "é" is 0xC3 0xA9 — two escapes per rune.
        if encode(&repeat(b"\xc3\xa9", 10), false) != repeat(b"=C3=A9", 10) {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 6] escapes never split      PASS");
        } else {
            fmt::Println!("[ 6] escapes never split      FAIL");
            failed += 1;
        }
    }

    // 7. Whitespace held across a soft line break is *not* encoded —
    //    only whitespace at a real end of line is. Go's output for
    //    "a" + 80 spaces + "b".
    {
        let mut input: Vec<byte> = alloc::vec![b'a'];
        input.extend_from_slice(&repeat(b" ", 80));
        input.push(b'b');

        let mut want: Vec<byte> = alloc::vec![b'a'];
        want.extend_from_slice(&repeat(b" ", 74));
        want.extend_from_slice(b"=\r\n");
        want.extend_from_slice(&repeat(b" ", 6));
        want.push(b'b');

        if encode(&input, false) == want {
            fmt::Println!("[ 7] whitespace over a break  PASS");
        } else {
            fmt::Println!("[ 7] whitespace over a break  FAIL");
            failed += 1;
        }
    }

    // 8. checkLastByte: a trailing space or tab is re-encoded on Close,
    //    because a transport that strips trailing whitespace would eat
    //    it otherwise.
    {
        let mut ok = true;
        if &encode(b"foo bar ", false)[..] != b"foo bar=20" {
            ok = false;
        }
        if &encode(b"foo bar\t", false)[..] != b"foo bar=09" {
            ok = false;
        }
        // ... and at a line end too, not only at Close.
        if &encode(b"foo \r\nbar", false)[..] != b"foo=20\r\nbar" {
            ok = false;
        }
        // Only the *last* byte is checked, so a space before a tab
        // survives while the tab is escaped.
        if &encode(b"foo \t\r\nbar", false)[..] != b"foo =09\r\nbar" {
            ok = false;
        }
        // Leading whitespace on the next line is untouched.
        if &encode(b"foo\r\n bar", false)[..] != b"foo\r\n bar" {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 8] trailing WS re-encoded   PASS");
        } else {
            fmt::Println!("[ 8] trailing WS re-encoded   FAIL");
            failed += 1;
        }
    }

    // 9. Binary mode makes '\r' and '\n' ordinary bytes; text mode
    //    normalises every line ending to CRLF.
    {
        let mut ok = true;
        if &encode(b"foo\rbar", true)[..] != b"foo=0Dbar" {
            ok = false;
        }
        if &encode(b"foo\rbar", false)[..] != b"foo\r\nbar" {
            ok = false;
        }
        if &encode(b"foo\r\nbar", true)[..] != b"foo=0D=0Abar" {
            ok = false;
        }
        if &encode(b"foo\r\nbar", false)[..] != b"foo\r\nbar" {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 9] Binary vs text EOL       PASS");
        } else {
            fmt::Println!("[ 9] Binary vs text EOL       FAIL");
            failed += 1;
        }
    }

    // 10. Round-trip: whatever the writer emits, the reader accepts and
    //     returns unchanged. Excludes the cases where the writer itself
    //     rewrites the input — a bare '\r' or '\n' becomes CRLF in text
    //     mode, so those cannot round-trip by construction.
    {
        let mut ok = true;
        let cases: [&[u8]; 8] = [
            b"",
            b"foo bar",
            b"foo bar\r\n",
            b"foo bar ",
            b"=",
            b"\x00\x01\x02",
            LOREM,
            b"Warum ist es so kalt?",
        ];
        let mut i = 0;
        while i < cases.len() {
            let enc = encode(cases[i], false);
            let (dec, err) = decode(&enc);
            if !err.is_empty() || &dec[..] != cases[i] {
                ok = false;
            }
            i += 1;
        }
        // Long inputs round-trip through the soft line breaks too.
        let long = repeat(b"a", 300);
        let enc = encode(&long, false);
        let (dec, err) = decode(&enc);
        if !err.is_empty() || dec != long {
            ok = false;
        }
        if ok {
            fmt::Println!("[10] writer -> reader         PASS");
        } else {
            fmt::Println!("[10] writer -> reader         FAIL");
            failed += 1;
        }
    }

    // 11. The reader refills across its bufio buffer: a 300-line input
    //     read seven bytes at a time (read_all's buffer) must still come
    //     back byte-for-byte.
    {
        let mut src: Vec<byte> = Vec::new();
        let mut want: Vec<byte> = Vec::new();
        let mut i = 0;
        while i < 300 {
            src.extend_from_slice(b"=41=42abc=\r\n");
            want.extend_from_slice(b"ABabc");
            i += 1;
        }
        let (got, err) = decode(&src);
        if err.is_empty() && got == want {
            fmt::Println!("[11] reader refills buffer    PASS");
        } else {
            fmt::Println!("[11] reader refills buffer    FAIL");
            failed += 1;
        }
    }

    // 12. Go leaves a long unbroken literal line alone when it fits, and
    //     the Lorem sentence is 69 characters — under the limit.
    {
        if &encode(LOREM, false)[..] == LOREM {
            fmt::Println!("[12] short line not broken    PASS");
        } else {
            fmt::Println!("[12] short line not broken    FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 12");
        syscall::Exit(1);
    }
}
