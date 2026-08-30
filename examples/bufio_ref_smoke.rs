// bufio_ref_smoke — bufio's Scanner, Reader and Writer against Go.
// (bufio/scan.go, bufio/bufio.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the tables
// are the output of `tools/gen_bufio_ref.go` run in `package bufio_test`
// by `scripts/goref.sh` — external, because `testing` imports `bufio`
// and an in-package ref file would be an import cycle.
//
// `ScanWords` is the reason this exists. It steps by *rune width*, not
// by byte, and its notion of space is scan.go's own table, which
// includes NBSP, NEL, the whole U+2000..U+200A run, and the ideographic
// space. An ASCII-only byte-wise version passes every ASCII test and
// gets all of those wrong.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::bufio;
use goish::bytes;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string as gostring;
use goish::syscall;
use goish::types::byte;

fn gb(s: &gostring) -> Vec<byte> {
    let c = goish::convert::bytes(s.clone());
    let r: &[byte] = &c;
    return r.to_vec();
}

fn newbuf(b: &[u8]) -> bytes::Buffer {
    return bytes::NewBuffer(slice::<byte>::__from_vec(b.to_vec()));
}

/// Run a scanner over `input` with `split`, collecting the tokens.
fn scan_with(
    input: &[u8],
    split: fn(&[byte], bool) -> (goish::types::int, Option<slice<byte>>, goish::errors::error),
) -> (Vec<Vec<byte>>, bool) {
    let mut src = newbuf(input);
    let mut sc = bufio::NewScanner(&mut src);
    sc.Split(split);
    let mut out: Vec<Vec<byte>> = Vec::new();
    while sc.Scan() {
        out.push(gb(&sc.Text()));
    }
    return (out, sc.Err().IsNil());
}

fn scan_lines(input: &[u8]) -> (Vec<Vec<byte>>, bool) {
    let mut src = newbuf(input);
    let mut sc = bufio::NewScanner(&mut src);
    let mut out: Vec<Vec<byte>> = Vec::new();
    while sc.Scan() {
        out.push(gb(&sc.Text()));
    }
    return (out, sc.Err().IsNil());
}

fn eq(got: &[Vec<byte>], want: &[&[u8]]) -> bool {
    if got.len() != want.len() {
        return false;
    }
    let mut i = 0;
    while i < got.len() {
        if got[i][..] != *want[i] {
            return false;
        }
        i += 1;
    }
    return true;
}

// Go's ScanWords table. The separators are, in order: NBSP (U+00A0),
// NEL (U+0085), EN QUAD (U+2000), HAIR SPACE (U+200A), OGHAM SPACE MARK
// (U+1680), LINE SEPARATOR (U+2028), PARAGRAPH SEPARATOR (U+2029),
// NARROW NBSP (U+202F), MEDIUM MATHEMATICAL SPACE (U+205F) and
// IDEOGRAPHIC SPACE (U+3000).
const WORDS: [(&[u8], &[&[u8]]); 21] = [
    (b"", &[]),
    (b"   ", &[]),
    (b"one", &[b"one"]),
    (b"one two three", &[b"one", b"two", b"three"]),
    (
        b"  leading and trailing  ",
        &[b"leading", b"and", b"trailing"],
    ),
    (
        b"a\tb\nc\rd\x0be\x0cf",
        &[b"a", b"b", b"c", b"d", b"e", b"f"],
    ),
    (b"tab\tsep", &[b"tab", b"sep"]),
    (b"nbsp\xc2\xa0sep", &[b"nbsp", b"sep"]),
    (b"nel\xc2\x85sep", &[b"nel", b"sep"]),
    (b"enquad\xe2\x80\x80sep", &[b"enquad", b"sep"]),
    (b"hairsp\xe2\x80\x8asep", &[b"hairsp", b"sep"]),
    (b"ogham\xe1\x9a\x80sep", &[b"ogham", b"sep"]),
    (b"lsep\xe2\x80\xa8sep", &[b"lsep", b"sep"]),
    (b"psep\xe2\x80\xa9sep", &[b"psep", b"sep"]),
    (b"nnbsp\xe2\x80\xafsep", &[b"nnbsp", b"sep"]),
    (b"mmsp\xe2\x81\x9fsep", &[b"mmsp", b"sep"]),
    (b"ideo\xe3\x80\x80sep", &[b"ideo", b"sep"]),
    (b"\xe3\x80\x80\xe3\x80\x80lead", &[b"lead"]),
    (b"trail\xe3\x80\x80\xe3\x80\x80", &[b"trail"]),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac \xe8\xaa\x9e \xe3\x83\x86",
        &[
            b"\xe6\x97\xa5\xe6\x9c\xac",
            b"\xe8\xaa\x9e",
            b"\xe3\x83\x86",
        ],
    ),
    (b"a  b", &[b"a", b"b"]),
];

// Go's ScanLines table. `\r` is stripped only immediately before `\n`.
const LINES: [(&[u8], &[&[u8]]); 12] = [
    (b"", &[]),
    (b"a", &[b"a"]),
    (b"a\n", &[b"a"]),
    (b"a\nb", &[b"a", b"b"]),
    (b"a\r\nb", &[b"a", b"b"]),
    (b"a\r\n", &[b"a"]),
    (b"\n", &[b""]),
    (b"\r\n", &[b""]),
    (b"a\n\nb", &[b"a", b"", b"b"]),
    // A bare '\r' mid-line is data, not a line ending …
    (b"a\rb", &[b"a\rb"]),
    // … but a trailing one at EOF is dropped, because dropCR runs on
    // the final unterminated line too.
    (b"a\r", &[b"a"]),
    (
        b"line1\r\nline2\nline3\r\n",
        &[b"line1", b"line2", b"line3"],
    ),
];

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. ScanWords over Go's 21 vectors. Ten of them separate on a
    //    non-ASCII space, which an ASCII-only isSpace misses entirely.
    {
        let mut ok = true;
        let mut i = 0;
        while i < WORDS.len() {
            let (input, want) = WORDS[i];
            let (got, no_err) = scan_with(input, bufio::ScanWords);
            if !no_err || !eq(&got, want) {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 1] ScanWords 21 vectors     PASS");
        } else {
            fmt::Println!("[ 1] ScanWords 21 vectors     FAIL");
            failed += 1;
        }
    }

    // 2. ScanLines over Go's 12 vectors.
    {
        let mut ok = true;
        let mut i = 0;
        while i < LINES.len() {
            let (input, want) = LINES[i];
            let (got, no_err) = scan_lines(input);
            if !no_err || !eq(&got, want) {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 2] ScanLines 12 vectors     PASS");
        } else {
            fmt::Println!("[ 2] ScanLines 12 vectors     FAIL");
            failed += 1;
        }
    }

    // 3. ScanRunes turns every invalid byte into one U+FFFD token;
    //    ScanBytes hands back the same bytes untouched.
    {
        let mut ok = true;
        let (r1, _) = scan_with(b"abc", bufio::ScanRunes);
        if !eq(&r1, &[b"a", b"b", b"c"]) {
            ok = false;
        }
        let (r2, _) = scan_with(b"a\xc3\xa9b", bufio::ScanRunes);
        if !eq(&r2, &[b"a", b"\xc3\xa9", b"b"]) {
            ok = false;
        }
        let (r3, _) = scan_with(b"\xff\xfe", bufio::ScanRunes);
        if !eq(&r3, &[b"\xef\xbf\xbd", b"\xef\xbf\xbd"]) {
            ok = false;
        }
        let (r4, _) = scan_with(b"a\xffb", bufio::ScanRunes);
        if !eq(&r4, &[b"a", b"\xef\xbf\xbd", b"b"]) {
            ok = false;
        }
        let (b1, _) = scan_with(b"a\xc3\xa9b", bufio::ScanBytes);
        if !eq(&b1, &[b"a", b"\xc3", b"\xa9", b"b"]) {
            ok = false;
        }
        let (b2, _) = scan_with(b"", bufio::ScanBytes);
        if !b2.is_empty() {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 3] ScanRunes / ScanBytes    PASS");
        } else {
            fmt::Println!("[ 3] ScanRunes / ScanBytes    FAIL");
            failed += 1;
        }
    }

    // 4. collectFragments: a line longer than the whole buffer still
    //    comes back whole from ReadBytes, stitched from the full
    //    buffers ReadSlice filled on the way.
    {
        let mut ok = true;
        let mut src = newbuf(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\nshort\n");
        let mut r = bufio::NewReaderSize(&mut src, 16);

        let (l1, e1) = r.ReadBytes(b'\n');
        if !e1.IsNil()
            || gb(&goish::convert::string(l1))
                != b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n".to_vec()
        {
            ok = false;
        }
        let (l2, e2) = r.ReadBytes(b'\n');
        if !e2.IsNil() || gb(&goish::convert::string(l2)) != b"short\n".to_vec() {
            ok = false;
        }
        let (l3, e3) = r.ReadBytes(b'\n');
        if e3.IsNil() || l3.Len() != 0 {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 4] ReadBytes over a long line PASS");
        } else {
            fmt::Println!("[ 4] ReadBytes over a long line FAIL");
            failed += 1;
        }
    }

    // 5. ReadSlice, by contrast, gives up at a full buffer: both calls
    //    return 16 bytes and ErrBufferFull.
    {
        let mut src = newbuf(b"yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy\n");
        let mut r = bufio::NewReaderSize(&mut src, 16);
        let (s1, e1) = r.ReadSlice(b'\n');
        let (s2, e2) = r.ReadSlice(b'\n');
        let full1 = goish::errors::Is(e1, bufio::ErrBufferFull);
        let full2 = goish::errors::Is(e2, bufio::ErrBufferFull);
        if full1 && full2 && s1.Len() == 16 && s2.Len() == 16 {
            fmt::Println!("[ 5] ReadSlice ErrBufferFull  PASS");
        } else {
            fmt::Println!("[ 5] ReadSlice ErrBufferFull  FAIL");
            failed += 1;
        }
    }

    // 6. ReadString hands back the final unterminated chunk with EOF.
    {
        let mut src = newbuf(b"hello\nworld");
        let mut r = bufio::NewReaderSize(&mut src, 16);
        let (s1, e1) = r.ReadString(b'\n');
        let (s2, e2) = r.ReadString(b'\n');
        if e1.IsNil()
            && gb(&s1) == b"hello\n".to_vec()
            && !e2.IsNil()
            && gb(&s2) == b"world".to_vec()
        {
            fmt::Println!("[ 6] ReadString then EOF      PASS");
        } else {
            fmt::Println!("[ 6] ReadString then EOF      FAIL");
            failed += 1;
        }
    }

    // 7. Peek fills the buffer without consuming, Discard consumes
    //    without returning, and UnreadByte puts exactly one back.
    {
        let mut ok = true;
        let mut src = newbuf(b"abcdef");
        let mut r = bufio::NewReader(&mut src);
        let (p, pe) = r.Peek(3);
        if !pe.IsNil() || gb(&goish::convert::string(p)) != b"abc".to_vec() || r.Buffered() != 6 {
            ok = false;
        }
        let (n, de) = r.Discard(2);
        if !de.IsNil() || n != 2 {
            ok = false;
        }
        let (b1, _) = r.ReadByte();
        if b1 != b'c' || !r.UnreadByte().IsNil() {
            ok = false;
        }
        let (b2, _) = r.ReadByte();
        if b2 != b'c' {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 7] Peek/Discard/UnreadByte  PASS");
        } else {
            fmt::Println!("[ 7] Peek/Discard/UnreadByte  FAIL");
            failed += 1;
        }
    }

    // 8. ReadRune reports the width Go reports: 1, 2, 3.
    {
        let mut src = newbuf(b"a\xc3\xa9\xe6\x97\xa5");
        let mut r = bufio::NewReader(&mut src);
        let (r1, s1, e1) = r.ReadRune();
        let (r2, s2, e2) = r.ReadRune();
        let (r3, s3, e3) = r.ReadRune();
        let (_, _, e4) = r.ReadRune();
        if e1.IsNil()
            && e2.IsNil()
            && e3.IsNil()
            && !e4.IsNil()
            && r1 == 0x61
            && s1 == 1
            && r2 == 0xE9
            && s2 == 2
            && r3 == 0x65E5
            && s3 == 3
        {
            fmt::Println!("[ 8] ReadRune widths          PASS");
        } else {
            fmt::Println!("[ 8] ReadRune widths          FAIL");
            failed += 1;
        }
    }

    // 9. The Writer over an 8-byte buffer: Go reports buffered=6 and
    //    available=2 after "hello ", and flushes to the exact bytes.
    {
        let mut sink = newbuf(b"");
        let mut ok = true;
        {
            let mut w = bufio::NewWriterSize(&mut sink, 8);
            let (n, _) = w.WriteString(goish::string("hello "));
            if n != 6 || w.Buffered() != 6 || w.Available() != 2 || w.Size() != 8 {
                ok = false;
            }
            let _ = w.WriteRune(0xE9);
            let _ = w.WriteByte(b'!');
            let _ = w.Write(goish::convert::bytes(" world"));
            if !w.Flush().IsNil() {
                ok = false;
            }
        }
        if gb(&sink.String()) != b"hello \xc3\xa9! world".to_vec() {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 9] Writer buffering         PASS");
        } else {
            fmt::Println!("[ 9] Writer buffering         FAIL");
            failed += 1;
        }
    }

    // 10. MaxScanTokenSize is Go's 64 KiB.
    {
        if bufio::MaxScanTokenSize == 65536 {
            fmt::Println!("[10] MaxScanTokenSize         PASS");
        } else {
            fmt::Println!("[10] MaxScanTokenSize         FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 10");
        syscall::Exit(1);
    }
}
