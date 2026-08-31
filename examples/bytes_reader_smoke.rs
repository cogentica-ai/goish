// bytes_reader_smoke — bytes.Reader against a running Go.
// (bytes/reader.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the values
// and the error strings are the output of
// `tools/gen_bytes_reader_ref.go` run in `package bytes_test` by
// `scripts/goref.sh`.
//
// Reader's behaviour is all in the edges. `UnreadByte` and `UnreadRune`
// are errors unless they directly follow the matching read; `prevRune`
// is invalidated by every other operation, so an `UnreadRune` after a
// `ReadByte` fails even though a rune was read moments earlier; `Seek`
// accepts a position past the end but not a negative one; and `ReadAt`
// does not move the cursor at all. None of that shows up in a
// read-the-whole-thing test, which is what the rest of the tree does
// with this type. bytes.Reader is the same shape as strings.Reader
// and reports the same refusals, with `slice` where the string version
// says `string`.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::bytes;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string as gostring;
use goish::io;
use goish::syscall;
use goish::types::byte;

fn gb(s: &gostring) -> Vec<byte> {
    let c = goish::convert::bytes(s.clone());
    let r: &[byte] = &c;
    return r.to_vec();
}

fn etext(e: &goish::errors::error) -> Vec<byte> {
    if e.IsNil() {
        return Vec::new();
    }
    return gb(&e.Error());
}

fn sl(b: &[u8]) -> slice<byte> {
    return slice::<byte>::__from_vec(b.to_vec());
}

fn buf(n: usize) -> slice<byte> {
    return slice::<byte>::__from_vec(alloc::vec![0u8; n]);
}

fn taken(p: &slice<byte>, n: i64) -> Vec<byte> {
    let mut v: Vec<byte> = Vec::new();
    let mut i = 0i64;
    while i < n {
        v.push(p[i]);
        i += 1;
    }
    return v;
}

// "héllo, 世界" — 14 bytes, 9 runes.
const S: &[u8] = b"h\xc3\xa9llo, \xe4\xb8\x96\xe7\x95\x8c";

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Size is the byte length and never moves; Len is what is left.
    {
        let mut r = bytes::NewReader(sl(S));
        let mut ok = r.Size() == 14 && r.Len() == 14;
        let mut p = buf(3);
        let (n, e) = r.Read(&mut p);
        if n != 3 || !e.IsNil() || taken(&p, n) != b"h\xc3\xa9".to_vec() || r.Len() != 11 {
            ok = false;
        }
        let (n, e) = r.Read(&mut p);
        if n != 3 || !e.IsNil() || taken(&p, n) != b"llo".to_vec() || r.Len() != 8 {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 1] Size / Len / Read         PASS");
        } else {
            fmt::Println!("[ 1] Size / Len / Read         FAIL");
            failed += 1;
        }
    }

    // 2. Reading to exhaustion: a short read is not an error, the read
    //    after it is EOF, and an empty Reader is EOF immediately.
    {
        let mut ok = true;
        let mut r = bytes::NewReader(sl(b"abc"));
        let mut p = buf(2);
        let (n, e) = r.Read(&mut p);
        if n != 2 || !e.IsNil() || taken(&p, n) != b"ab".to_vec() {
            ok = false;
        }
        let (n, e) = r.Read(&mut p);
        if n != 1 || !e.IsNil() || taken(&p, n) != b"c".to_vec() {
            ok = false;
        }
        let (n, e) = r.Read(&mut p);
        if n != 0 || !goish::errors::Is(e, io::EOF) {
            ok = false;
        }
        let mut r2 = bytes::NewReader(sl(b""));
        let mut q = buf(4);
        let (n, e) = r2.Read(&mut q);
        if n != 0 || !goish::errors::Is(e, io::EOF) || r2.Len() != 0 || r2.Size() != 0 {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 2] EOF and empty Reader      PASS");
        } else {
            fmt::Println!("[ 2] EOF and empty Reader      FAIL");
            failed += 1;
        }
    }

    // 3. ReadByte / UnreadByte, including Go's exact error text for an
    //    unread at the beginning.
    {
        let mut ok = true;
        let mut r = bytes::NewReader(sl(b"ab"));
        if etext(&r.UnreadByte()) != b"bytes.Reader.UnreadByte: at beginning of slice".to_vec() {
            ok = false;
        }
        let (c, e) = r.ReadByte();
        if c != b'a' || !e.IsNil() {
            ok = false;
        }
        if !r.UnreadByte().IsNil() {
            ok = false;
        }
        let (c, _) = r.ReadByte();
        if c != b'a' {
            ok = false;
        }
        let (c, _) = r.ReadByte();
        if c != b'b' {
            ok = false;
        }
        let (_, e) = r.ReadByte();
        if !goish::errors::Is(e, io::EOF) {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 3] ReadByte / UnreadByte     PASS");
        } else {
            fmt::Println!("[ 3] ReadByte / UnreadByte     FAIL");
            failed += 1;
        }
    }

    // 4. ReadRune / UnreadRune, and the invalidation rule: a ReadByte
    //    between a ReadRune and an UnreadRune makes the unread an
    //    error, with its own message.
    {
        let mut ok = true;
        let mut r = bytes::NewReader(sl(b"h\xc3\xa9llo"));
        if etext(&r.UnreadRune()) != b"bytes.Reader.UnreadRune: at beginning of slice".to_vec() {
            ok = false;
        }
        let (ch, sz, e) = r.ReadRune();
        if ch != 0x68 || sz != 1 || !e.IsNil() {
            ok = false;
        }
        let (ch, sz, _) = r.ReadRune();
        if ch != 0xE9 || sz != 2 {
            ok = false;
        }
        let (ch, sz, _) = r.ReadRune();
        if ch != 0x6C || sz != 1 {
            ok = false;
        }
        if !r.UnreadRune().IsNil() {
            ok = false;
        }
        let (ch, sz, _) = r.ReadRune();
        if ch != 0x6C || sz != 1 {
            ok = false;
        }
        let (_, _, _) = r.ReadRune();
        let (_, _) = r.ReadByte();
        if etext(&r.UnreadRune())
            != b"bytes.Reader.UnreadRune: previous operation was not ReadRune".to_vec()
        {
            ok = false;
        }
        // An invalid sequence is one U+FFFD of width 1.
        let mut r2 = bytes::NewReader(sl(b"\xff\xfe"));
        let (ch, sz, e) = r2.ReadRune();
        if ch != 0xFFFD || sz != 1 || !e.IsNil() {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 4] ReadRune / UnreadRune     PASS");
        } else {
            fmt::Println!("[ 4] ReadRune / UnreadRune     FAIL");
            failed += 1;
        }
    }

    // 5. Seek: all three whences, a position past the end (legal), a
    //    negative one (not), and an unknown whence.
    //    (offset, whence, position, error text, Len after)
    {
        const SEEKS: [(i64, i64, i64, &str, i64); 9] = [
            (0, 0, 0, "", 6),
            (3, 0, 3, "", 3),
            (100, 0, 100, "", 0),
            (-1, 0, 0, "bytes.Reader.Seek: negative position", 4),
            (0, 2, 6, "", 0),
            (-3, 2, 3, "", 3),
            (-100, 2, 0, "bytes.Reader.Seek: negative position", 4),
            (2, 1, 4, "", 2),
            (-1, 1, 1, "", 5),
        ];
        let mut ok = true;
        let mut i = 0;
        while i < SEEKS.len() {
            let (off, whence, want_pos, want_err, want_len) = SEEKS[i];
            let mut r = bytes::NewReader(sl(b"abcdef"));
            let mut p = buf(2);
            let _ = r.Read(&mut p); // cursor at 2
            let (pos, e) = r.Seek(off, whence);
            if pos != want_pos || etext(&e) != want_err.as_bytes().to_vec() || r.Len() != want_len {
                ok = false;
            }
            i += 1;
        }
        let mut r = bytes::NewReader(sl(b"abc"));
        let (pos, e) = r.Seek(0, 99);
        if pos != 0 || etext(&e) != b"bytes.Reader.Seek: invalid whence".to_vec() {
            ok = false;
        }
        // Seeking past the end is legal; reading there is EOF.
        let mut r2 = bytes::NewReader(sl(b"abc"));
        let _ = r2.Seek(10, 0);
        let mut q = buf(4);
        let (n, e) = r2.Read(&mut q);
        if n != 0 || !goish::errors::Is(e, io::EOF) || r2.Len() != 0 {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 5] Seek, all whences         PASS");
        } else {
            fmt::Println!("[ 5] Seek, all whences         FAIL");
            failed += 1;
        }
    }

    // 6. ReadAt leaves the cursor alone and reports EOF on a short
    //    read — including a zero-length one exactly at the end.
    //    (offset, n, bytes, error text)
    {
        const ATS: [(i64, i64, &[u8], &str); 6] = [
            (0, 3, b"abc", ""),
            (4, 2, b"ef", "EOF"),
            (5, 1, b"f", "EOF"),
            (6, 0, b"", "EOF"),
            (7, 0, b"", "EOF"),
            (-1, 0, b"", "bytes.Reader.ReadAt: negative offset"),
        ];
        let mut ok = true;
        let mut r = bytes::NewReader(sl(b"abcdef"));
        let mut p2 = buf(2);
        let _ = r.Read(&mut p2); // cursor at 2, Len 4
        let mut i = 0;
        while i < ATS.len() {
            let (off, want_n, want_b, want_err) = ATS[i];
            let mut p = buf(3);
            let (n, e) = r.ReadAt(&mut p, off);
            if n != want_n || taken(&p, n) != want_b.to_vec() {
                ok = false;
            }
            if etext(&e) != want_err.as_bytes().to_vec() {
                ok = false;
            }
            // The cursor never moves.
            if r.Len() != 4 {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 6] ReadAt keeps the cursor   PASS");
        } else {
            fmt::Println!("[ 6] ReadAt keeps the cursor   FAIL");
            failed += 1;
        }
    }

    // 7. WriteTo drains from the cursor, and a second one has nothing
    //    left to give.
    {
        let mut ok = true;
        let mut r = bytes::NewReader(sl(b"abcdef"));
        let mut p = buf(2);
        let _ = r.Read(&mut p);
        let mut sink = bytes::NewBuffer(slice::<byte>::__from_vec(Vec::new()));
        let (n, e) = r.WriteTo(&mut sink);
        if n != 4 || !e.IsNil() || gb(&sink.String()) != b"cdef".to_vec() || r.Len() != 0 {
            ok = false;
        }
        let mut sink2 = bytes::NewBuffer(slice::<byte>::__from_vec(Vec::new()));
        let (n, e) = r.WriteTo(&mut sink2);
        if n != 0 || !e.IsNil() || sink2.String().Len() != 0 {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 7] WriteTo drains once       PASS");
        } else {
            fmt::Println!("[ 7] WriteTo drains once       FAIL");
            failed += 1;
        }
    }

    // 8. Reset re-arms everything, prevRune included.
    {
        let mut r = bytes::NewReader(sl(b"abc"));
        let _ = r.ReadRune();
        r.Reset(sl(b"xyz"));
        let unread = etext(&r.UnreadRune());
        // Go's reference prints Len and Size BEFORE the read, so they
        // are captured before it here too.
        let (len_after_reset, size_after_reset) = (r.Len(), r.Size());
        let (b, _) = r.ReadByte();
        if len_after_reset == 3
            && size_after_reset == 3
            && unread == b"bytes.Reader.UnreadRune: at beginning of slice".to_vec()
            && b == b'x'
        {
            fmt::Println!("[ 8] Reset                     PASS");
        } else {
            fmt::Println!("[ 8] Reset                     FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 8");
        syscall::Exit(1);
    }
}
