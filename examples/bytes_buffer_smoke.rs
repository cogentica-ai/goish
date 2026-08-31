// bytes_buffer_smoke — bytes.Buffer against a running Go.
// (bytes/buffer.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the values
// and the error strings are the output of
// `tools/gen_bytes_buffer_ref.go` run in `package bytes_test` by
// `scripts/goref.sh`.
//
// Buffer's growth is three steps and only the last allocates: reset
// when the buffer is logically empty but `off` has walked forward, try
// a reslice into capacity already owned, then either slide the live
// bytes down over the consumed prefix or double. The observable
// consequences are Len/Cap/Available across a write-drain-write cycle,
// and the fact that `Grow(n)` leaves Len alone while guaranteeing n
// bytes of headroom.
//
// `Truncate` is the one that catches a port reading the wrong index:
// it counts from the START OF THE UNREAD PORTION, not from the start of
// the buffer. On a Buffer holding "abcdef" with two bytes already read,
// `Truncate(1)` leaves "c".

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

fn raw(s: &slice<byte>) -> Vec<byte> {
    let r: &[byte] = s;
    return r.to_vec();
}

fn etext(e: &goish::errors::error) -> Vec<byte> {
    if e.IsNil() {
        return Vec::new();
    }
    return gb(&e.Error());
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

fn newbuf(b: &[u8]) -> bytes::Buffer {
    return bytes::NewBuffer(slice::<byte>::__from_vec(b.to_vec()));
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. A write / read / write cycle: Len tracks the UNREAD portion,
    //    and String shows only that.
    {
        let mut ok = true;
        let mut b = bytes::Buffer::new();
        if b.Len() != 0 || gb(&b.String()).len() != 0 {
            ok = false;
        }
        let _ = b.WriteString(gostring::from_bytes(b"hello"));
        if b.Len() != 5
            || gb(&b.String()) != b"hello".to_vec()
            || raw(&b.Bytes()) != b"hello".to_vec()
        {
            ok = false;
        }
        let mut p = buf(3);
        let (n, e) = b.Read(&mut p);
        if n != 3 || !e.IsNil() || taken(&p, n) != b"hel".to_vec() || b.Len() != 2 {
            ok = false;
        }
        if gb(&b.String()) != b"lo".to_vec() {
            ok = false;
        }
        let _ = b.WriteString(gostring::from_bytes(b" world"));
        if b.Len() != 8 || gb(&b.String()) != b"lo world".to_vec() {
            ok = false;
        }
        let (out, e) = goish::io::ReadAll(&mut b);
        if !e.IsNil() || raw(&out) != b"lo world".to_vec() || b.Len() != 0 {
            ok = false;
        }
        let (n, e) = b.Read(&mut p);
        if n != 0 || !goish::errors::Is(e, io::EOF) {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 1] write / read / write     PASS");
        } else {
            fmt::Println!("[ 1] write / read / write     FAIL");
            failed += 1;
        }
    }

    // 2. Grow leaves Len alone and guarantees the headroom it promised.
    //    Go's contract: "after Grow(n), at least n bytes can be written
    //    to the buffer without another allocation."
    {
        let mut ok = true;
        let mut b = bytes::Buffer::new();
        let _ = b.WriteString(gostring::from_bytes(b"abc"));
        b.Grow(100);
        if b.Len() != 3 || b.Available() < 100 || gb(&b.String()) != b"abc".to_vec() {
            ok = false;
        }
        let mut c = bytes::Buffer::new();
        c.Grow(0);
        if c.Len() != 0 {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 2] Grow keeps Len, adds cap PASS");
        } else {
            fmt::Println!("[ 2] Grow keeps Len, adds cap FAIL");
            failed += 1;
        }
    }

    // 3. Truncate counts from the start of the UNREAD portion.
    {
        let mut ok = true;
        let mut b = newbuf(b"abcdef");
        b.Truncate(3);
        if b.Len() != 3 || gb(&b.String()) != b"abc".to_vec() {
            ok = false;
        }
        b.Truncate(0);
        if b.Len() != 0 || gb(&b.String()).len() != 0 {
            ok = false;
        }
        let mut b2 = newbuf(b"abcdef");
        let mut p = buf(2);
        let _ = b2.Read(&mut p);
        b2.Truncate(1);
        if b2.Len() != 1 || gb(&b2.String()) != b"c".to_vec() {
            ok = false;
        }
        b2.Reset();
        if b2.Len() != 0 || gb(&b2.String()).len() != 0 {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 3] Truncate / Reset         PASS");
        } else {
            fmt::Println!("[ 3] Truncate / Reset         FAIL");
            failed += 1;
        }
    }

    // 4. Next returns at most what is there, and empties the buffer.
    {
        let mut b = newbuf(b"abcdef");
        let n3 = raw(&b.Next(3));
        let l3 = b.Len();
        let n99 = raw(&b.Next(99));
        let l99 = b.Len();
        let ne = raw(&b.Next(1));
        if n3 == b"abc".to_vec() && l3 == 3 && n99 == b"def".to_vec() && l99 == 0 && ne.is_empty() {
            fmt::Println!("[ 4] Next                     PASS");
        } else {
            fmt::Println!("[ 4] Next                     FAIL");
            failed += 1;
        }
    }

    // 5. ReadByte / UnreadByte / ReadRune / UnreadRune, and Go's exact
    //    error text for each refusal. A ReadByte between a ReadRune and
    //    an UnreadRune invalidates the unread.
    {
        let mut ok = true;
        let mut b = newbuf(b"h\xc3\xa9llo");
        if etext(&b.UnreadByte())
            != b"bytes.Buffer: UnreadByte: previous operation was not a successful read".to_vec()
        {
            ok = false;
        }
        let (c, e) = b.ReadByte();
        if c != b'h' || !e.IsNil() || !b.UnreadByte().IsNil() {
            ok = false;
        }
        let (r, sz, e) = b.ReadRune();
        if r != 0x68 || sz != 1 || !e.IsNil() {
            ok = false;
        }
        let (r, sz, _) = b.ReadRune();
        if r != 0xE9 || sz != 2 {
            ok = false;
        }
        if !b.UnreadRune().IsNil() {
            ok = false;
        }
        let (r, sz, _) = b.ReadRune();
        if r != 0xE9 || sz != 2 {
            ok = false;
        }
        let (_, _, _) = b.ReadRune();
        let (_, _) = b.ReadByte();
        if etext(&b.UnreadRune())
            != b"bytes.Buffer: UnreadRune: previous operation was not a successful ReadRune"
                .to_vec()
        {
            ok = false;
        }
        let (_, _) = goish::io::ReadAll(&mut b);
        let (_, e) = b.ReadByte();
        if !goish::errors::Is(e, io::EOF) {
            ok = false;
        }
        let (_, _, e) = b.ReadRune();
        if !goish::errors::Is(e, io::EOF) {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 5] Unread{Byte,Rune} rules  PASS");
        } else {
            fmt::Println!("[ 5] Unread{Byte,Rune} rules  FAIL");
            failed += 1;
        }
    }

    // 6. ReadBytes / ReadString: the final chunk without a delimiter
    //    comes back WITH io.EOF, and the read after that is empty.
    {
        let mut ok = true;
        let mut b = newbuf(b"one\ntwo\nthree");
        let (l0, e0) = b.ReadBytes(b'\n');
        let (l1, e1) = b.ReadBytes(b'\n');
        let (l2, e2) = b.ReadBytes(b'\n');
        let (l3, e3) = b.ReadBytes(b'\n');
        if raw(&l0) != b"one\n".to_vec() || !e0.IsNil() {
            ok = false;
        }
        if raw(&l1) != b"two\n".to_vec() || !e1.IsNil() {
            ok = false;
        }
        if raw(&l2) != b"three".to_vec() || !goish::errors::Is(e2, io::EOF) {
            ok = false;
        }
        if l3.Len() != 0 || !goish::errors::Is(e3, io::EOF) {
            ok = false;
        }
        let mut c = newbuf(b"a,b");
        let (s0, se0) = c.ReadString(b',');
        let (s1, se1) = c.ReadString(b',');
        if gb(&s0) != b"a,".to_vec() || !se0.IsNil() {
            ok = false;
        }
        if gb(&s1) != b"b".to_vec() || !goish::errors::Is(se1, io::EOF) {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 6] ReadBytes / ReadString   PASS");
        } else {
            fmt::Println!("[ 6] ReadBytes / ReadString   FAIL");
            failed += 1;
        }
    }

    // 7. WriteTo drains from the read cursor; WriteRune reports the
    //    encoded width, not one.
    {
        let mut ok = true;
        let mut b = newbuf(b"abcdef");
        let mut p = buf(2);
        let _ = b.Read(&mut p);
        let mut sink = bytes::NewBuffer(slice::<byte>::__from_vec(Vec::new()));
        let (n, e) = b.WriteTo(&mut sink);
        if n != 4 || !e.IsNil() || gb(&sink.String()) != b"cdef".to_vec() || b.Len() != 0 {
            ok = false;
        }
        let mut c = bytes::Buffer::new();
        let (nr, _) = c.WriteRune(0x4E16);
        let (nr2, _) = c.WriteRune(0x61);
        if nr != 3 || nr2 != 1 || gb(&c.String()) != b"\xe4\xb8\x96a".to_vec() || c.Len() != 4 {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 7] WriteTo / WriteRune      PASS");
        } else {
            fmt::Println!("[ 7] WriteTo / WriteRune      FAIL");
            failed += 1;
        }
    }

    // 8. ReadFrom appends and reports the count; NewBuffer adopts the
    //    slice it is handed.
    {
        let mut ok = true;
        let mut b = newbuf(b"pre-");
        let mut src = goish::strings::NewReader(gostring::from_bytes(b"body"));
        let (n, e) = b.ReadFrom(&mut src);
        if n != 4 || !e.IsNil() || gb(&b.String()) != b"pre-body".to_vec() {
            ok = false;
        }
        let mut empty = goish::strings::NewReader(gostring::from_bytes(b""));
        let (n, e) = b.ReadFrom(&mut empty);
        if n != 0 || !e.IsNil() {
            ok = false;
        }
        let mut s = newbuf(b"seed");
        if s.Len() != 4 || gb(&s.String()) != b"seed".to_vec() {
            ok = false;
        }
        let _ = s.WriteString(gostring::from_bytes(b"+more"));
        if gb(&s.String()) != b"seed+more".to_vec() {
            ok = false;
        }
        let z = bytes::NewBuffer(slice::<byte>::__from_vec(Vec::new()));
        if z.Len() != 0 || gb(&z.String()).len() != 0 {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 8] ReadFrom / NewBuffer     PASS");
        } else {
            fmt::Println!("[ 8] ReadFrom / NewBuffer     FAIL");
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
