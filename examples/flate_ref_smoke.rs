// flate_ref_smoke — compress/flate against a running Go.
// (compress/flate/deflate.go, compress/flate/inflate.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_flate_ref.go` run in
// `package flate_test` by `scripts/goref.sh`.
//
// Two halves, and the compressor's is the stricter test. Go's flate is
// DETERMINISTIC: the same input at the same level gives the same bytes.
// So this compares the compressed output BYTE FOR BYTE rather than
// checking that it round-trips — a port whose output merely
// "decompresses correctly" is not the same thing, because every stored
// artifact would then differ and anything that hashes or caches
// compressed output would disagree between the two implementations.
// goish's output is byte-identical to Go's at all five levels across
// seven inputs, including the stored-block form NoCompression produces.
//
// The decompressor is fed by whoever produced the stream, which for
// anything accepting gzip means the far end of a connection. Its
// refusals are pinned with the exact offsets, and one behaviour is
// unusual enough to be worth naming: a stream can be well-formed for a
// while and then wrong, so the reader must fail PART WAY THROUGH and
// report how much it had already produced — "truncated-half" yields 9
// bytes and then io.ErrUnexpectedEOF, and "truncated-last" yields 240.
// A reader that discarded the partial output, or that reported success
// because it had produced something, would pass a round-trip test and
// fail here.
//
// Two cases are worth reading twice because they are NOT errors:
// trailing junk after a complete stream is ignored, and a flipped bit
// in the middle of this particular stream still decodes — DEFLATE has
// no checksum of its own, which is exactly why gzip and zlib wrap it in
// one. The malformed-stream source is Go's own compressed output,
// embedded as hex so both sides inflate the same bytes.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::compress::flate;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io;
use goish::syscall;
use goish::types::{byte, int};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn hx(b: &[u8]) -> string {
    const H: &[u8] = b"0123456789abcdef";
    let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(b.len() * 2);
    for &x in b {
        v.push(H[(x >> 4) as usize]);
        v.push(H[(x & 0xf) as usize]);
    }
    return string::from_bytes(&v);
}
fn unhex(h: &str) -> alloc::vec::Vec<u8> {
    let b = h.as_bytes();
    let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(b.len() / 2);
    let mut i = 0usize;
    while i + 1 < b.len() {
        let hi = (b[i] as char).to_digit(16).unwrap_or(0) as u8;
        let lo = (b[i + 1] as char).to_digit(16).unwrap_or(0) as u8;
        out.push((hi << 4) | lo);
        i += 2;
    }
    return out;
}
fn rep(x: &str, n: usize) -> alloc::vec::Vec<u8> {
    let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    for _ in 0..n {
        v.extend_from_slice(x.as_bytes());
    }
    return v;
}
// The malformed-stream source is Go's compressed output, embedded so
// both sides inflate the SAME bytes.
const BAD_SRC: &str = "ca48cdc9c95728cf2fca495118096c40000000ffff";

// go: none — goish idiom: the reference lines, in the order Go printed
//     them. Comparing whole rendered lines keeps this smoke and the
//     generator in lockstep: a case added to one is a mismatch in the
//     other, never a silent pass.
const GO: [&str; 83] = [
    "deflate default  empty           -> len=5     hex=010000ffff",
    "inflate default  empty           -> same=true  err=<nil>",
    "deflate default  one-byte        -> len=7     hex=4a04040000ffff",
    "inflate default  one-byte        -> same=true  err=<nil>",
    "deflate default  repeat          -> len=10    hex=4a4c1a1e10100000ffff",
    "inflate default  repeat          -> same=true  err=<nil>",
    "deflate default  text            -> len=47    hex=2ac94855282ccd4cce56482aca2fcf5348cbaf50c82acd2d2856c82f4b2d520049e72456552aa4e4a703020000ffff",
    "inflate default  text            -> same=true  err=<nil>",
    "deflate default  incompressible  -> len=18    hex=6260646266616563e7e0e4e206040000ffff",
    "inflate default  incompressible  -> same=true  err=<nil>",
    "deflate default  long-run        -> len=11    hex=aa1805440340000000ffff",
    "inflate default  long-run        -> same=true  err=<nil>",
    "deflate default  binary          -> len=12    hex=faff8f81118401010000ffff",
    "inflate default  binary          -> same=true  err=<nil>",
    "deflate none     empty           -> len=5     hex=010000ffff",
    "inflate none     empty           -> same=true  err=<nil>",
    "deflate none     one-byte        -> len=11    hex=000100feff61010000ffff",
    "inflate none     one-byte        -> same=true  err=<nil>",
    "deflate none     repeat          -> len=210   hex=00c80037ff6162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162010000ffff",
    "inflate none     repeat          -> same=true  err=<nil>",
    "deflate none     text            -> len=53    hex=002b00d4ff74686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67010000ffff",
    "inflate none     text            -> same=true  err=<nil>",
    "deflate none     incompressible  -> len=22    hex=000c00f3ff000102030405060708090a0b010000ffff",
    "inflate none     incompressible  -> same=true  err=<nil>",
    "deflate none     long-run        -> len=310   hex=002c01d3fe787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878010000ffff",
    "inflate none     long-run        -> same=true  err=<nil>",
    "deflate none     binary          -> len=18    hex=000800f7fffffe0001fffe0001010000ffff",
    "inflate none     binary          -> same=true  err=<nil>",
    "deflate speed    empty           -> len=5     hex=010000ffff",
    "inflate speed    empty           -> same=true  err=<nil>",
    "deflate speed    one-byte        -> len=11    hex=000100feff61010000ffff",
    "inflate speed    one-byte        -> same=true  err=<nil>",
    "deflate speed    repeat          -> len=21    hex=dcc1810c0000008030d6f287c8a31d1f0a0000ffff",
    "inflate speed    repeat          -> same=true  err=<nil>",
    "deflate speed    text            -> len=50    hex=04c0870180300844d155fe6a1634d65304dbf479518c33a76ea1753d3b835ee6dc8e0bdde64431d6e6ffe835d6000000ffff",
    "inflate speed    text            -> same=true  err=<nil>",
    "deflate speed    incompressible  -> len=22    hex=000c00f3ff000102030405060708090a0b010000ffff",
    "inflate speed    incompressible  -> same=true  err=<nil>",
    "deflate speed    long-run        -> len=21    hex=ecc081000000008020edf15718e05866000000ffff",
    "inflate speed    long-run        -> same=true  err=<nil>",
    "deflate speed    binary          -> len=18    hex=000800f7fffffe0001fffe0001010000ffff",
    "inflate speed    binary          -> same=true  err=<nil>",
    "deflate best     empty           -> len=5     hex=010000ffff",
    "inflate best     empty           -> same=true  err=<nil>",
    "deflate best     one-byte        -> len=7     hex=4a04040000ffff",
    "inflate best     one-byte        -> same=true  err=<nil>",
    "deflate best     repeat          -> len=10    hex=4a4c1a1e10100000ffff",
    "inflate best     repeat          -> same=true  err=<nil>",
    "deflate best     text            -> len=47    hex=2ac94855282ccd4cce56482aca2fcf5348cbaf50c82acd2d2856c82f4b2d520049e72456552aa4e4a703020000ffff",
    "inflate best     text            -> same=true  err=<nil>",
    "deflate best     incompressible  -> len=18    hex=6260646266616563e7e0e4e206040000ffff",
    "inflate best     incompressible  -> same=true  err=<nil>",
    "deflate best     long-run        -> len=11    hex=aa1805440340000000ffff",
    "inflate best     long-run        -> same=true  err=<nil>",
    "deflate best     binary          -> len=12    hex=faff8f81118401010000ffff",
    "inflate best     binary          -> same=true  err=<nil>",
    "deflate huffman  empty           -> len=5     hex=010000ffff",
    "inflate huffman  empty           -> same=true  err=<nil>",
    "deflate huffman  one-byte        -> len=11    hex=000100feff61010000ffff",
    "inflate huffman  one-byte        -> same=true  err=<nil>",
    "deflate huffman  repeat          -> len=55    hex=04c081000000008020d6f387b824499224499224499224499224499224499224499224499224499224499224499224499224390000ffff",
    "inflate huffman  repeat          -> same=true  err=<nil>",
    "deflate huffman  text            -> len=50    hex=04c0870180300844d155fe6a1634d65304dbf479518c33a76ea1753d3b835ee6dc8e0bdde64431d6e6ffe835d6000000ffff",
    "inflate huffman  text            -> same=true  err=<nil>",
    "deflate huffman  incompressible  -> len=22    hex=000c00f3ff000102030405060708090a0b010000ffff",
    "inflate huffman  incompressible  -> same=true  err=<nil>",
    "deflate huffman  long-run        -> len=54    hex=04c0810000000000906df900000000000000000000000000000000000000000000000000000000000000000000000000c0000000ffff",
    "inflate huffman  long-run        -> same=true  err=<nil>",
    "deflate huffman  binary          -> len=18    hex=000800f7fffffe0001fffe0001010000ffff",
    "inflate huffman  binary          -> same=true  err=<nil>",
    "level -3    -> err=\"flate: invalid compression level -3: want value in range [-2, 9]\"",
    "level 10    -> err=\"flate: invalid compression level 10: want value in range [-2, 9]\"",
    "level 100   -> err=\"flate: invalid compression level 100: want value in range [-2, 9]\"",
    "bad empty            -> n=0    err=unexpected EOF",
    "bad one-byte         -> n=0    err=unexpected EOF",
    "bad truncated-half   -> n=9    err=unexpected EOF",
    "bad truncated-last   -> n=240  err=unexpected EOF",
    "bad trailing-junk    -> n=240  err=<nil>",
    "bad all-ff           -> n=0    err=flate: corrupt input before offset 1",
    "bad all-zero         -> n=0    err=flate: corrupt input before offset 5",
    "bad flipped-bit      -> n=240  err=<nil>",
    "stored hex=001500eaff73746f72656420626c6f636b20636f6e74656e7473010000ffff",
    "stored out=\"stored block contents\" err=<nil>",
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

    let inputs: [(&str, alloc::vec::Vec<u8>); 7] = [
        ("empty", alloc::vec::Vec::new()),
        ("one-byte", b"a".to_vec()),
        ("repeat", rep("ab", 100)),
        (
            "text",
            b"the quick brown fox jumps over the lazy dog".to_vec(),
        ),
        (
            "incompressible",
            alloc::vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0a, 0x0b],
        ),
        ("long-run", rep("x", 300)),
        (
            "binary",
            alloc::vec![0xffu8, 0xfe, 0x00, 0x01, 0xff, 0xfe, 0x00, 0x01],
        ),
    ];
    let levels: [(&str, int); 5] = [
        ("default", flate::DefaultCompression),
        ("none", flate::NoCompression),
        ("speed", flate::BestSpeed),
        ("best", flate::BestCompression),
        ("huffman", flate::HuffmanOnly),
    ];
    for (lname, lvl) in levels.iter() {
        for (iname, data) in inputs.iter() {
            let mut buf = bytes::Buffer::new();
            let enc = {
                let (mut w, err) = flate::NewWriter(&mut buf, *lvl);
                if !err.IsNil() {
                    chk(
                        &mut failed,
                        &mut ln,
                        fmt::Sprintf!(
                            "deflate %-8s %-15s -> newwriter-err=%q",
                            s(lname),
                            s(iname),
                            err.Error()
                        ),
                    );
                    continue;
                }
                let _ = w.Write(slice::__from_vec(data.clone()));
                let _ = w.Close();
                drop(w);
                buf.Bytes()
            };
            let eb: &[u8] = &enc;
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "deflate %-8s %-15s -> len=%-5d hex=%s",
                    s(lname),
                    s(iname),
                    eb.len() as int,
                    hx(eb)
                ),
            );
            let mut src = bytes::NewReader(enc.clone());
            let mut r = flate::NewReader(&mut src);
            let (out, rerr) = io::ReadAll(&mut r);
            let ob: &[u8] = &out;
            let re = if rerr.IsNil() {
                s("<nil>")
            } else {
                rerr.Error()
            };
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "inflate %-8s %-15s -> same=%-5v err=%s",
                    s(lname),
                    s(iname),
                    ob == &data[..],
                    re
                ),
            );
        }
    }
    for l in [-3 as int, 10, 100] {
        let mut sink = bytes::Buffer::new();
        let (_, err) = flate::NewWriter(&mut sink, l);
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("level %-5d -> err=%q", l, err.Error()),
            );
            continue;
        }
        chk(&mut failed, &mut ln, fmt::Sprintf!("level %-5d -> ok", l));
    }
    {
        let g = unhex(BAD_SRC);
        let mut half = g.clone();
        half.truncate(g.len() / 2);
        let mut last = g.clone();
        last.truncate(g.len() - 1);
        let mut junk = g.clone();
        junk.push(0xff);
        junk.push(0xff);
        let mut flipped = g.clone();
        let mid = g.len() / 2;
        flipped[mid] ^= 0x40;
        let mut one = g.clone();
        one.truncate(1);
        let cases: [(&str, alloc::vec::Vec<u8>); 8] = [
            ("empty", alloc::vec::Vec::new()),
            ("one-byte", one),
            ("truncated-half", half),
            ("truncated-last", last),
            ("trailing-junk", junk),
            ("all-ff", alloc::vec![0xffu8; 16]),
            ("all-zero", alloc::vec![0u8; 16]),
            ("flipped-bit", flipped),
        ];
        for (name, data) in cases.iter() {
            let mut src = bytes::NewReader(slice::__from_vec(data.clone()));
            let mut r = flate::NewReader(&mut src);
            let (out, err) = io::ReadAll(&mut r);
            let re = if err.IsNil() { s("<nil>") } else { err.Error() };
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("bad %-16s -> n=%-4d err=%s", s(name), out.Len(), re),
            );
        }
    }
    {
        let mut buf = bytes::Buffer::new();
        let enc = {
            let (mut w, _) = flate::NewWriter(&mut buf, flate::NoCompression);
            let _ = w.Write(slice::__from_vec(b"stored block contents".to_vec()));
            let _ = w.Close();
            drop(w);
            buf.Bytes()
        };
        let eb: &[u8] = &enc;
        chk(&mut failed, &mut ln, fmt::Sprintf!("stored hex=%s", hx(eb)));
        let mut src = bytes::NewReader(enc);
        let mut r = flate::NewReader(&mut src);
        let (out, err) = io::ReadAll(&mut r);
        let re = if err.IsNil() { s("<nil>") } else { err.Error() };
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("stored out=%q err=%s", out, re),
        );
    }
    let _: byte = 0;
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
