// codecs_ref_smoke — compress/zlib, compress/lzw and compress/bzip2
// against a running Go.
// (compress/zlib, compress/lzw, compress/bzip2)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_codecs_ref.go` run in
// `package flate_test` by `scripts/goref.sh`.
//
// The three codecs that had smokes but had never been diffed. Each
// carries a rule the others do not, and the streams they decode come
// from ELSEWHERE — the zlib ones from Go, the bzip2 ones from the
// system bzip2 — because a decompressor tested only against its own
// compressor tests nothing about the format.
//
// goish matched Go on all 84 lines, and its zlib and lzw output is
// byte-identical to Go's at every level and both orders.
//
//   * zlib wraps DEFLATE in a header AND an Adler-32 checksum, so
//     corruption IS detected: a flipped bit in the body or the trailer
//     both come back as "zlib: invalid checksum". That is the exact
//     contrast with raw flate, pinned in flate_ref_smoke, where the
//     same flip decodes silently — DEFLATE has no checksum, which is
//     why zlib and gzip add one, and pinning both makes the difference
//     visible rather than folklore.
//   * A stream compressed with a DICTIONARY is undecodable without it,
//     and Go says so specifically ("zlib: invalid dictionary") rather
//     than failing as corruption.
//   * lzw's Order and litWidth are part of the FORMAT, not options: the
//     same bytes read LSB-first and MSB-first are different streams and
//     produce "lzw: invalid code", and a litWidth outside 2..8 is
//     refused by name.
//   * bzip2 is decompress-only, so every stream here was produced by a
//     tool outside this tree.
//
// One pinned case is deliberately NOT an error and reads oddly:
// bzip2 "corrupt-crc" flips the last bit and still succeeds, because
// that bit is not part of the CRC. It is pinned as it is rather than
// tidied into the answer it "should" have, since both implementations
// agree and the alternative is asserting something untrue.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::compress::bzip2;
use goish::compress::lzw;
use goish::compress::zlib;
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
fn et(e: &goish::errors::error) -> string {
    if e.IsNil() {
        return s("<nil>");
    }
    return e.Error();
}
// Streams produced elsewhere: the zlib ones by Go, the bzip2 ones by
// the system bzip2. Embedding them is the point — a decompressor tested
// only against its own compressor tests nothing about the format.
const Z_SRC: &str = "789c4ace484dce2e2ecdcd4d4d5118096c40000000fffffe5d5d35";
const Z_DICT: &str = "78bb478e0734c222a490559a5b500c080000ffff7a060983";
const BZ_HELLO: &str = "425a6839314159265359579eb9560000069980400010001664d09020003100d0005541a01a6d17710e36c5e5e759252f3497c5dc914e142415e7ae5580";
const BZ_EMPTY: &str = "425a683917724538509000000000";

// go: none — goish idiom: the reference lines, in the order Go printed
//     them. Comparing whole rendered lines keeps this smoke and the
//     generator in lockstep: a case added to one is a mismatch in the
//     other, never a silent pass.
const GO: [&str; 84] = [
    "zlib default  empty    -> len=11   hex=789c010000ffff00000001",
    "zlibr default  empty    -> same=true  err=<nil>",
    "zlib default  one      -> len=13   hex=789c4a04040000ffff00620062",
    "zlibr default  one      -> same=true  err=<nil>",
    "zlib default  text     -> len=53   hex=789c2ac94855282ccd4cce56482aca2fcf5348cbaf50c82acd2d2856c82f4b2d520049e72456552aa4e4a703020000ffff613c0ffa",
    "zlibr default  text     -> same=true  err=<nil>",
    "zlib default  repeat   -> len=16   hex=789c4a4c1a1e10100000ffffe98f4c2d",
    "zlibr default  repeat   -> same=true  err=<nil>",
    "zlib default  binary   -> len=20   hex=789c626064faf79f819109100000ffff09110204",
    "zlibr default  binary   -> same=true  err=<nil>",
    "zlib none     empty    -> len=11   hex=7801010000ffff00000001",
    "zlibr none     empty    -> same=true  err=<nil>",
    "zlib none     one      -> len=17   hex=7801000100feff61010000ffff00620062",
    "zlibr none     one      -> same=true  err=<nil>",
    "zlib none     text     -> len=59   hex=7801002b00d4ff74686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67010000ffff613c0ffa",
    "zlibr none     text     -> same=true  err=<nil>",
    "zlib none     repeat   -> len=216  hex=780100c80037ff6162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162010000ffffe98f4c2d",
    "zlibr none     repeat   -> same=true  err=<nil>",
    "zlib none     binary   -> len=24   hex=7801000800f7ff000102feff000102010000ffff09110204",
    "zlibr none     binary   -> same=true  err=<nil>",
    "zlib speed    empty    -> len=11   hex=7801010000ffff00000001",
    "zlibr speed    empty    -> same=true  err=<nil>",
    "zlib speed    one      -> len=17   hex=7801000100feff61010000ffff00620062",
    "zlibr speed    one      -> same=true  err=<nil>",
    "zlib speed    text     -> len=56   hex=780104c0870180300844d155fe6a1634d65304dbf479518c33a76ea1753d3b835ee6dc8e0bdde64431d6e6ffe835d6000000ffff613c0ffa",
    "zlibr speed    text     -> same=true  err=<nil>",
    "zlib speed    repeat   -> len=27   hex=7801dcc1810c0000008030d6f287c8a31d1f0a0000ffffe98f4c2d",
    "zlibr speed    repeat   -> same=true  err=<nil>",
    "zlib speed    binary   -> len=24   hex=7801000800f7ff000102feff000102010000ffff09110204",
    "zlibr speed    binary   -> same=true  err=<nil>",
    "zlib best     empty    -> len=11   hex=78da010000ffff00000001",
    "zlibr best     empty    -> same=true  err=<nil>",
    "zlib best     one      -> len=13   hex=78da4a04040000ffff00620062",
    "zlibr best     one      -> same=true  err=<nil>",
    "zlib best     text     -> len=53   hex=78da2ac94855282ccd4cce56482aca2fcf5348cbaf50c82acd2d2856c82f4b2d520049e72456552aa4e4a703020000ffff613c0ffa",
    "zlibr best     text     -> same=true  err=<nil>",
    "zlib best     repeat   -> len=16   hex=78da4a4c1a1e10100000ffffe98f4c2d",
    "zlibr best     repeat   -> same=true  err=<nil>",
    "zlib best     binary   -> len=20   hex=78da626064faf79f819109100000ffff09110204",
    "zlibr best     binary   -> same=true  err=<nil>",
    "zlib-source hex=789c4ace484dce2e2ecdcd4d4d5118096c40000000fffffe5d5d35",
    "zlibbad empty             -> newreader-err=\"unexpected EOF\"",
    "zlibbad header-only       -> n=0    err=unexpected EOF",
    "zlibbad bad-header        -> newreader-err=\"zlib: invalid header\"",
    "zlibbad truncated         -> n=240  err=unexpected EOF",
    "zlibbad corrupt-checksum  -> n=240  err=zlib: invalid checksum",
    "zlibbad corrupt-body      -> n=240  err=zlib: invalid checksum",
    "zlibbad trailing-junk     -> n=240  err=<nil>",
    "zlibdict hex=78bb478e0734c222a490559a5b500c080000ffff7a060983",
    "zlibdict no-dict-err=zlib: invalid dictionary",
    "zlibdict out=\"the quick brown fox jumps\" err=<nil>",
    "lzw lsb  empty    -> len=3    hex=000302",
    "lzwr lsb  empty    -> same=true  err=<nil>",
    "lzw lsb  one      -> len=4    hex=00c30404",
    "lzwr lsb  one      -> same=true  err=<nil>",
    "lzw lsb  text     -> len=49   hex=00e9a02903224e9d3463d6801023e7cd1d3720ccbcc103424d9d3670e6807863a78c1c100209b209a3270f08326fce0404",
    "lzwr lsb  text     -> same=true  err=<nil>",
    "lzw lsb  repeat   -> len=34   hex=00c388114870a0c182080f2a4cc870a1c386101f4a8c4871a2c58a182f6acc583020",
    "lzwr lsb  repeat   -> same=true  err=<nil>",
    "lzw lsb  binary   -> len=11   hex=00010410e0ef9f40010101",
    "lzwr lsb  binary   -> same=true  err=<nil>",
    "lzw msb  empty    -> len=3    hex=804040",
    "lzwr msb  empty    -> same=true  err=<nil>",
    "lzw msb  one      -> len=4    hex=80186020",
    "lzwr msb  one      -> same=true  err=<nil>",
    "lzw msb  text     -> len=49   hex=801d0d065101c4ea69319ac4062391bcee6e10198de78101a8ea6d381cc406f3b194e42081410d8613d1e440643799e020",
    "lzwr msb  text     -> same=true  err=<nil>",
    "lzw msb  repeat   -> len=34   hex=80184c5028240e0d058441e15098642e1d0d8843e25118a44e2d158c45e351982c04",
    "lzwr msb  repeat   -> same=true  err=<nil>",
    "lzw msb  binary   -> len=11   hex=8000002027f3fe04028080",
    "lzwr msb  binary   -> same=true  err=<nil>",
    "lzw-mismatch n=1 err=lzw: invalid code",
    "lzw-litwidth 1  -> n=0 err=lzw: litWidth 1 out of range",
    "lzw-litwidth 2  -> n=0 err=unexpected EOF",
    "lzw-litwidth 8  -> n=0 err=unexpected EOF",
    "lzw-litwidth 9  -> n=0 err=lzw: litWidth 9 out of range",
    "bzip2 hello  -> same=true  n=35  err=<nil>",
    "bzip2 empty  -> same=true  n=0   err=<nil>",
    "bzip2bad empty          -> n=0   err=unexpected EOF",
    "bzip2bad magic-only     -> n=0   err=unexpected EOF",
    "bzip2bad bad-magic      -> n=0   err=bzip2 data invalid: bad magic value",
    "bzip2bad truncated      -> n=0   err=unexpected EOF",
    "bzip2bad corrupt-crc    -> n=35  err=<nil>",
    "bzip2bad trailing-junk  -> n=35  err=bzip2 data invalid: bad magic value in continuation file",
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

    let inputs: [(&str, alloc::vec::Vec<u8>); 5] = [
        ("empty", alloc::vec::Vec::new()),
        ("one", b"a".to_vec()),
        (
            "text",
            b"the quick brown fox jumps over the lazy dog".to_vec(),
        ),
        ("repeat", rep("ab", 100)),
        ("binary", alloc::vec![0u8, 1, 2, 0xfe, 0xff, 0, 1, 2]),
    ];
    let levels: [(&str, int); 4] = [
        ("default", zlib::DefaultCompression),
        ("none", zlib::NoCompression),
        ("speed", zlib::BestSpeed),
        ("best", zlib::BestCompression),
    ];
    for (lname, lvl) in levels.iter() {
        for (iname, data) in inputs.iter() {
            let mut buf = bytes::Buffer::new();
            let enc = {
                let (mut w, err) = zlib::NewWriterLevel(&mut buf, *lvl);
                if !err.IsNil() {
                    chk(
                        &mut failed,
                        &mut ln,
                        fmt::Sprintf!(
                            "zlib %-8s %-8s -> newwriter-err=%q",
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
                    "zlib %-8s %-8s -> len=%-4d hex=%s",
                    s(lname),
                    s(iname),
                    eb.len() as int,
                    hx(eb)
                ),
            );
            let mut src = bytes::NewReader(enc.clone());
            let (mut r, err) = zlib::NewReader(&mut src);
            if !err.IsNil() {
                chk(
                    &mut failed,
                    &mut ln,
                    fmt::Sprintf!(
                        "zlibr %-8s %-8s -> newreader-err=%q",
                        s(lname),
                        s(iname),
                        err.Error()
                    ),
                );
                continue;
            }
            let (out, rerr) = io::ReadAll(&mut r);
            let ob: &[u8] = &out;
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "zlibr %-8s %-8s -> same=%-5v err=%s",
                    s(lname),
                    s(iname),
                    ob == &data[..],
                    et(&rerr)
                ),
            );
        }
    }
    {
        let g = unhex(Z_SRC);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("zlib-source hex=%s", hx(&g)),
        );
        let mut hdr2 = g.clone();
        hdr2.truncate(2);
        let mut trunc = g.clone();
        trunc.truncate(g.len() - 2);
        let mut ck = g.clone();
        let n = ck.len();
        ck[n - 1] ^= 0x01;
        let mut body = g.clone();
        let m = body.len() / 2;
        body[m] ^= 0x40;
        let mut junk = g.clone();
        junk.push(0xde);
        junk.push(0xad);
        let cases: [(&str, alloc::vec::Vec<u8>); 7] = [
            ("empty", alloc::vec::Vec::new()),
            ("header-only", hdr2),
            ("bad-header", alloc::vec![0u8, 0, 3, 0]),
            ("truncated", trunc),
            ("corrupt-checksum", ck),
            ("corrupt-body", body),
            ("trailing-junk", junk),
        ];
        for (name, data) in cases.iter() {
            let mut src = bytes::NewReader(slice::__from_vec(data.clone()));
            let (mut r, err) = zlib::NewReader(&mut src);
            if !err.IsNil() {
                chk(
                    &mut failed,
                    &mut ln,
                    fmt::Sprintf!("zlibbad %-17s -> newreader-err=%q", s(name), err.Error()),
                );
                continue;
            }
            let (out, rerr) = io::ReadAll(&mut r);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "zlibbad %-17s -> n=%-4d err=%s",
                    s(name),
                    out.Len(),
                    et(&rerr)
                ),
            );
        }
    }
    {
        let dict = slice::__from_vec(b"the quick brown fox".to_vec());
        let enc = unhex(Z_DICT);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("zlibdict hex=%s", hx(&enc)),
        );
        let mut s1 = bytes::NewReader(slice::__from_vec(enc.clone()));
        let (_, err) = zlib::NewReader(&mut s1);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("zlibdict no-dict-err=%s", et(&err)),
        );
        let mut s2 = bytes::NewReader(slice::__from_vec(enc));
        let (mut r, err) = zlib::NewReaderDict(&mut s2, dict);
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("zlibdict with-dict-err=%s", et(&err)),
            );
        } else {
            let (out, rerr) = io::ReadAll(&mut r);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("zlibdict out=%q err=%s", out, et(&rerr)),
            );
        }
    }
    for (oname, ord) in [("lsb", lzw::LSB), ("msb", lzw::MSB)].iter() {
        for (iname, data) in inputs.iter() {
            let mut buf = bytes::Buffer::new();
            let enc = {
                let mut w = lzw::NewWriter(&mut buf, *ord, 8);
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
                    "lzw %-4s %-8s -> len=%-4d hex=%s",
                    s(oname),
                    s(iname),
                    eb.len() as int,
                    hx(eb)
                ),
            );
            let mut src = bytes::NewReader(enc.clone());
            let mut r = lzw::NewReader(&mut src, *ord, 8);
            let (out, rerr) = io::ReadAll(&mut r);
            let ob: &[u8] = &out;
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "lzwr %-4s %-8s -> same=%-5v err=%s",
                    s(oname),
                    s(iname),
                    ob == &data[..],
                    et(&rerr)
                ),
            );
        }
    }
    {
        let mut buf = bytes::Buffer::new();
        let enc = {
            let mut w = lzw::NewWriter(&mut buf, lzw::LSB, 8);
            let _ = w.Write(slice::__from_vec(b"mismatch me".to_vec()));
            let _ = w.Close();
            drop(w);
            buf.Bytes()
        };
        let mut src = bytes::NewReader(enc);
        let mut r = lzw::NewReader(&mut src, lzw::MSB, 8);
        let (out, err) = io::ReadAll(&mut r);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("lzw-mismatch n=%d err=%s", out.Len(), et(&err)),
        );
    }
    for lw in [1 as int, 2, 8, 9] {
        let mut src = bytes::NewReader(slice::__from_vec(alloc::vec::Vec::new()));
        let mut r = lzw::NewReader(&mut src, lzw::LSB, lw);
        let (out, err) = io::ReadAll(&mut r);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("lzw-litwidth %-2d -> n=%d err=%s", lw, out.Len(), et(&err)),
        );
    }
    for (name, hexs, want) in [
        ("hello", BZ_HELLO, "hello bzip2 world hello bzip2 world"),
        ("empty", BZ_EMPTY, ""),
    ]
    .iter()
    {
        let data = unhex(hexs);
        let mut src = bytes::NewReader(slice::__from_vec(data));
        let mut r = bzip2::NewReader(&mut src);
        let (out, err) = io::ReadAll(&mut r);
        let ob: &[u8] = &out;
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "bzip2 %-6s -> same=%-5v n=%-3d err=%s",
                s(name),
                ob == want.as_bytes(),
                out.Len(),
                et(&err)
            ),
        );
    }
    {
        let data = unhex(BZ_HELLO);
        let mut m3 = data.clone();
        m3.truncate(3);
        let mut trunc = data.clone();
        trunc.truncate(data.len() / 2);
        let mut crc = data.clone();
        let n = crc.len();
        crc[n - 1] ^= 0x01;
        let mut junk = data.clone();
        junk.push(0);
        junk.push(0);
        let cases: [(&str, alloc::vec::Vec<u8>); 6] = [
            ("empty", alloc::vec::Vec::new()),
            ("magic-only", m3),
            ("bad-magic", b"XYZ98abcdefgh".to_vec()),
            ("truncated", trunc),
            ("corrupt-crc", crc),
            ("trailing-junk", junk),
        ];
        for (name, d) in cases.iter() {
            let mut src = bytes::NewReader(slice::__from_vec(d.clone()));
            let mut r = bzip2::NewReader(&mut src);
            let (out, err) = io::ReadAll(&mut r);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "bzip2bad %-14s -> n=%-3d err=%s",
                    s(name),
                    out.Len(),
                    et(&err)
                ),
            );
        }
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
