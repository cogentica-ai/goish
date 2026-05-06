// crypto/md5 — Go's `crypto/md5`, ported (RFC 1321).
//
// MD5 is cryptographically broken; provided for legacy integrity
// checks (Content-MD5, ETag derivations, file checksums) — not
// for security.
//
// Inlines blockGeneric from md5block.go since goish has no separate
// fips140 internal layer.
//
// Slim deviations:
//   * No MarshalBinary / UnmarshalBinary / AppendBinary / Clone.
//   * No assembly fast path (Go's amd64/arm64/etc. have no MD5 NI).
//   * No crypto.RegisterHash / fips140only hooks.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::hash::Hash;
use crate::io;
use crate::math::bits;
use crate::types::{byte, int};

extern crate alloc;
use alloc::vec::Vec;

// ─── Constants (Go: md5.go:26-41) ─────────────────────────────────────

/// `md5.Size` — MD5 checksum length in bytes.
pub const Size: int = 16;

/// `md5.BlockSize` — MD5 block size in bytes.
pub const BlockSize: int = 64;

const CHUNK: usize = 64;

const init0: u32 = 0x67452301;
const init1: u32 = 0xEFCDAB89;
const init2: u32 = 0x98BADCFE;
const init3: u32 = 0x10325476;

// ─── Digest (Go: md5.go:44) ───────────────────────────────────────────

/// `md5` digest — partial MD5 evaluation.
pub struct Digest {
    s: [u32; 4],
    x: [byte; CHUNK],
    nx: usize,
    len: u64,
}

/// `md5.New()` (md5.go:116) — new MD5 digest.
pub fn New() -> Digest {
    // Go: d := new(digest); d.Reset(); return d
    let mut d = Digest {
        s: [0; 4],
        x: [0; CHUNK],
        nx: 0,
        len: 0,
    };
    d.Reset();
    d
}

// Go: blockGeneric (md5block.go:14)
fn block(dig: &mut Digest, p: &[byte]) {
    // Go: a, b, c, d := dig.s[0], dig.s[1], dig.s[2], dig.s[3]
    let mut a = dig.s[0];
    let mut b = dig.s[1];
    let mut c = dig.s[2];
    let mut d = dig.s[3];

    let mut i: usize = 0;
    while i + CHUNK <= p.len() {
        let q = &p[i..i + CHUNK];

        // Go: aa, bb, cc, dd := a, b, c, d
        let aa = a;
        let bb = b;
        let cc = c;
        let dd = d;

        // Go: x0..xf := byteorder.LEUint32(q[4*N:])
        let le = |k: usize| -> u32 {
            (q[k] as u32)
                | ((q[k + 1] as u32) << 8)
                | ((q[k + 2] as u32) << 16)
                | ((q[k + 3] as u32) << 24)
        };
        let x0 = le(0x0 * 4);
        let x1 = le(0x1 * 4);
        let x2 = le(0x2 * 4);
        let x3 = le(0x3 * 4);
        let x4 = le(0x4 * 4);
        let x5 = le(0x5 * 4);
        let x6 = le(0x6 * 4);
        let x7 = le(0x7 * 4);
        let x8 = le(0x8 * 4);
        let x9 = le(0x9 * 4);
        let xa = le(0xa * 4);
        let xb = le(0xb * 4);
        let xc = le(0xc * 4);
        let xd = le(0xd * 4);
        let xe = le(0xe * 4);
        let xf = le(0xf * 4);

        // Round 1: F = (c^d)&b ^ d
        macro_rules! r1 {
            ($a:ident, $b:ident, $c:ident, $d:ident, $x:ident, $k:expr, $s:expr) => {
                $a = $b.wrapping_add(bits::RotateLeft32(
                    ((($c ^ $d) & $b) ^ $d)
                        .wrapping_add($a)
                        .wrapping_add($x)
                        .wrapping_add($k),
                    $s,
                ));
            };
        }
        r1!(a, b, c, d, x0, 0xd76aa478u32, 7);
        r1!(d, a, b, c, x1, 0xe8c7b756u32, 12);
        r1!(c, d, a, b, x2, 0x242070dbu32, 17);
        r1!(b, c, d, a, x3, 0xc1bdceeeu32, 22);
        r1!(a, b, c, d, x4, 0xf57c0fafu32, 7);
        r1!(d, a, b, c, x5, 0x4787c62au32, 12);
        r1!(c, d, a, b, x6, 0xa8304613u32, 17);
        r1!(b, c, d, a, x7, 0xfd469501u32, 22);
        r1!(a, b, c, d, x8, 0x698098d8u32, 7);
        r1!(d, a, b, c, x9, 0x8b44f7afu32, 12);
        r1!(c, d, a, b, xa, 0xffff5bb1u32, 17);
        r1!(b, c, d, a, xb, 0x895cd7beu32, 22);
        r1!(a, b, c, d, xc, 0x6b901122u32, 7);
        r1!(d, a, b, c, xd, 0xfd987193u32, 12);
        r1!(c, d, a, b, xe, 0xa679438eu32, 17);
        r1!(b, c, d, a, xf, 0x49b40821u32, 22);

        // Round 2: F = (b^c)&d ^ c
        macro_rules! r2 {
            ($a:ident, $b:ident, $c:ident, $d:ident, $x:ident, $k:expr, $s:expr) => {
                $a = $b.wrapping_add(bits::RotateLeft32(
                    ((($b ^ $c) & $d) ^ $c)
                        .wrapping_add($a)
                        .wrapping_add($x)
                        .wrapping_add($k),
                    $s,
                ));
            };
        }
        r2!(a, b, c, d, x1, 0xf61e2562u32, 5);
        r2!(d, a, b, c, x6, 0xc040b340u32, 9);
        r2!(c, d, a, b, xb, 0x265e5a51u32, 14);
        r2!(b, c, d, a, x0, 0xe9b6c7aau32, 20);
        r2!(a, b, c, d, x5, 0xd62f105du32, 5);
        r2!(d, a, b, c, xa, 0x02441453u32, 9);
        r2!(c, d, a, b, xf, 0xd8a1e681u32, 14);
        r2!(b, c, d, a, x4, 0xe7d3fbc8u32, 20);
        r2!(a, b, c, d, x9, 0x21e1cde6u32, 5);
        r2!(d, a, b, c, xe, 0xc33707d6u32, 9);
        r2!(c, d, a, b, x3, 0xf4d50d87u32, 14);
        r2!(b, c, d, a, x8, 0x455a14edu32, 20);
        r2!(a, b, c, d, xd, 0xa9e3e905u32, 5);
        r2!(d, a, b, c, x2, 0xfcefa3f8u32, 9);
        r2!(c, d, a, b, x7, 0x676f02d9u32, 14);
        r2!(b, c, d, a, xc, 0x8d2a4c8au32, 20);

        // Round 3: F = b^c^d
        macro_rules! r3 {
            ($a:ident, $b:ident, $c:ident, $d:ident, $x:ident, $k:expr, $s:expr) => {
                $a = $b.wrapping_add(bits::RotateLeft32(
                    ($b ^ $c ^ $d)
                        .wrapping_add($a)
                        .wrapping_add($x)
                        .wrapping_add($k),
                    $s,
                ));
            };
        }
        r3!(a, b, c, d, x5, 0xfffa3942u32, 4);
        r3!(d, a, b, c, x8, 0x8771f681u32, 11);
        r3!(c, d, a, b, xb, 0x6d9d6122u32, 16);
        r3!(b, c, d, a, xe, 0xfde5380cu32, 23);
        r3!(a, b, c, d, x1, 0xa4beea44u32, 4);
        r3!(d, a, b, c, x4, 0x4bdecfa9u32, 11);
        r3!(c, d, a, b, x7, 0xf6bb4b60u32, 16);
        r3!(b, c, d, a, xa, 0xbebfbc70u32, 23);
        r3!(a, b, c, d, xd, 0x289b7ec6u32, 4);
        r3!(d, a, b, c, x0, 0xeaa127fau32, 11);
        r3!(c, d, a, b, x3, 0xd4ef3085u32, 16);
        r3!(b, c, d, a, x6, 0x04881d05u32, 23);
        r3!(a, b, c, d, x9, 0xd9d4d039u32, 4);
        r3!(d, a, b, c, xc, 0xe6db99e5u32, 11);
        r3!(c, d, a, b, xf, 0x1fa27cf8u32, 16);
        r3!(b, c, d, a, x2, 0xc4ac5665u32, 23);

        // Round 4: F = c ^ (b | ^d)
        macro_rules! r4 {
            ($a:ident, $b:ident, $c:ident, $d:ident, $x:ident, $k:expr, $s:expr) => {
                $a = $b.wrapping_add(bits::RotateLeft32(
                    ($c ^ ($b | (!$d)))
                        .wrapping_add($a)
                        .wrapping_add($x)
                        .wrapping_add($k),
                    $s,
                ));
            };
        }
        r4!(a, b, c, d, x0, 0xf4292244u32, 6);
        r4!(d, a, b, c, x7, 0x432aff97u32, 10);
        r4!(c, d, a, b, xe, 0xab9423a7u32, 15);
        r4!(b, c, d, a, x5, 0xfc93a039u32, 21);
        r4!(a, b, c, d, xc, 0x655b59c3u32, 6);
        r4!(d, a, b, c, x3, 0x8f0ccc92u32, 10);
        r4!(c, d, a, b, xa, 0xffeff47du32, 15);
        r4!(b, c, d, a, x1, 0x85845dd1u32, 21);
        r4!(a, b, c, d, x8, 0x6fa87e4fu32, 6);
        r4!(d, a, b, c, xf, 0xfe2ce6e0u32, 10);
        r4!(c, d, a, b, x6, 0xa3014314u32, 15);
        r4!(b, c, d, a, xd, 0x4e0811a1u32, 21);
        r4!(a, b, c, d, x4, 0xf7537e82u32, 6);
        r4!(d, a, b, c, xb, 0xbd3af235u32, 10);
        r4!(c, d, a, b, x2, 0x2ad7d2bbu32, 15);
        r4!(b, c, d, a, x9, 0xeb86d391u32, 21);

        // Go: a += aa; b += bb; c += cc; d += dd
        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);

        i += CHUNK;
    }

    dig.s[0] = a;
    dig.s[1] = b;
    dig.s[2] = c;
    dig.s[3] = d;
}

// ─── Hash trait impls for Digest ──────────────────────────────────────

impl io::Writer for Digest {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: md5.go:126 (digest.Write)
        let raw: &[byte] = &p;
        let nn = raw.len();
        self.len += nn as u64;
        let mut q: &[byte] = raw;
        if self.nx > 0 {
            let copy_n = core::cmp::min(CHUNK - self.nx, q.len());
            self.x[self.nx..self.nx + copy_n].copy_from_slice(&q[..copy_n]);
            self.nx += copy_n;
            if self.nx == CHUNK {
                let buf = self.x;
                block(self, &buf);
                self.nx = 0;
            }
            q = &q[copy_n..];
        }
        if q.len() >= CHUNK {
            let n = q.len() & !(CHUNK - 1);
            block(self, &q[..n]);
            q = &q[n..];
        }
        if !q.is_empty() {
            self.x[..q.len()].copy_from_slice(q);
            self.nx = q.len();
        }
        (nn as int, nil)
    }
}

impl Hash for Digest {
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        // Go: md5.go:168 — copy then checkSum then append.
        let mut d0 = Digest {
            s: self.s,
            x: self.x,
            nx: self.nx,
            len: self.len,
        };
        let digest = check_sum(&mut d0);
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(&digest);
        slice::__from_vec(out)
    }
    fn Reset(&mut self) {
        // Go: md5.go:51
        self.s[0] = init0;
        self.s[1] = init1;
        self.s[2] = init2;
        self.s[3] = init3;
        self.nx = 0;
        self.len = 0;
    }
    fn Size(&self) -> int {
        Size
    }
    fn BlockSize(&self) -> int {
        BlockSize
    }
}

// Go: checkSum (md5.go:175)
fn check_sum(d: &mut Digest) -> [byte; 16] {
    // Go: tmp := [1+63+8]byte{0x80}
    let mut tmp = [0u8; 1 + 63 + 8];
    tmp[0] = 0x80;
    // Go: pad := (55 - d.len) % 64
    // (subtraction wraps in unsigned, then modulo masks to 0..63)
    let pad = (55u64.wrapping_sub(d.len)) % 64;
    let pad_us = pad as usize;
    // Go: byteorder.LEPutUint64(tmp[1+pad:], d.len<<3)
    let bit_len = d.len << 3;
    let off = 1 + pad_us;
    tmp[off] = bit_len as byte;
    tmp[off + 1] = (bit_len >> 8) as byte;
    tmp[off + 2] = (bit_len >> 16) as byte;
    tmp[off + 3] = (bit_len >> 24) as byte;
    tmp[off + 4] = (bit_len >> 32) as byte;
    tmp[off + 5] = (bit_len >> 40) as byte;
    tmp[off + 6] = (bit_len >> 48) as byte;
    tmp[off + 7] = (bit_len >> 56) as byte;
    // Go: d.Write(tmp[:1+pad+8])
    let total = 1 + pad_us + 8;
    let padv: Vec<byte> = tmp[..total].to_vec();
    let _ = io::Writer::Write(d, slice::__from_vec(padv));

    if d.nx != 0 {
        panic!("d.nx != 0");
    }

    // Go: byteorder.LEPutUint32(digest[i*4:], d.s[i])
    let mut digest = [0u8; 16];
    for i in 0..4 {
        let s = d.s[i];
        digest[i * 4] = s as byte;
        digest[i * 4 + 1] = (s >> 8) as byte;
        digest[i * 4 + 2] = (s >> 16) as byte;
        digest[i * 4 + 3] = (s >> 24) as byte;
    }
    digest
}

// ─── One-shot helper (Go: md5.go:205) ─────────────────────────────────

/// `md5.Sum(data)` (md5.go:205) — MD5 of `data`.
pub fn Sum(data: slice<byte>) -> [byte; 16] {
    // Go: var d digest; d.Reset(); d.Write(data); return d.checkSum()
    let mut d = New();
    let _ = io::Writer::Write(&mut d, data);
    check_sum(&mut d)
}

// ─── Boxed constructor for trait-object consumers (e.g. hmac::New) ────

/// `md5.NewHash()` — boxed constructor matching `hash.Hash` interface.
/// Use with `hmac::New(crypto::md5::NewHash, key)`.
pub fn NewHash() -> alloc::boxed::Box<dyn Hash> {
    alloc::boxed::Box::new(New())
}
