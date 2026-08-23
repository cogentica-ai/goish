// xxh3_smoke — the github.com/zeebo/xxh3 port surface typescript-go
// hashes content with: Hash128 / HashString128 / Uint128 / streaming
// Hasher, plus the 64-bit family (Hash / HashString / Hasher.Sum64)
// that tracing's stable thread IDs need. Assertion values are reference
// vectors produced by the real zeebo/xxh3 (Go) over deterministic
// xorshift buffers; the 128-bit sweep matched exactly at port time
// (2026-07-23) and the 64-bit family was added and swept the same way.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;
use goish::{syscall, xxh3};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

/// Same deterministic filler as the reference-vector generator.
fn fill(n: usize) -> Vec<u8> {
    let mut b = alloc::vec![0u8; n];
    let mut state: u64 = 0x9E3779B97F4A7C15;
    for i in 0..n {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        b[i] = state as u8;
    }
    b
}

include!("include/xxh3_sweep64.rs");

fn expect64(n: usize, want: u64, msg: &[u8]) {
    if xxh3::Hash(&fill(n)[..]) != want {
        die(msg);
    }
}

fn expect(n: usize, hi: u64, lo: u64, msg: &[u8]) {
    let h = xxh3::Hash128(&fill(n)[..]);
    if h.Hi != hi || h.Lo != lo {
        die(msg);
    }
}

#[goish::main]
fn main() {
    // ─── 1. one-shot vectors across every size class ───────────────
    expect(0, 0x99aa06d3014798d8, 0x6001c324468d497f, b"t1: empty\n");
    expect(1, 0x22e0f229e62f4dfa, 0xf538d79fd227fb5a, b"t1: len 1\n");
    expect(3, 0xb7ff0aed4fe98ff5, 0xa923e223fb2db579, b"t1: len 3\n");
    expect(
        8,
        0xb19d0b5570d4f7c2,
        0x4cc884410fc431b0,
        b"t1: len 8 (4-8 class)\n",
    );
    expect(
        16,
        0xd59f7d8a670a120c,
        0xda104e0e92b92ab5,
        b"t1: len 16 (9-16 class)\n",
    );
    expect(
        100,
        0x7578ee648027fe8b,
        0x47e5e246671542c7,
        b"t1: len 100 (17-128)\n",
    );
    expect(
        240,
        0x900a1bc3b8998817,
        0x46a9f03f26915c0a,
        b"t1: len 240 (129-240)\n",
    );
    expect(
        241,
        0xb98e6930da993da1,
        0x15d313c6669c668c,
        b"t1: len 241 (long head)\n",
    );
    expect(
        1024,
        0x42b9fc9a5558669d,
        0x167a4ff2b7f6e8df,
        b"t1: len 1024 (block edge)\n",
    );
    expect(
        1025,
        0xf841813c059e8d32,
        0x175b38b1d35c8b95,
        b"t1: len 1025\n",
    );
    expect(
        1089,
        0x598bf64e567f555c,
        0xcf5fb001e32a4dd5,
        b"t1: len 1089 (buf edge)\n",
    );
    expect(
        100000,
        0x1fdfe43dfad48aa0,
        0x37ae5ab7973f0fce,
        b"t1: len 100000\n",
    );

    // ─── 2. streaming == one-shot, any chunking ────────────────────
    let b = fill(100000);
    for &chunk in [1usize, 7, 64, 1024, 4096].iter() {
        let mut h = xxh3::New();
        let mut off = 0;
        while off < b.len() {
            let end = (off + chunk).min(b.len());
            let _ = h.Write(&b[off..end]);
            off = end;
        }
        let s = h.Sum128();
        check(
            s.Hi == 0x1fdfe43dfad48aa0 && s.Lo == 0x37ae5ab7973f0fce,
            b"t2: streamed 100000 mismatch\n",
        );
    }
    // Sub-one-shot sizes stream through the blk==0 path.
    let mut h = xxh3::New();
    let small = fill(241);
    let _ = h.Write(&small[..100]);
    let _ = h.Write(&small[100..]);
    let s = h.Sum128();
    check(
        s == xxh3::Hash128(&small[..]),
        b"t2b: split small == one-shot\n",
    );

    // ─── 3. the typescript-go usage patterns ───────────────────────
    // HashString128 + Bytes canonical form (extendedconfigcache /
    // incremental snapshot shape).
    let u = xxh3::HashString128("hello, goish");
    check(
        u.Hi == 0x3ee0438014dfbfc6 && u.Lo == 0xffacb08bbbe87709,
        b"t3: HashString128\n",
    );
    let bs = u.Bytes();
    check(
        bs[0] == 0x3e && bs[7] == 0xc6 && bs[8] == 0xff && bs[15] == 0x09,
        b"t3: Bytes big-endian canonical\n",
    );

    // Comparable + zero value (overlayfs / extendedconfigcache shape:
    // `entry.Hash == xxh3.Uint128{}`).
    let zero = xxh3::Uint128::default();
    check(zero != u, b"t3b: zero != real hash\n");
    check(
        zero == xxh3::Uint128 { Hi: 0, Lo: 0 },
        b"t3b: zero compare\n",
    );

    // Hasher reuse via Reset (checker hashWrite shape: many small
    // writes of binary values).
    let mut h = xxh3::New();
    let _ = h.WriteString("part one|");
    let _ = h.Write(42_u64.to_le_bytes());
    let first = h.Sum128();
    h.Reset();
    let _ = h.WriteString("part one|");
    let _ = h.Write(42_u64.to_le_bytes());
    check(h.Sum128() == first, b"t3c: Reset reproducibility\n");
    h.Reset();
    let _ = h.WriteString("different");
    check(h.Sum128() != first, b"t3c: different input differs\n");

    // ─── 4. the 64-bit family ──────────────────────────────────────
    // One-shot vectors across every size class.
    expect64(0, 0x2d06800538d394c2, b"t4: len 0\n");
    expect64(1, 0xf538d79fd227fb5a, b"t4: len 1\n");
    expect64(3, 0xa923e223fb2db579, b"t4: len 3\n");
    expect64(8, 0xc709accf2cba8434, b"t4: len 8 (4-8 class)\n");
    expect64(16, 0xf39430324abc1245, b"t4: len 16 (9-16 class)\n");
    expect64(100, 0xde6353941816ab56, b"t4: len 100 (17-128)\n");
    expect64(240, 0xc20b499b4eca149d, b"t4: len 240 (129-240)\n");
    expect64(241, 0x15d313c6669c668c, b"t4: len 241 (long head)\n");
    expect64(1024, 0x167a4ff2b7f6e8df, b"t4: len 1024 (block edge)\n");
    expect64(1025, 0x175b38b1d35c8b95, b"t4: len 1025\n");
    expect64(1089, 0xcf5fb001e32a4dd5, b"t4: len 1089 (buf edge)\n");
    expect64(100000, 0x37ae5ab7973f0fce, b"t4: len 100000\n");

    // Exhaustive sweep of EVERY length 0..=300, so no size-class
    // boundary can be missed by a hand-picked list.
    for n in 0..=300usize {
        if xxh3::Hash(&fill(n)[..]) != SWEEP64[n] {
            die(b"t4b: sweep64 mismatch\n");
        }
    }

    // HashString agrees with Hash over the same bytes.
    check(
        xxh3::HashString("hello, goish") == xxh3::Hash(b"hello, goish"),
        b"t4c: HashString literal\n",
    );
    check(
        xxh3::HashString("") == xxh3::Hash(b""),
        b"t4c: HashString empty\n",
    );

    // Streaming Sum64 == one-shot, at every chunking, including the
    // block-carry path above 1024 bytes.
    let b64 = fill(100000);
    for &chunk in [1usize, 7, 64, 100, 1024, 4096].iter() {
        let mut h = xxh3::New();
        let mut off = 0;
        while off < b64.len() {
            let end = (off + chunk).min(b64.len());
            let _ = h.Write(&b64[off..end]);
            off = end;
        }
        check(h.Sum64() == 0x37ae5ab7973f0fce, b"t4d: streamed 100000\n");
    }
    // Sub-block sizes go through the blk==0 path.
    for &n in [0usize, 5, 64, 100, 240, 241, 1024, 1088, 1089].iter() {
        let b = fill(n);
        let mut h = xxh3::New();
        let _ = h.Write(&b[..n / 2]);
        let _ = h.Write(&b[n / 2..]);
        check(h.Sum64() == xxh3::Hash(&b[..]), b"t4d: split == one-shot\n");
    }
    // Sum64 and Sum128 share a hasher without disturbing each other.
    let mut h = xxh3::New();
    let _ = h.WriteString("shared state");
    let s64 = h.Sum64();
    let s128 = h.Sum128();
    check(h.Sum64() == s64, b"t4e: Sum64 is non-destructive\n");
    check(h.Sum128() == s128, b"t4e: Sum128 is non-destructive\n");

    let msg = b"XXH3_OK all 4 test groups passed\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
    syscall::Exit(0);
}
