// crc64_maphash_ref_smoke — hash/crc64 and hash/maphash against a running Go.
// (hash/crc64/crc64.go, hash/maphash/maphash.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_crc64_ref.go` run in
// `package crc64_test` by `scripts/goref.sh`. goish matched Go on all
// 92 lines.
//
// Two hashes with OPPOSITE contracts, measured together because the
// contrast is the lesson.
//
// crc64 is a checksum: its value IS the contract, it must be identical
// everywhere, and an artifact carrying one is unreadable if two
// implementations disagree by a bit. So it is pinned byte for byte
// across both polynomials. ISO and ECMA are different tables, crc64 has
// NO other user in this tree, and nothing else would notice if one of
// them were wrong — which is the whole reason to measure it. Two
// arbitrary polynomials are included so MakeTable is measured rather
// than two baked-in tables.
//
// maphash is the opposite: its value is deliberately NOT stable. Every
// process picks a random seed, so the same bytes hash differently
// between runs and a caller must never persist or transmit a value. A
// port whose maphash was stable across processes would look MORE
// useful and would be wrong — code would come to depend on it, and the
// hash-flooding resistance the random seed exists to provide would be
// gone.
//
// So what is pinned for maphash is its INVARIANTS, which is all a
// caller may rely on: the same seed gives the same answer, two seeds
// give different answers, Bytes and String agree for the same input,
// and the streaming Hash agrees with the one-shot however the bytes
// are fed — as a string, as a slice, or one byte at a time. Reset
// KEEPS the seed, so a Hash reset and refed matches itself and not a
// fresh Hash, which is the property anyone reusing a Hash in a loop
// depends on.
//
// One gap closed. Go's `maphash.Seed` is a struct of one uint64 and is
// therefore COMPARABLE — `s1 == s2` is ordinary Go, and a caller
// checking that a Hash kept its seed across Reset writes exactly that.
// goish's derive list omitted PartialEq, so the comparison did not
// compile. The last two lines here are the ones that could not be
// written before.
//
// crc64's boundaries are the same ones that matter for every checksum:
// the empty input, a single zero byte, and lengths at 15/16/17 that
// cross the table-lookup stride. Sum appends to the slice it is given
// rather than replacing it.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::vec::Vec;
use goish::encoding::hex;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::hash::crc64;
use goish::hash::maphash;
use goish::hash::{Hash, Hash64};
use goish::io::Writer;
use goish::strings;
use goish::syscall;
use goish::types::{byte, int, uint64};
const GO: [&str; 92] = [
    "crc64 ISO         empty        -> 0000000000000000",
    "crc64 ISO         zero-byte    -> 6f90000000000000",
    "crc64 ISO         one          -> 3420000000000000",
    "crc64 ISO         abc          -> 3776c42000000000",
    "crc64 ISO         check        -> b90956c775a41001",
    "crc64 ISO         eight        -> 0e21b002d36776c4",
    "crc64 ISO         fifteen      -> 0b788c9364af5b6e",
    "crc64 ISO         sixteen      -> 7cbb788c9364af5b",
    "crc64 ISO         seventeen    -> 570cbb788c9364af",
    "crc64 ISO         long         -> 81098f75a11b7f86",
    "crc64 ISO         binary       -> fffe4c0c9e4f9000",
    "crc64 ISO         high-bytes   -> 90ffff00ffffffff",
    "crc64 ISO         update-seeded -> a6add9deadbeefca",
    "crc64 ECMA        empty        -> 0000000000000000",
    "crc64 ECMA        zero-byte    -> 1fada17364673f59",
    "crc64 ECMA        one          -> 330284772e652b05",
    "crc64 ECMA        abc          -> 2cd8094a1a277627",
    "crc64 ECMA        check        -> 995dc9bbdf1939fa",
    "crc64 ECMA        eight        -> 67b4f30a647a0c59",
    "crc64 ECMA        fifteen      -> c84b31adfd591e7e",
    "crc64 ECMA        sixteen      -> 67909898614b2449",
    "crc64 ECMA        seventeen    -> 6ec755aaf04d62c0",
    "crc64 ECMA        long         -> 4325c1440b540923",
    "crc64 ECMA        binary       -> 093c51cecdb44505",
    "crc64 ECMA        high-bytes   -> 7642bad50786112f",
    "crc64 ECMA        update-seeded -> d0f2ae88154abf69",
    "crc64 custom-1    empty        -> 0000000000000000",
    "crc64 custom-1    zero-byte    -> ff00000000000000",
    "crc64 custom-1    one          -> ff00000000000001",
    "crc64 custom-1    abc          -> ffffff0000000000",
    "crc64 custom-1    check        -> fffffffffffffffe",
    "crc64 custom-1    eight        -> fffffffffffffffe",
    "crc64 custom-1    fifteen      -> ffffffffffffffff",
    "crc64 custom-1    sixteen      -> fffffffffffffffe",
    "crc64 custom-1    seventeen    -> fffffffffffffffe",
    "crc64 custom-1    long         -> ffffffffffffffff",
    "crc64 custom-1    binary       -> ffffffffffff0000",
    "crc64 custom-1    high-bytes   -> ffffffffffffffff",
    "crc64 custom-1    update-seeded -> ffffffdeadbeefca",
    "crc64 custom-max  empty        -> 0000000000000000",
    "crc64 custom-max  zero-byte    -> feffffffffffffff",
    "crc64 custom-max  one          -> 3cffffffffffffff",
    "crc64 custom-max  abc          -> 393b3cffffffffff",
    "crc64 custom-max  check        -> 4b8f91939597999b",
    "crc64 custom-max  eight        -> 2f31333537393b3c",
    "crc64 custom-max  fifteen      -> 43454f495b5d54d0",
    "crc64 custom-max  sixteen      -> 4143454f495b5d54",
    "crc64 custom-max  seventeen    -> b4bebcbab0b6a4a2",
    "crc64 custom-max  long         -> a0f313c611753eee",
    "crc64 custom-max  binary       -> fffdfa0402010000",
    "crc64 custom-max  high-bytes   -> ffffffffffffff80",
    "crc64 custom-max  update-seeded -> 3bb1bfdeadbeefca",
    "crc64r empty        -> stream=true bytewise=true size=8 blocksize=1",
    "crc64r zero-byte    -> stream=true bytewise=true size=8 blocksize=1",
    "crc64r one          -> stream=true bytewise=true size=8 blocksize=1",
    "crc64r abc          -> stream=true bytewise=true size=8 blocksize=1",
    "crc64r check        -> stream=true bytewise=true size=8 blocksize=1",
    "crc64r eight        -> stream=true bytewise=true size=8 blocksize=1",
    "crc64r fifteen      -> stream=true bytewise=true size=8 blocksize=1",
    "crc64r sixteen      -> stream=true bytewise=true size=8 blocksize=1",
    "crc64r seventeen    -> stream=true bytewise=true size=8 blocksize=1",
    "crc64r long         -> stream=true bytewise=true size=8 blocksize=1",
    "crc64r binary       -> stream=true bytewise=true size=8 blocksize=1",
    "crc64r high-bytes   -> stream=true bytewise=true size=8 blocksize=1",
    "crc64 sum-append=aa2cd8094a1a277627",
    "crc64 after-reset=0000000000000000",
    "maphash empty        -> stable=true  seed-differs=true  bytes-eq-string=true",
    "maphash zero-byte    -> stable=true  seed-differs=true  bytes-eq-string=true",
    "maphash one          -> stable=true  seed-differs=true  bytes-eq-string=true",
    "maphash abc          -> stable=true  seed-differs=true  bytes-eq-string=true",
    "maphash check        -> stable=true  seed-differs=true  bytes-eq-string=true",
    "maphash eight        -> stable=true  seed-differs=true  bytes-eq-string=true",
    "maphash fifteen      -> stable=true  seed-differs=true  bytes-eq-string=true",
    "maphash sixteen      -> stable=true  seed-differs=true  bytes-eq-string=true",
    "maphash seventeen    -> stable=true  seed-differs=true  bytes-eq-string=true",
    "maphash long         -> stable=true  seed-differs=true  bytes-eq-string=true",
    "maphash binary       -> stable=true  seed-differs=true  bytes-eq-string=true",
    "maphash high-bytes   -> stable=true  seed-differs=true  bytes-eq-string=true",
    "maphashr empty       -> writestring=true  bytewise=true  write=true  size=8",
    "maphashr zero-byte   -> writestring=true  bytewise=true  write=true  size=8",
    "maphashr one         -> writestring=true  bytewise=true  write=true  size=8",
    "maphashr abc         -> writestring=true  bytewise=true  write=true  size=8",
    "maphashr check       -> writestring=true  bytewise=true  write=true  size=8",
    "maphashr eight       -> writestring=true  bytewise=true  write=true  size=8",
    "maphashr fifteen     -> writestring=true  bytewise=true  write=true  size=8",
    "maphashr sixteen     -> writestring=true  bytewise=true  write=true  size=8",
    "maphashr seventeen   -> writestring=true  bytewise=true  write=true  size=8",
    "maphashr long        -> writestring=true  bytewise=true  write=true  size=8",
    "maphashr binary      -> writestring=true  bytewise=true  write=true  size=8",
    "maphashr high-bytes  -> writestring=true  bytewise=true  write=true  size=8",
    "maphash reset-stable=true fresh-differs=true seed-nonzero=true",
    "maphash seed-self-eq=true seed-differs=true",
];

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

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn bs(v: Vec<u8>) -> slice<byte> {
    return slice::<byte>::__from_vec(v);
}
fn sb(x: &string) -> slice<byte> {
    return bs(x.as_bytes().to_vec());
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    let long = strings::Repeat(s("The quick brown fox. "), 50);
    let ff64 = strings::Repeat(string::from_bytes(b"\xff"), 64);
    let inputs: [(&str, string); 12] = [
        ("empty", string::new()),
        ("zero-byte", string::from_bytes(b"\x00")),
        ("one", s("a")),
        ("abc", s("abc")),
        ("check", s("123456789")),
        ("eight", s("abcdefgh")),
        ("fifteen", s("abcdefghijklmno")),
        ("sixteen", s("abcdefghijklmnop")),
        ("seventeen", s("abcdefghijklmnopq")),
        ("long", long),
        ("binary", string::from_bytes(b"\x00\x01\x02\xfd\xfe\xff")),
        ("high-bytes", ff64),
    ];
    let tables: [(&str, uint64); 4] = [
        ("ISO", crc64::ISO),
        ("ECMA", crc64::ECMA),
        ("custom-1", 0x0000000000000001),
        ("custom-max", 0xffffffffffffffff),
    ];
    for (tn, poly) in tables.iter() {
        let tbl = crc64::MakeTable(*poly);
        for (name, data) in inputs.iter() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "crc64 %-11s %-12s -> %016x",
                    s(tn),
                    s(name),
                    crc64::Checksum(sb(data), &tbl)
                ),
            );
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "crc64 %-11s update-seeded -> %016x",
                s(tn),
                crc64::Update(0xdeadbeefcafebabe, &tbl, sb(&s("abc")))
            ),
        );
    }
    {
        let tbl = crc64::MakeTable(crc64::ECMA);
        for (name, data) in inputs.iter() {
            let one = crc64::Checksum(sb(data), &tbl);
            let mut h = crc64::New(tbl.clone());
            let _ = h.Write(sb(data));
            let mut h2 = crc64::New(tbl.clone());
            for b in data.as_bytes() {
                let _ = h2.Write(bs(alloc::vec![*b]));
            }
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "crc64r %-12s -> stream=%v bytewise=%v size=%d blocksize=%d",
                    s(name),
                    h.Sum64() == one,
                    h2.Sum64() == one,
                    h.Size(),
                    h.BlockSize()
                ),
            );
        }
        let mut h = crc64::New(tbl.clone());
        let _ = h.Write(sb(&s("abc")));
        let out = h.Sum(bs(alloc::vec![0xaa]));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("crc64 sum-append=%s", hex::EncodeToString(&out.to_vec())),
        );
        h.Reset();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("crc64 after-reset=%016x", h.Sum64()),
        );
    }
    {
        let s1 = maphash::MakeSeed();
        let s2 = maphash::MakeSeed();
        for (name, data) in inputs.iter() {
            let a = maphash::String(s1, data.clone());
            let b = maphash::String(s1, data.clone());
            let c = maphash::String(s2, data.clone());
            let d = maphash::Bytes(s1, sb(data));
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "maphash %-12s -> stable=%-5v seed-differs=%-5v bytes-eq-string=%v",
                    s(name),
                    a == b,
                    a != c,
                    a == d
                ),
            );
        }
        for (name, data) in inputs.iter() {
            let want = maphash::String(s1, data.clone());
            let mut h = maphash::Hash::default();
            h.SetSeed(s1);
            let _ = h.WriteString(data.clone());
            let mut h2 = maphash::Hash::default();
            h2.SetSeed(s1);
            for b in data.as_bytes() {
                let _ = h2.WriteByte(*b);
            }
            let mut h3 = maphash::Hash::default();
            h3.SetSeed(s1);
            let _ = h3.Write(sb(data));
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "maphashr %-11s -> writestring=%-5v bytewise=%-5v write=%-5v size=%d",
                    s(name),
                    h.Sum64() == want,
                    h2.Sum64() == want,
                    h3.Sum64() == want,
                    h.Size()
                ),
            );
        }
        let mut h = maphash::Hash::default();
        let _ = h.WriteString(s("abc"));
        let first = h.Sum64();
        h.Reset();
        let _ = h.WriteString(s("abc"));
        let second = h.Sum64();
        let mut other = maphash::Hash::default();
        let _ = other.WriteString(s("abc"));
        let zero = maphash::Seed::default();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "maphash reset-stable=%v fresh-differs=%v seed-nonzero=%v",
                first == second,
                first != other.Sum64(),
                h.Seed() != zero
            ),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "maphash seed-self-eq=%v seed-differs=%v",
                s1 == s1,
                s1 != s2
            ),
        );
    }
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
