// checksum_ref_smoke — hash/crc32, hash/adler32 and hash/fnv against a running Go.
// (hash/crc32/crc32.go, hash/adler32/adler32.go, hash/fnv/fnv.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_crc32_ref.go` run in
// `package crc32_test` by `scripts/goref.sh`. goish matched Go on all
// 128 lines — no defects found.
//
// A checksum has one job and no interesting behaviour except its VALUE.
// Every artifact that stores one — a gzip trailer, a zip directory, a
// zlib stream, a protocol frame — becomes unreadable to the other side
// if the two implementations disagree by a bit, and the failure
// surfaces as "corrupt data" a long way from its cause.
//
// The three CRC polynomials are here because only IEEE has any other
// user in the tree: gzip and zlib exercise it on every round trip, so
// it was already proven. Castagnoli and Koopman have NO other user, and
// nothing else in the tree would notice if their tables were wrong.
// Two arbitrary polynomials are included as well, so MakeTable is
// measured rather than three baked-in tables.
//
// The boundaries are what separate a real implementation from a
// plausible one:
//
//   * The EMPTY input is not zero for two of these three algorithms.
//     adler32 of nothing is 1, and FNV of nothing is the offset basis
//     — 811c9dc5 and cbf29ce484222325. Those constants are the single
//     most commonly mis-ported thing in this family, because a
//     zero-initialised accumulator looks right until the first empty
//     buffer.
//   * A single ZERO byte is different again from the empty input.
//   * Lengths at 15/16/17 and 31/32/33 cross the table-lookup stride,
//     which is where a slice-by-eight or slice-by-sixteen
//     implementation gets its tail wrong.
//   * The one-shot, the streaming and the fed-one-byte-at-a-time paths
//     must all agree, on every input.
//   * "123456789" is the canonical CRC check vector, so `ieee check ->
//     cbf43926` anchors this to the STANDARD rather than only to Go.
//
// Sum appends to the slice it is given rather than replacing it —
// pinned with a two-byte prefix, because a caller who assumes
// otherwise gets a checksum with garbage in front of it and no error.

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
use goish::hash::adler32;
use goish::hash::crc32;
use goish::hash::fnv;
use goish::hash::{Hash, Hash32, Hash64};
use goish::io::Writer;
use goish::strings;
use goish::syscall;
use goish::types::{byte, int, uint32};
const GO: [&str; 128] = [
    "crc32 IEEE         empty        -> 00000000",
    "crc32 IEEE         zero-byte    -> d202ef8d",
    "crc32 IEEE         one          -> e8b7be43",
    "crc32 IEEE         abc          -> 352441c2",
    "crc32 IEEE         check        -> cbf43926",
    "crc32 IEEE         eight        -> aeef2a50",
    "crc32 IEEE         fifteen      -> 519167df",
    "crc32 IEEE         sixteen      -> 943ac093",
    "crc32 IEEE         seventeen    -> 9c925619",
    "crc32 IEEE         thirtyone    -> c157f85e",
    "crc32 IEEE         thirtytwo    -> 00ce3d88",
    "crc32 IEEE         thirtythree  -> 6fbfd3ac",
    "crc32 IEEE         long         -> 58819aef",
    "crc32 IEEE         binary       -> 3c8a83a5",
    "crc32 IEEE         high-bytes   -> 0f6187ba",
    "crc32 IEEE         update-seeded -> 45bb8ae2",
    "crc32 Castagnoli   empty        -> 00000000",
    "crc32 Castagnoli   zero-byte    -> 527d5351",
    "crc32 Castagnoli   one          -> c1d04330",
    "crc32 Castagnoli   abc          -> 364b3fb7",
    "crc32 Castagnoli   check        -> e3069283",
    "crc32 Castagnoli   eight        -> 0a9421b7",
    "crc32 Castagnoli   fifteen      -> bf1a2c62",
    "crc32 Castagnoli   sixteen      -> a3a7fee5",
    "crc32 Castagnoli   seventeen    -> 07ec9fa7",
    "crc32 Castagnoli   thirtyone    -> f7104fc4",
    "crc32 Castagnoli   thirtytwo    -> addcfe07",
    "crc32 Castagnoli   thirtythree  -> 7d5be786",
    "crc32 Castagnoli   long         -> 4b11420c",
    "crc32 Castagnoli   binary       -> 130aa6a7",
    "crc32 Castagnoli   high-bytes   -> 2fcd4e66",
    "crc32 Castagnoli   update-seeded -> 85d9eace",
    "crc32 Koopman      empty        -> 00000000",
    "crc32 Koopman      zero-byte    -> 3f522c72",
    "crc32 Koopman      one          -> 0da2aa8a",
    "crc32 Koopman      abc          -> ba2322ac",
    "crc32 Koopman      check        -> 2d3dd0ae",
    "crc32 Koopman      eight        -> d5cc0e40",
    "crc32 Koopman      fifteen      -> c8320257",
    "crc32 Koopman      sixteen      -> a3498e99",
    "crc32 Koopman      seventeen    -> 3142787e",
    "crc32 Koopman      thirtyone    -> b6a6666b",
    "crc32 Koopman      thirtytwo    -> d1f6782b",
    "crc32 Koopman      thirtythree  -> a409c422",
    "crc32 Koopman      long         -> f52448f5",
    "crc32 Koopman      binary       -> 35986a91",
    "crc32 Koopman      high-bytes   -> 5787e548",
    "crc32 Koopman      update-seeded -> 1a7ff1e9",
    "crc32 custom-1     empty        -> 00000000",
    "crc32 custom-1     zero-byte    -> ff000000",
    "crc32 custom-1     one          -> ff000001",
    "crc32 custom-1     abc          -> ffffff00",
    "crc32 custom-1     check        -> fffffffe",
    "crc32 custom-1     eight        -> fffffffe",
    "crc32 custom-1     fifteen      -> ffffffff",
    "crc32 custom-1     sixteen      -> fffffffe",
    "crc32 custom-1     seventeen    -> fffffffe",
    "crc32 custom-1     thirtyone    -> ffffffff",
    "crc32 custom-1     thirtytwo    -> ffffffff",
    "crc32 custom-1     thirtythree  -> ffffffff",
    "crc32 custom-1     long         -> ffffffff",
    "crc32 custom-1     binary       -> ffffffff",
    "crc32 custom-1     high-bytes   -> ffffffff",
    "crc32 custom-1     update-seeded -> ffffffde",
    "crc32 custom-ffffffff empty        -> 00000000",
    "crc32 custom-ffffffff zero-byte    -> feffffff",
    "crc32 custom-ffffffff one          -> 3cffffff",
    "crc32 custom-ffffffff abc          -> 393b3cff",
    "crc32 custom-ffffffff check        -> 2aa0a2a4",
    "crc32 custom-ffffffff eight        -> 4143454c",
    "crc32 custom-ffffffff fifteen      -> 819fb3a5",
    "crc32 custom-ffffffff sixteen      -> ab819fb3",
    "crc32 custom-ffffffff seventeen    -> 85ab819f",
    "crc32 custom-ffffffff thirtyone    -> ffff0787",
    "crc32 custom-ffffffff thirtytwo    -> ffffff07",
    "crc32 custom-ffffffff thirtythree  -> 00000000",
    "crc32 custom-ffffffff long         -> 24c2b000",
    "crc32 custom-ffffffff binary       -> fbfffa04",
    "crc32 custom-ffffffff high-bytes   -> ffff8000",
    "crc32 custom-ffffffff update-seeded -> 9db91dde",
    "ieee empty        -> 00000000 stream=true bytewise=true size=4 blocksize=1",
    "ieee zero-byte    -> d202ef8d stream=true bytewise=true size=4 blocksize=1",
    "ieee one          -> e8b7be43 stream=true bytewise=true size=4 blocksize=1",
    "ieee abc          -> 352441c2 stream=true bytewise=true size=4 blocksize=1",
    "ieee check        -> cbf43926 stream=true bytewise=true size=4 blocksize=1",
    "ieee eight        -> aeef2a50 stream=true bytewise=true size=4 blocksize=1",
    "ieee fifteen      -> 519167df stream=true bytewise=true size=4 blocksize=1",
    "ieee sixteen      -> 943ac093 stream=true bytewise=true size=4 blocksize=1",
    "ieee seventeen    -> 9c925619 stream=true bytewise=true size=4 blocksize=1",
    "ieee thirtyone    -> c157f85e stream=true bytewise=true size=4 blocksize=1",
    "ieee thirtytwo    -> 00ce3d88 stream=true bytewise=true size=4 blocksize=1",
    "ieee thirtythree  -> 6fbfd3ac stream=true bytewise=true size=4 blocksize=1",
    "ieee long         -> 58819aef stream=true bytewise=true size=4 blocksize=1",
    "ieee binary       -> 3c8a83a5 stream=true bytewise=true size=4 blocksize=1",
    "ieee high-bytes   -> 0f6187ba stream=true bytewise=true size=4 blocksize=1",
    "sum-append prefix=aabb352441c2",
    "after-reset=00000000",
    "adler32 empty        -> 00000001 stream=true size=4",
    "adler32 zero-byte    -> 00010001 stream=true size=4",
    "adler32 one          -> 00620062 stream=true size=4",
    "adler32 abc          -> 024d0127 stream=true size=4",
    "adler32 check        -> 091e01de stream=true size=4",
    "adler32 eight        -> 0e000325 stream=true size=4",
    "adler32 fifteen      -> 2fb70619 stream=true size=4",
    "adler32 sixteen      -> 36400689 stream=true size=4",
    "adler32 seventeen    -> 3d3a06fa stream=true size=4",
    "adler32 thirtyone    -> e89f0e89 stream=true size=4",
    "adler32 thirtytwo    -> f7a00f01 stream=true size=4",
    "adler32 thirtythree  -> 07280f79 stream=true size=4",
    "adler32 long         -> 09cb7102 stream=true size=4",
    "adler32 binary       -> 060502fe stream=true size=4",
    "adler32 high-bytes   -> 18983fc1 stream=true size=4",
    "fnv empty        -> 32=811c9dc5 32a=811c9dc5 64=cbf29ce484222325 64a=cbf29ce484222325",
    "fnv zero-byte    -> 32=050c5d1f 32a=050c5d1f 64=af63bd4c8601b7df 64a=af63bd4c8601b7df",
    "fnv one          -> 32=050c5d7e 32a=e40c292c 64=af63bd4c8601b7be 64a=af63dc4c8601ec8c",
    "fnv abc          -> 32=439c2f4b 32a=1a47e90b 64=d8dcca186bafadcb 64a=e71fa2190541574b",
    "fnv check        -> 32=24148816 32a=bb86b11c 64=a72ffc362bf916d6 64a=06d5573923c6cdfc",
    "fnv eight        -> 32=e2a37115 32a=76daaa8d 64=1538b46aacff1cf5 64a=25da8c1836a8d66d",
    "fnv fifteen      -> 32=9e121957 32a=3c25d327 64=7c163a2938836297 64a=0bcd021dac7199a7",
    "fnv sixteen      -> 32=2d7de385 32a=068bb1f5 64=5d276b0b074086e5 64a=7ef46f6c05086855",
    "fnv seventeen    -> 32=222d2a2e 32a=d1e872cc 64=8a81c8bd52a5376e 64a=c1c1788c8d48f52c",
    "fnv thirtyone    -> 32=690550ef 32a=5c83d1bf 64=7081b6826861ce2f 64a=1bb98f0fae83573f",
    "fnv thirtytwo    -> 32=425e6845 32a=6a833c45 64=8e374e975e3159a5 64a=9fa55ea5892d4da5",
    "fnv thirtythree  -> 32=bf9e24e7 32a=e997d407 64=d95430350ddb5327 64a=734db04817fb4e87",
    "fnv long         -> 32=0d20896f 32a=eb899293 64=e565db62d1fcb5ef 64a=8f3567b42ebda913",
    "fnv binary       -> 32=7f833446 32a=605157d4 64=4b525af1defc3226 64a=62d5a5c24e275794",
    "fnv high-bytes   -> 32=43eaf005 32a=bbc5c685 64=f1fbfc673341b365 64a=84cc4da0e20ecde5",
    "fnv128 abc -> a68bb2a4348b5822836dbc78c6aee73b / a68d622cec8b5822836dbc7977af7f3b size=16",
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
    let x31 = strings::Repeat(s("x"), 31);
    let x32 = strings::Repeat(s("x"), 32);
    let x33 = strings::Repeat(s("x"), 33);
    let long = strings::Repeat(s("The quick brown fox. "), 50);
    let ff64 = strings::Repeat(string::from_bytes(b"\xff"), 64);
    let inputs: [(&str, string); 15] = [
        ("empty", string::new()),
        ("zero-byte", string::from_bytes(b"\x00")),
        ("one", s("a")),
        ("abc", s("abc")),
        ("check", s("123456789")),
        ("eight", s("abcdefgh")),
        ("fifteen", s("abcdefghijklmno")),
        ("sixteen", s("abcdefghijklmnop")),
        ("seventeen", s("abcdefghijklmnopq")),
        ("thirtyone", x31),
        ("thirtytwo", x32),
        ("thirtythree", x33),
        ("long", long),
        ("binary", string::from_bytes(b"\x00\x01\x02\xfd\xfe\xff")),
        ("high-bytes", ff64),
    ];
    let tables: [(&str, uint32); 5] = [
        ("IEEE", crc32::IEEE),
        ("Castagnoli", crc32::Castagnoli),
        ("Koopman", crc32::Koopman),
        ("custom-1", 0x00000001),
        ("custom-ffffffff", 0xffffffff),
    ];
    for (tn, poly) in tables.iter() {
        let tbl = crc32::MakeTable(*poly);
        for (name, data) in inputs.iter() {
            let sum = crc32::Checksum(sb(data), &tbl);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("crc32 %-12s %-12s -> %08x", s(tn), s(name), sum),
            );
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "crc32 %-12s update-seeded -> %08x",
                s(tn),
                crc32::Update(0xdeadbeef, &tbl, sb(&s("abc")))
            ),
        );
    }
    for (name, data) in inputs.iter() {
        let one = crc32::ChecksumIEEE(sb(data));
        let mut h = crc32::NewIEEE();
        let _ = h.Write(sb(data));
        let streamed = h.Sum32();
        let mut h2 = crc32::NewIEEE();
        for b in data.as_bytes() {
            let _ = h2.Write(bs(alloc::vec![*b]));
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "ieee %-12s -> %08x stream=%v bytewise=%v size=%d blocksize=%d",
                s(name),
                one,
                streamed == one,
                h2.Sum32() == one,
                h.Size(),
                h.BlockSize()
            ),
        );
    }
    {
        let mut h = crc32::NewIEEE();
        let _ = h.Write(sb(&s("abc")));
        let out = h.Sum(bs(alloc::vec![0xaa, 0xbb]));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("sum-append prefix=%s", hex::EncodeToString(&out.to_vec())),
        );
        h.Reset();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("after-reset=%08x", h.Sum32()),
        );
    }
    for (name, data) in inputs.iter() {
        let one = adler32::Checksum(sb(data));
        let mut h = adler32::New();
        let _ = h.Write(sb(data));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "adler32 %-12s -> %08x stream=%v size=%d",
                s(name),
                one,
                h.Sum32() == one,
                h.Size()
            ),
        );
    }
    for (name, data) in inputs.iter() {
        let mut h32 = fnv::New32();
        let mut h32a = fnv::New32a();
        let mut h64 = fnv::New64();
        let mut h64a = fnv::New64a();
        let _ = h32.Write(sb(data));
        let _ = h32a.Write(sb(data));
        let _ = h64.Write(sb(data));
        let _ = h64a.Write(sb(data));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "fnv %-12s -> 32=%08x 32a=%08x 64=%016x 64a=%016x",
                s(name),
                h32.Sum32(),
                h32a.Sum32(),
                h64.Sum64(),
                h64a.Sum64()
            ),
        );
    }
    {
        let mut h = fnv::New128();
        let mut ha = fnv::New128a();
        let _ = h.Write(sb(&s("abc")));
        let _ = ha.Write(sb(&s("abc")));
        let a = h.Sum(bs(Vec::new()));
        let b = ha.Sum(bs(Vec::new()));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "fnv128 abc -> %s / %s size=%d",
                hex::EncodeToString(&a.to_vec()),
                hex::EncodeToString(&b.to_vec()),
                h.Size()
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
