// fips140_nistec_smoke — the P-224, P-384 and P-521 curve implementations
// of crypto/internal/fips140/nistec.
//
// p384.rs and p521.rs are generated from p224.rs by scripts/nistec_gen.py,
// mirroring Go, where generate.go produces all three from one template.
// That makes a per-curve check mandatory rather than redundant: the three
// files share their code and differ only in the generator, the curve B,
// the element length, and the square-root chain — which is exactly the
// set of things a substitution bug would corrupt silently.
//
// Every expected value below is what Go prints for the same input, via
// scripts/goref.sh (AGENTS.md §10). No vector here was transcribed.
//
// What each check is for:
//
//   * G / Gcompressed / Gx pin the generator constants and the three
//     encodings of SEC 1 §2.3.3 and §2.3.5.
//   * sG computed by ScalarBaseMult and by ScalarMult must agree: the
//     first walks the precomputed generatorTable, the second builds a
//     table at runtime, so a wrong table shows up as a mismatch.
//   * The round trips go out through BytesCompressed and back in through
//     SetBytes, which is the only path that runs pNNNSqrt — the part of
//     each curve file that is genuinely different code per curve.
//   * 2G and 3G exercise Double and Add against Go directly, rather than
//     only through a scalar multiplication that could hide a sign error.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::crypto::internal::fips140::nistec;
use goish::encoding::hex;
use goish::fmt;
use goish::goslice::slice;
use goish::types::byte;

static mut FAILED: bool = false;

fn check(name: &str, got: goish::string, want: &str) {
    if got == goish::string::from(want) {
        fmt::Printf!("PASS: %s\n", goish::string::from(name));
    } else {
        fmt::Printf!(
            "FAIL: %s\n  got  %s\n  want %s\n",
            goish::string::from(name),
            got,
            goish::string::from(want)
        );
        unsafe { FAILED = true };
    }
}

fn hx(s: &slice<byte>) -> goish::string {
    let r: &[byte] = s;
    return hex::EncodeToString(r);
}

/// The same deterministic scalar the Go reference used: s[i] = i*7+3, with
/// the top byte cleared so the value stays below every group order.
fn scalarOf(n: usize) -> slice<byte> {
    let mut b: Vec<byte> = Vec::with_capacity(n);
    let mut i: usize = 0;
    while i < n {
        b.push(((i * 7 + 3) & 0xff) as byte);
        i += 1;
    }
    b[0] = 0x0f;
    return slice::__from_vec(b);
}

#[goish::main]
fn main() {

    // ---- P-224
    {
        let mut g = nistec::NewP224Point();
        g.SetGenerator();
        check("p224 G", hx(&g.Bytes()), P224_G);
        check("p224 Gcompressed", hx(&g.BytesCompressed()), P224_GC);
        let (gx, err) = g.BytesX();
        check("p224 BytesX err", fmt::Sprintf!("%v", err != goish::nil), "false");
        check("p224 Gx", hx(&gx), P224_GX);

        let s = scalarOf(28);
        let mut p = nistec::NewP224Point();
        let err = p.ScalarBaseMult(&s);
        check("p224 ScalarBaseMult err", fmt::Sprintf!("%v", err != goish::nil), "false");
        check("p224 sG (base)", hx(&p.Bytes()), P224_SGB);

        let mut q = nistec::NewP224Point();
        let err = q.ScalarMult(g, &s);
        check("p224 ScalarMult err", fmt::Sprintf!("%v", err != goish::nil), "false");
        check("p224 sG (mult)", hx(&q.Bytes()), P224_SGM);

        let c = p.BytesCompressed();
        let mut r = nistec::NewP224Point();
        let err = r.SetBytes(&c);
        check("p224 SetBytes(compressed) err", fmt::Sprintf!("%v", err != goish::nil), "false");
        check("p224 round trip (compressed)", hx(&r.Bytes()), P224_RTC);

        let u8s = p.Bytes();
        let mut u = nistec::NewP224Point();
        let err = u.SetBytes(&u8s);
        check("p224 SetBytes(uncompressed) err", fmt::Sprintf!("%v", err != goish::nil), "false");
        check("p224 round trip (uncompressed)", hx(&u.Bytes()), P224_RTU);

        let inf = nistec::NewP224Point();
        check("p224 infinity", hx(&inf.Bytes()), P224_INF);

        let mut d = nistec::NewP224Point();
        d.Double(g);
        check("p224 2G", hx(&d.Bytes()), P224_G2);
        let mut a = nistec::NewP224Point();
        a.Add(d, g);
        check("p224 3G", hx(&a.Bytes()), P224_G3);

        // A truncated scalar must be rejected by ScalarBaseMult, which is
        // the only length check in the package.
        let mut bad = nistec::NewP224Point();
        let err = bad.ScalarBaseMult(&scalarOf(28 - 1));
        check("p224 short scalar rejected", fmt::Sprintf!("%v", err.Error()), "invalid scalar length");

        // A point encoding of the right length that is not on the curve.
        let mut off = Vec::<byte>::with_capacity(1 + 2 * 28);
        off.push(4);
        let mut i: usize = 0;
        while i < 2 * 28 {
            off.push(1);
            i += 1;
        }
        let mut nope = nistec::NewP224Point();
        let err = nope.SetBytes(&slice::__from_vec(off));
        check("p224 off-curve rejected", fmt::Sprintf!("%v", err.Error()), "P224 point not on curve");
    }

    // ---- P-384
    {
        let mut g = nistec::NewP384Point();
        g.SetGenerator();
        check("p384 G", hx(&g.Bytes()), P384_G);
        check("p384 Gcompressed", hx(&g.BytesCompressed()), P384_GC);
        let (gx, err) = g.BytesX();
        check("p384 BytesX err", fmt::Sprintf!("%v", err != goish::nil), "false");
        check("p384 Gx", hx(&gx), P384_GX);

        let s = scalarOf(48);
        let mut p = nistec::NewP384Point();
        let err = p.ScalarBaseMult(&s);
        check("p384 ScalarBaseMult err", fmt::Sprintf!("%v", err != goish::nil), "false");
        check("p384 sG (base)", hx(&p.Bytes()), P384_SGB);

        let mut q = nistec::NewP384Point();
        let err = q.ScalarMult(g, &s);
        check("p384 ScalarMult err", fmt::Sprintf!("%v", err != goish::nil), "false");
        check("p384 sG (mult)", hx(&q.Bytes()), P384_SGM);

        let c = p.BytesCompressed();
        let mut r = nistec::NewP384Point();
        let err = r.SetBytes(&c);
        check("p384 SetBytes(compressed) err", fmt::Sprintf!("%v", err != goish::nil), "false");
        check("p384 round trip (compressed)", hx(&r.Bytes()), P384_RTC);

        let u8s = p.Bytes();
        let mut u = nistec::NewP384Point();
        let err = u.SetBytes(&u8s);
        check("p384 SetBytes(uncompressed) err", fmt::Sprintf!("%v", err != goish::nil), "false");
        check("p384 round trip (uncompressed)", hx(&u.Bytes()), P384_RTU);

        let inf = nistec::NewP384Point();
        check("p384 infinity", hx(&inf.Bytes()), P384_INF);

        let mut d = nistec::NewP384Point();
        d.Double(g);
        check("p384 2G", hx(&d.Bytes()), P384_G2);
        let mut a = nistec::NewP384Point();
        a.Add(d, g);
        check("p384 3G", hx(&a.Bytes()), P384_G3);

        // A truncated scalar must be rejected by ScalarBaseMult, which is
        // the only length check in the package.
        let mut bad = nistec::NewP384Point();
        let err = bad.ScalarBaseMult(&scalarOf(48 - 1));
        check("p384 short scalar rejected", fmt::Sprintf!("%v", err.Error()), "invalid scalar length");

        // A point encoding of the right length that is not on the curve.
        let mut off = Vec::<byte>::with_capacity(1 + 2 * 48);
        off.push(4);
        let mut i: usize = 0;
        while i < 2 * 48 {
            off.push(1);
            i += 1;
        }
        let mut nope = nistec::NewP384Point();
        let err = nope.SetBytes(&slice::__from_vec(off));
        check("p384 off-curve rejected", fmt::Sprintf!("%v", err.Error()), "P384 point not on curve");
    }

    // ---- P-521
    {
        let mut g = nistec::NewP521Point();
        g.SetGenerator();
        check("p521 G", hx(&g.Bytes()), P521_G);
        check("p521 Gcompressed", hx(&g.BytesCompressed()), P521_GC);
        let (gx, err) = g.BytesX();
        check("p521 BytesX err", fmt::Sprintf!("%v", err != goish::nil), "false");
        check("p521 Gx", hx(&gx), P521_GX);

        let s = scalarOf(66);
        let mut p = nistec::NewP521Point();
        let err = p.ScalarBaseMult(&s);
        check("p521 ScalarBaseMult err", fmt::Sprintf!("%v", err != goish::nil), "false");
        check("p521 sG (base)", hx(&p.Bytes()), P521_SGB);

        let mut q = nistec::NewP521Point();
        let err = q.ScalarMult(g, &s);
        check("p521 ScalarMult err", fmt::Sprintf!("%v", err != goish::nil), "false");
        check("p521 sG (mult)", hx(&q.Bytes()), P521_SGM);

        let c = p.BytesCompressed();
        let mut r = nistec::NewP521Point();
        let err = r.SetBytes(&c);
        check("p521 SetBytes(compressed) err", fmt::Sprintf!("%v", err != goish::nil), "false");
        check("p521 round trip (compressed)", hx(&r.Bytes()), P521_RTC);

        let u8s = p.Bytes();
        let mut u = nistec::NewP521Point();
        let err = u.SetBytes(&u8s);
        check("p521 SetBytes(uncompressed) err", fmt::Sprintf!("%v", err != goish::nil), "false");
        check("p521 round trip (uncompressed)", hx(&u.Bytes()), P521_RTU);

        let inf = nistec::NewP521Point();
        check("p521 infinity", hx(&inf.Bytes()), P521_INF);

        let mut d = nistec::NewP521Point();
        d.Double(g);
        check("p521 2G", hx(&d.Bytes()), P521_G2);
        let mut a = nistec::NewP521Point();
        a.Add(d, g);
        check("p521 3G", hx(&a.Bytes()), P521_G3);

        // A truncated scalar must be rejected by ScalarBaseMult, which is
        // the only length check in the package.
        let mut bad = nistec::NewP521Point();
        let err = bad.ScalarBaseMult(&scalarOf(66 - 1));
        check("p521 short scalar rejected", fmt::Sprintf!("%v", err.Error()), "invalid scalar length");

        // A point encoding of the right length that is not on the curve.
        let mut off = Vec::<byte>::with_capacity(1 + 2 * 66);
        off.push(4);
        let mut i: usize = 0;
        while i < 2 * 66 {
            off.push(1);
            i += 1;
        }
        let mut nope = nistec::NewP521Point();
        let err = nope.SetBytes(&slice::__from_vec(off));
        check("p521 off-curve rejected", fmt::Sprintf!("%v", err.Error()), "P521 point not on curve");
    }

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("fips140_nistec_smoke OK\n");
}

const P224_G: &str = "04b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21bd3763\
                      88b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34";
const P224_GC: &str = "02b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21";
const P224_GX: &str = "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21";
const P224_SGB: &str = "044471b949edf2bdc1ce809efd1829225e1e9f44c3cff03993fa467d256170f1\
                      10469a279113134bbaf80314de8d947c98ba3eb9fd940f6667";
const P224_SGM: &str = "044471b949edf2bdc1ce809efd1829225e1e9f44c3cff03993fa467d256170f1\
                      10469a279113134bbaf80314de8d947c98ba3eb9fd940f6667";
const P224_RTC: &str = "044471b949edf2bdc1ce809efd1829225e1e9f44c3cff03993fa467d256170f1\
                      10469a279113134bbaf80314de8d947c98ba3eb9fd940f6667";
const P224_RTU: &str = "044471b949edf2bdc1ce809efd1829225e1e9f44c3cff03993fa467d256170f1\
                      10469a279113134bbaf80314de8d947c98ba3eb9fd940f6667";
const P224_INF: &str = "00";
const P224_G2: &str = "04706a46dc76dcb76798e60e6d89474788d16dc18032d268fd1a704fa61c2b76\
                      a7bc25e7702a704fa986892849fca629487acf3709d2e4e8bb";
const P224_G3: &str = "04df1b1d66a551d0d31eff822558b9d2cc75c2180279fe0d08fd896d04a3f7f0\
                      3cadd0be444c0aa56830130ddf77d317344e1af3591981a925";
const P384_G: &str = "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a\
                      385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc\
                      29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e\
                      5f";
const P384_GC: &str = "03aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a\
                      385502f25dbf55296c3a545e3872760ab7";
const P384_GX: &str = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38\
                      5502f25dbf55296c3a545e3872760ab7";
const P384_SGB: &str = "0435bacb600e1fdf47cc26b69606db79e8a8acdf79c4e006be62071b0c0fcfb0\
                      aa96214385880f0cee3df703c5fa9a77a4a199bc6114cbc78d8daa0086fd5821\
                      468171baacb182f9c6b4c8c9ce22215a36aa53b608fbb42b00bf1e8d7236d1c2\
                      29";
const P384_SGM: &str = "0435bacb600e1fdf47cc26b69606db79e8a8acdf79c4e006be62071b0c0fcfb0\
                      aa96214385880f0cee3df703c5fa9a77a4a199bc6114cbc78d8daa0086fd5821\
                      468171baacb182f9c6b4c8c9ce22215a36aa53b608fbb42b00bf1e8d7236d1c2\
                      29";
const P384_RTC: &str = "0435bacb600e1fdf47cc26b69606db79e8a8acdf79c4e006be62071b0c0fcfb0\
                      aa96214385880f0cee3df703c5fa9a77a4a199bc6114cbc78d8daa0086fd5821\
                      468171baacb182f9c6b4c8c9ce22215a36aa53b608fbb42b00bf1e8d7236d1c2\
                      29";
const P384_RTU: &str = "0435bacb600e1fdf47cc26b69606db79e8a8acdf79c4e006be62071b0c0fcfb0\
                      aa96214385880f0cee3df703c5fa9a77a4a199bc6114cbc78d8daa0086fd5821\
                      468171baacb182f9c6b4c8c9ce22215a36aa53b608fbb42b00bf1e8d7236d1c2\
                      29";
const P384_INF: &str = "00";
const P384_G2: &str = "0408d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e\
                      9e4fe0e86ebe0e64f85b96a9c75295df618e80f1fa5b1b3cedb7bfe8dffd6dba\
                      74b275d875bc6cc43e904e505f256ab4255ffd43e94d39e22d61501e700a940e\
                      80";
const P384_G3: &str = "04077a41d4606ffa1464793c7e5fdc7d98cb9d3910202dcd06bea4f240d3566d\
                      a6b408bbae5026580d02d7e5c70500c831c995f7ca0b0c42837d0bbe9602a9fc\
                      998520b41c85115aa5f7684c0edc111eacc24abd6be4b5d298b65f28600a2f1d\
                      f1";
const P521_G: &str = "0400c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b\
                      4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2\
                      e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd\
                      17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94\
                      769fd16650";
const P521_GC: &str = "0200c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b\
                      4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2\
                      e5bd66";
const P521_GX: &str = "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d\
                      3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5\
                      bd66";
const P521_SGB: &str = "0400af42765c1c890d2ef67c08426fb426f9a2bf1920be6f0dfedb0bcba64d43\
                      da9af4b6f9531df4ea1fec429c227cb85efd021a1081addc5e3ed21a8c0930f1\
                      643e5f006f55a8bae0f38c6e3007a50ffb41940ecc1009ecbab65ad94d38a81e\
                      ff3bd78a11333ae42006f8d92f3bf69b3b92f971a169829052fb902cf559b688\
                      af211be438";
const P521_SGM: &str = "0400af42765c1c890d2ef67c08426fb426f9a2bf1920be6f0dfedb0bcba64d43\
                      da9af4b6f9531df4ea1fec429c227cb85efd021a1081addc5e3ed21a8c0930f1\
                      643e5f006f55a8bae0f38c6e3007a50ffb41940ecc1009ecbab65ad94d38a81e\
                      ff3bd78a11333ae42006f8d92f3bf69b3b92f971a169829052fb902cf559b688\
                      af211be438";
const P521_RTC: &str = "0400af42765c1c890d2ef67c08426fb426f9a2bf1920be6f0dfedb0bcba64d43\
                      da9af4b6f9531df4ea1fec429c227cb85efd021a1081addc5e3ed21a8c0930f1\
                      643e5f006f55a8bae0f38c6e3007a50ffb41940ecc1009ecbab65ad94d38a81e\
                      ff3bd78a11333ae42006f8d92f3bf69b3b92f971a169829052fb902cf559b688\
                      af211be438";
const P521_RTU: &str = "0400af42765c1c890d2ef67c08426fb426f9a2bf1920be6f0dfedb0bcba64d43\
                      da9af4b6f9531df4ea1fec429c227cb85efd021a1081addc5e3ed21a8c0930f1\
                      643e5f006f55a8bae0f38c6e3007a50ffb41940ecc1009ecbab65ad94d38a81e\
                      ff3bd78a11333ae42006f8d92f3bf69b3b92f971a169829052fb902cf559b688\
                      af211be438";
const P521_INF: &str = "00";
const P521_G2: &str = "0400433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d7\
                      69be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba\
                      6d783d00f4bb8cc7f86db26700a7f3eceeeed3f0b5c6b5107c4da97740ab21a2\
                      9906c42dbbb3e377de9f251f6b93937fa99a3248f4eafcbe95edc0f4f71be356\
                      d661f41b02";
const P521_G3: &str = "0401a73d352443de29195dd91d6a64b5959479b52a6e5b123d9ab9e5ad7a112d\
                      7a8dd1ad3f164a3a4832051da6bd16b59fe21baeb490862c32ea05a5919d2ede\
                      37ad7d013e9b03b97dfa62ddd9979f86c6cab814f2f1557fa82a9d0317d2f8ab\
                      1fa355ceec2e2dd4cf8dc575b02d5aced1dec3c70cf105c9bc93a590425f588c\
                      a1ee86c0e5";
