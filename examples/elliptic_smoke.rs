// elliptic_smoke — crypto/elliptic, the legacy big.Int Curve API over the
// nistec point arithmetic.
//
// Two distinct code paths live here and both are checked:
//
//   * the four curves returned by P224/P256/P384/P521, which dispatch every
//     operation to the constant-time nistec implementation; and
//   * CurveParams' own generic Jacobian arithmetic, reached only when
//     matchesSpecificCurve misses. The last block builds a CurveParams that
//     is P-224 in every respect except its Name, which is exactly what makes
//     the generic addJacobian/doubleJacobian/ScalarMult run — and then
//     requires it to agree with the constant-time answer.
//
// Every expected value is what Go prints for the same input, via
// scripts/goref.sh (AGENTS.md §10). Nothing was transcribed.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::crypto::elliptic::{self, Curve, CurveParams};
use goish::encoding::hex;
use goish::fmt;
use goish::goslice::slice;
use goish::math::big::Int;
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

/// `x.Text(16),y.Text(16)` — the pair form the Go reference printed.
fn xy(x: &Int, y: &Int) -> goish::string {
    let mut s = x.Text(16);
    s = s + goish::string::from(",");
    s = s + y.Text(16);
    return s;
}

fn nm(curve: &str, case: &str) -> alloc::string::String {
    let mut s = alloc::string::String::with_capacity(curve.len() + case.len() + 1);
    s.push_str(curve);
    s.push(' ');
    s.push_str(case);
    return s;
}

/// The same deterministic scalar the Go reference used.
fn scal(n: usize) -> slice<byte> {
    let mut b: Vec<byte> = Vec::with_capacity(n);
    let mut i: usize = 0;
    while i < n {
        b.push(((i * 13 + 3) & 0xff) as byte);
        i += 1;
    }
    b[0] &= 0x0f;
    return slice::__from_vec(b);
}

fn run(name: &str, c: &'static (dyn Curve + Send + Sync), n: usize, want: &[&str; 14]) {
    let p = c.Params();
    check(&nm(name, "Name"), p.Name.clone(), want[0]);
    check(&nm(name, "BitSize"), fmt::Sprintf!("%d", p.BitSize), want[1]);

    let m = elliptic::Marshal(c, &p.Gx, &p.Gy);
    check(&nm(name, "Marshal"), hx(&m), want[2]);
    let mc = elliptic::MarshalCompressed(c, &p.Gx, &p.Gy);
    check(&nm(name, "MarshalCompressed"), hx(&mc), want[3]);

    let (ux, uy, ok) = elliptic::Unmarshal(c, &m);
    check(&nm(name, "Unmarshal ok"), fmt::Sprintf!("%v", ok), "true");
    check(&nm(name, "Unmarshal"), xy(&ux, &uy), want[4]);
    let (cx, cy, ok) = elliptic::UnmarshalCompressed(c, &mc);
    check(&nm(name, "UnmarshalCompressed ok"), fmt::Sprintf!("%v", ok), "true");
    check(&nm(name, "UnmarshalCompressed"), xy(&cx, &cy), want[5]);

    let (dx, dy) = c.Double(&p.Gx, &p.Gy);
    check(&nm(name, "Double"), xy(&dx, &dy), want[6]);
    let (ax, ay) = c.Add(&dx, &dy, &p.Gx, &p.Gy);
    check(&nm(name, "Add"), xy(&ax, &ay), want[7]);

    let k = scal(n);
    let (bx, by) = c.ScalarBaseMult(&k);
    check(&nm(name, "ScalarBaseMult"), xy(&bx, &by), want[8]);
    let (sx, sy) = c.ScalarMult(&p.Gx, &p.Gy, &k);
    check(&nm(name, "ScalarMult"), xy(&sx, &sy), want[9]);

    check(&nm(name, "IsOnCurve"), fmt::Sprintf!("%v", c.IsOnCurve(&bx, &by)), want[10]);
    let mut one = Int::default();
    one.SetInt64(1);
    check(&nm(name, "IsOnCurve(1,1)"), fmt::Sprintf!("%v", c.IsOnCurve(&one, &one)), want[11]);
    let z = Int::default();
    check(&nm(name, "IsOnCurve(0,0)"), fmt::Sprintf!("%v", c.IsOnCurve(&z, &z)), want[12]);

    let mut bad: Vec<byte> = {
        let r: &[byte] = &m;
        r.to_vec()
    };
    let last = bad.len() - 1;
    bad[last] ^= 1;
    let (_, _, ok) = elliptic::Unmarshal(c, &slice::__from_vec(bad));
    check(&nm(name, "corrupted point rejected"), fmt::Sprintf!("%v", !ok), want[13]);
}

#[goish::main]
fn main() {
    run("p224", elliptic::P224(), 28, &[P224_NAME, P224_BITS, P224_MARSH, P224_MCOMP, P224_UNM, P224_UNCMP, P224_DBL, P224_ADD, P224_BASE, P224_MULT, P224_ONC, P224_OFF, P224_ZERO, P224_BADUN]);
    run("p256", elliptic::P256(), 32, &[P256_NAME, P256_BITS, P256_MARSH, P256_MCOMP, P256_UNM, P256_UNCMP, P256_DBL, P256_ADD, P256_BASE, P256_MULT, P256_ONC, P256_OFF, P256_ZERO, P256_BADUN]);
    run("p384", elliptic::P384(), 48, &[P384_NAME, P384_BITS, P384_MARSH, P384_MCOMP, P384_UNM, P384_UNCMP, P384_DBL, P384_ADD, P384_BASE, P384_MULT, P384_ONC, P384_OFF, P384_ZERO, P384_BADUN]);
    run("p521", elliptic::P521(), 66, &[P521_NAME, P521_BITS, P521_MARSH, P521_MCOMP, P521_UNM, P521_UNCMP, P521_DBL, P521_ADD, P521_BASE, P521_MULT, P521_ONC, P521_OFF, P521_ZERO, P521_BADUN]);

    // The generic CurveParams path: P-224 in every respect except its
    // Name, so matchesSpecificCurve misses and the Jacobian arithmetic in
    // params.rs runs instead of nistec.
    {
        let base = elliptic::P224().Params();
        let mut gen = CurveParams::default();
        gen.Name = goish::string::from("generic-P-224");
        gen.BitSize = 224;
        gen.P = base.P.clone();
        gen.N = base.N.clone();
        gen.B = base.B.clone();
        gen.Gx = base.Gx.clone();
        gen.Gy = base.Gy.clone();

        check("gen IsOnCurve", fmt::Sprintf!("%v", gen.IsOnCurve(&gen.Gx, &gen.Gy)), GEN_ONC);
        let (dx, dy) = gen.Double(&gen.Gx, &gen.Gy);
        check("gen Double (generic Jacobian)", xy(&dx, &dy), GEN_DBL);
        let (ax, ay) = gen.Add(&dx, &dy, &gen.Gx, &gen.Gy);
        check("gen Add (generic Jacobian)", xy(&ax, &ay), GEN_ADD);
        let (sx, sy) = gen.ScalarBaseMult(&scal(28));
        check("gen ScalarBaseMult (generic Jacobian)", xy(&sx, &sy), GEN_BASE);

        // And it must land on the same point as the constant-time code.
        let (rx, ry) = elliptic::P224().ScalarBaseMult(&scal(28));
        check(
            "gen generic path agrees with nistec",
            fmt::Sprintf!("%v", sx.Cmp(&rx) == 0 && sy.Cmp(&ry) == 0),
            GEN_AGREE,
        );
    }

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("elliptic_smoke OK\n");
}

const P224_NAME: &str = "P-224";
const P224_BITS: &str = "224";
const P224_MARSH: &str = "04b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21bd3763\
                      88b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34";
const P224_MCOMP: &str = "02b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21";
const P224_UNM: &str = "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21,bd37638\
                      8b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34";
const P224_UNCMP: &str = "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21,bd37638\
                      8b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34";
const P224_DBL: &str = "706a46dc76dcb76798e60e6d89474788d16dc18032d268fd1a704fa6,1c2b76a\
                      7bc25e7702a704fa986892849fca629487acf3709d2e4e8bb";
const P224_ADD: &str = "df1b1d66a551d0d31eff822558b9d2cc75c2180279fe0d08fd896d04,a3f7f03\
                      cadd0be444c0aa56830130ddf77d317344e1af3591981a925";
const P224_BASE: &str = "7306521918ee0767afcbda4e60ddbd0d4bd2f6b94a8c16be2e90d032,68eba4e\
                      2449a9216ce9a5c78afc53b3cde92af8629afd22f8f096b8d";
const P224_MULT: &str = "7306521918ee0767afcbda4e60ddbd0d4bd2f6b94a8c16be2e90d032,68eba4e\
                      2449a9216ce9a5c78afc53b3cde92af8629afd22f8f096b8d";
const P224_ONC: &str = "true";
const P224_OFF: &str = "false";
const P224_ZERO: &str = "false";
const P224_BADUN: &str = "true";
const P256_NAME: &str = "P-256";
const P256_BITS: &str = "256";
const P256_MARSH: &str = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2\
                      964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51\
                      f5";
const P256_MCOMP: &str = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2\
                      96";
const P256_UNM: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
                      ,4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f\
                      5";
const P256_UNCMP: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
                      ,4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f\
                      5";
const P256_DBL: &str = "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978\
                      ,7775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1";
const P256_ADD: &str = "5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c\
                      ,8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d503\
                      2";
const P256_BASE: &str = "9aa0c8cf2c7d1a3aadf3cc1a9ae6ddb166d942d6725546f18a94a312ba297d7e\
                      ,603f5365ac752648d1e8702cbd60ac61171c171b9d9f9686941227ff77083a9";
const P256_MULT: &str = "9aa0c8cf2c7d1a3aadf3cc1a9ae6ddb166d942d6725546f18a94a312ba297d7e\
                      ,603f5365ac752648d1e8702cbd60ac61171c171b9d9f9686941227ff77083a9";
const P256_ONC: &str = "true";
const P256_OFF: &str = "false";
const P256_ZERO: &str = "false";
const P256_BADUN: &str = "true";
const P384_NAME: &str = "P-384";
const P384_BITS: &str = "384";
const P384_MARSH: &str = "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a\
                      385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc\
                      29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e\
                      5f";
const P384_MCOMP: &str = "03aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a\
                      385502f25dbf55296c3a545e3872760ab7";
const P384_UNM: &str = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38\
                      5502f25dbf55296c3a545e3872760ab7,3617de4a96262c6f5d9e98bf9292dc2\
                      9f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5\
                      f";
const P384_UNCMP: &str = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38\
                      5502f25dbf55296c3a545e3872760ab7,3617de4a96262c6f5d9e98bf9292dc2\
                      9f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5\
                      f";
const P384_DBL: &str = "8d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4\
                      fe0e86ebe0e64f85b96a9c75295df61,8e80f1fa5b1b3cedb7bfe8dffd6dba74\
                      b275d875bc6cc43e904e505f256ab4255ffd43e94d39e22d61501e700a940e80";
const P384_ADD: &str = "77a41d4606ffa1464793c7e5fdc7d98cb9d3910202dcd06bea4f240d3566da6b\
                      408bbae5026580d02d7e5c70500c831,c995f7ca0b0c42837d0bbe9602a9fc99\
                      8520b41c85115aa5f7684c0edc111eacc24abd6be4b5d298b65f28600a2f1df1";
const P384_BASE: &str = "52c6243481b08a8ac29360ba811ddc312225e67ecd2056971aa615eccafd053e\
                      426c11371027d3f05915e1ef9e5e85a5,eeeb49c7163a683843758a6c0c42f6c\
                      d07f2ecb785ddaf555248cde8b14067c8604acb118475ea5cf6be0720b0d3e1b\
                      3";
const P384_MULT: &str = "52c6243481b08a8ac29360ba811ddc312225e67ecd2056971aa615eccafd053e\
                      426c11371027d3f05915e1ef9e5e85a5,eeeb49c7163a683843758a6c0c42f6c\
                      d07f2ecb785ddaf555248cde8b14067c8604acb118475ea5cf6be0720b0d3e1b\
                      3";
const P384_ONC: &str = "true";
const P384_OFF: &str = "false";
const P384_ZERO: &str = "false";
const P384_BADUN: &str = "true";
const P521_NAME: &str = "P-521";
const P521_BITS: &str = "521";
const P521_MARSH: &str = "0400c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b\
                      4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2\
                      e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd\
                      17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94\
                      769fd16650";
const P521_MCOMP: &str = "0200c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b\
                      4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2\
                      e5bd66";
const P521_UNM: &str = "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3d\
                      baa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd\
                      66,11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd1727\
                      3e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769f\
                      d16650";
const P521_UNCMP: &str = "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3d\
                      baa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd\
                      66,11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd1727\
                      3e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769f\
                      d16650";
const P521_DBL: &str = "433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769be\
                      97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d78\
                      3d,f4bb8cc7f86db26700a7f3eceeeed3f0b5c6b5107c4da97740ab21a29906c\
                      42dbbb3e377de9f251f6b93937fa99a3248f4eafcbe95edc0f4f71be356d661f\
                      41b02";
const P521_ADD: &str = "1a73d352443de29195dd91d6a64b5959479b52a6e5b123d9ab9e5ad7a112d7a8\
                      dd1ad3f164a3a4832051da6bd16b59fe21baeb490862c32ea05a5919d2ede37a\
                      d7d,13e9b03b97dfa62ddd9979f86c6cab814f2f1557fa82a9d0317d2f8ab1fa\
                      355ceec2e2dd4cf8dc575b02d5aced1dec3c70cf105c9bc93a590425f588ca1e\
                      e86c0e5";
const P521_BASE: &str = "aacc14595e10dd03a43cc8f142f3b2afbbcab8f6d1103a2782719551c189f7e5\
                      8a300774b92920ff6ff4f94e6823ee7b0ab11e50e7c0e299d365783cea9aa724\
                      16,cfa9b0448687e452e3f0ceb0c5ff0136b3a8bb7c8e59c7a3134f5f4019c2f\
                      728f553ccc7edff0d746001a7264f2d06eed6e45a0b2fe8ac3cc04f067dbda5e\
                      5e604";
const P521_MULT: &str = "aacc14595e10dd03a43cc8f142f3b2afbbcab8f6d1103a2782719551c189f7e5\
                      8a300774b92920ff6ff4f94e6823ee7b0ab11e50e7c0e299d365783cea9aa724\
                      16,cfa9b0448687e452e3f0ceb0c5ff0136b3a8bb7c8e59c7a3134f5f4019c2f\
                      728f553ccc7edff0d746001a7264f2d06eed6e45a0b2fe8ac3cc04f067dbda5e\
                      5e604";
const P521_ONC: &str = "true";
const P521_OFF: &str = "false";
const P521_ZERO: &str = "false";
const P521_BADUN: &str = "true";
const GEN_ONC: &str = "true";
const GEN_DBL: &str = "706a46dc76dcb76798e60e6d89474788d16dc18032d268fd1a704fa6,1c2b76a\
                      7bc25e7702a704fa986892849fca629487acf3709d2e4e8bb";
const GEN_ADD: &str = "df1b1d66a551d0d31eff822558b9d2cc75c2180279fe0d08fd896d04,a3f7f03\
                      cadd0be444c0aa56830130ddf77d317344e1af3591981a925";
const GEN_BASE: &str = "7306521918ee0767afcbda4e60ddbd0d4bd2f6b94a8c16be2e90d032,68eba4e\
                      2449a9216ce9a5c78afc53b3cde92af8629afd22f8f096b8d";
const GEN_AGREE: &str = "true";
