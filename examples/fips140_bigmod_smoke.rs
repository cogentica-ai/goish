// fips140_bigmod_smoke — constant-time modular arithmetic
// (crypto/internal/fips140/bigmod).
//
// This package was counted as 57/60 ported with ZERO anchors: name-level
// agreement with Go and nothing diffed against it. These values come from
// scripts/goref.sh (AGENTS.md §10) — the same operands through the same
// calls in Go — which is what turns "same names" into "same behaviour".
//
// The three moduli hit both sides of montgomeryMul's size dispatch: 2048
// bits takes the arm that calls addMulVVW2048, 1024 takes addMulVVW1024,
// 256 takes the generic path. a*(1/a) == 1 catches a Montgomery-domain
// slip, which is the failure mode a round-trip test would miss — and the
// 2048-bit operand has no inverse at all, so InverseVarTime reporting
// ok=false honestly is pinned too.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::crypto::internal::fips140::bigmod;
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

/// The same deterministic operands the Go reference built.
fn mk(n: usize, seed: u8) -> slice<byte> {
    let mut b: Vec<byte> = Vec::with_capacity(n);
    let mut i = 0;
    while i < n {
        b.push(((i as u8).wrapping_mul(7)).wrapping_add(seed));
        i += 1;
    }
    b[0] |= 0x80;
    b[n - 1] |= 1;
    return slice::__from_vec(b);
}

fn operand(n: usize, seed: u8) -> slice<byte> {
    let mut v = slice::__into_vec(mk(n, seed));
    v[0] &= 0x7f;
    return slice::__from_vec(v);
}

macro_rules! curve {
    ($bits:expr, $tag:expr, $a:expr, $add:expr, $sub:expr, $mul:expr,
     $exp:expr, $exps:expr, $invok:expr, $inv:expr, $sizebits:expr) => {{
        let n = $bits / 8;
        let (m, err) = bigmod::Modulus::NewModulus(mk(n, 3));
        check(
            concat!($tag, " NewModulus"),
            fmt::Sprintf!("%v", err == goish::nil),
            "true",
        );
        let bB = operand(n, 29);
        let (a, err) = bigmod::Nat::NewNat().SetBytes(operand(n, 11), &m);
        check(
            concat!($tag, " SetBytes"),
            fmt::Sprintf!("%v", err == goish::nil),
            "true",
        );
        let (b, _) = bigmod::Nat::NewNat().SetBytes(bB.clone(), &m);
        check(concat!($tag, " a"), hx(&a.Bytes(&m)), $a);

        let mut t = bigmod::Nat::NewNat();
        t.ExpandFor(&m);
        let mut acc = a.clone();
        check(concat!($tag, " a+b"), hx(&acc.Add(&b, &m).Bytes(&m)), $add);
        let mut acc = a.clone();
        check(concat!($tag, " a-b"), hx(&acc.Sub(&b, &m).Bytes(&m)), $sub);
        let mut acc = a.clone();
        check(concat!($tag, " a*b"), hx(&acc.Mul(&b, &m).Bytes(&m)), $mul);

        let mut e = bigmod::Nat::NewNat();
        check(
            concat!($tag, " a^b"),
            hx(&e.Exp(&a, bB, &m).Bytes(&m)),
            $exp,
        );
        let mut e = bigmod::Nat::NewNat();
        check(
            concat!($tag, " a^65537"),
            hx(&e.ExpShortVarTime(&a, 65537, &m).Bytes(&m)),
            $exps,
        );

        // InverseVarTime must report honestly when gcd(a, m) != 1 — the
        // 2048-bit operand here has no inverse, and returning garbage
        // with ok=true is exactly the bug this catches.
        let mut iv = bigmod::Nat::NewNat();
        let (inv, ok) = iv.InverseVarTime(&a, &m);
        check(
            concat!($tag, " InverseVarTime ok"),
            fmt::Sprintf!("%v", ok),
            $invok,
        );
        if ok {
            check(concat!($tag, " 1/a"), hx(&inv.Bytes(&m)), $inv);
            // The Montgomery-domain check: a * (1/a) must be exactly 1.
            let mut prod = a.clone();
            let got = hx(&prod.Mul(&inv, &m).Bytes(&m));
            let mut expect = alloc::string::String::new();
            let mut i = 0;
            while i < ($bits / 8) * 2 - 1 {
                expect.push('0');
                i += 1;
            }
            expect.push('1');
            check(concat!($tag, " a*(1/a) is one"), got, &expect);
        }

        check(
            concat!($tag, " Size/BitLen"),
            fmt::Sprintf!("%d %d", m.Size(), m.BitLen()),
            $sizebits,
        );
    }};
}

#[goish::main]
fn main() {
    curve!(
        256,
        "256",
        "0b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde5",
        "28364452606e7c8a98a6b4c2d0deecfb09172533414f5d6b798795a3b1bfcddc",
        "70f7ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cb",
        "74ed8d89b2ea5375f3809bf25c644437453b9e244ea780b5f7cae7c20ee8881d",
        "0e98550ef88a30cd8e50df012e123374c73d1b0462a9ffefc6424bad57c460e8",
        "02c75996b41cb3210c77d06a118ae55ffda676ddb37606984a17d03d6f075fcb",
        "true",
        "62c56e0fad0098e971aa23a87b532e191c2df35f7889875d0bf88ac963180856",
        "32 256"
    );
    curve!(
        1024,
        "1024",
        "0b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4\
         ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4\
         cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4\
         abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d85",
        "28364452606e7c8a98a6b4c2d0deecfb09172533414f5d6b798795a3b1bfcddb\
         e8f70412202e3c4a58667482909eacbac8d6e4f3010f1d2b39475563717f8d9b\
         a9b7c5d3e0eefd0a18263442505e6c7a8896a4b2c0cedceaf9071523313f4d5b\
         69778593a1afbdcbd9e6f503101e2c3a48566472808e9caab8c6d4e2f0ff0d1c",
        "70f7ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3ca\
         d2d9dfe6ecf3fb020910171e252c333a41484f565d646b727980878e959ca3aa\
         b1b8bfc6ced5dce2e8eff6fe050c131a21282f363d444b525960676e757c838a\
         91989fa6adb4bbc2c9d1d8dfe5ebf2fa01080f161d242b323940474e555c636b",
        "6923820a34c6b49b918c15e83d6fca1bbb2abf2c1399ea91b5a8b0b530037f22\
         a1df31f75b6e1339743b8abe3f745d1717e8181cccdd215f0acb0edfb8ab1e13\
         86b09f2b486b4715d7350df01c6b31ce77eef0ad760e4a31fd1bb22c4996faee\
         f9bbe2c2455556f5aa39b6fd9d31f4b3e20101244c04dc7f278e0a777f433b02",
        "230f1b6a1a132ff39581bf9dc5813229dd1f1e6a5371b1e4ae4bc587ac0e1d83\
         d22b0a0257286bea99e751ea04a359353e6002565675e92771c2f6b9a7fe2777\
         9b1d4b402ada24843fd69252187e4390146c11c2df308e0b42f81f6800dd978e\
         82143773ec39459061984eec298a51c1cb99fe9d17ada2159c75f2ae8e1d48c7",
        "1eb65737a190b73e4ca77738f56637838947917d1ff06fba896c4982d1b266e2\
         bfd99f060a73f344287c1c71f9b714672cff2546707a7f6296311ebe8a1b4f39\
         8612e635b20ee2b97a01cc955701cb60d162f3f986c864c06fdd3fd43097a616\
         d6454698ad42d6dd214ce43a9ff4f937d09591402370edc1e8adb297a2b59e73",
        "true",
        "2146dec68532d7e967fdd0b6cd08f0449d87a22d24113e305cdc2dbce1cb5255\
         ae7bf2000a7406e6f6207ffde065fab67a3b234609875dc031f7db4c14083d82\
         5a6dd585ae5eb86416560e336a7bd71ca89a74116ef2f4199d7c8c6226589fc6\
         e977dea54ba2f461ac07e1648dd0df5c46d181ecca441cbbff75cfda3f5de8af",
        "128 1024"
    );
    curve!(
        2048,
        "2048",
        "0b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4\
         ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4\
         cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4\
         abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d84\
         8b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d64\
         6b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d44\
         4b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d24\
         2b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd05",
        "28364452606e7c8a98a6b4c2d0deecfb09172533414f5d6b798795a3b1bfcddb\
         e8f70412202e3c4a58667482909eacbac8d6e4f3010f1d2b39475563717f8d9b\
         a9b7c5d3e0eefd0a18263442505e6c7a8896a4b2c0cedceaf9071523313f4d5b\
         69778593a1afbdcbd9e6f503101e2c3a48566472808e9caab8c6d4e2f0ff0d1b\
         29374553616f7d8b99a7b5c3d1dfecfb08162432404e5c6a788694a2b0beccda\
         e8f70513212f3d4b59677583919fadbbc9d7e4f3010e1c2a38465462707e8c9a\
         a8b6c4d2e0eefd0b19273543515f6d7b8997a5b3c1cfddeaf9061422303e4c5a\
         68768492a0aebccad8e6f503111f2d3b49576573818f9dabb9c7d5e2f0ff0c1c",
        "70f7ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3ca\
         d2d9dfe6ecf3fb020910171e252c333a41484f565d646b727980878e959ca3aa\
         b1b8bfc6ced5dce2e8eff6fe050c131a21282f363d444b525960676e757c838a\
         91989fa6adb4bbc2c9d1d8dfe5ebf2fa01080f161d242b323940474e555c636a\
         71787f868d949ba2a9b0b7bec5ccd4dbe1e7eef5fd040b121920272e353c434a\
         51585f666d747b828990979ea5acb3bac1c8d0d7dee4eaf1f900070e151c232a\
         31383f464d545b626970777e858c939aa1a8afb6bdc4cbd3dae0e6edf4fc030a\
         11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7cfd6dde3eb",
        "362190a202a37cb5b2c875d16b4316f898e461aa761aa0d5ec6dc5454d0d7dcc\
         b6a600268027a685451e65212c9d0f068520c31c3e1c3d7a110d50c43d6da7fe\
         ade44dfe78d04ce3dfde0959101b117bdc0b6a629ddfa0ccd19c824b5edc290b\
         ae88f0315359969a07e77acfa658192377263cb0235a1ae92f977a4436d81c5c\
         d2cd79441cadd06c3f09f2f4e2fa2f4e7fbdc3b5bb626cba09764d867fba82d2\
         8c882542d26e77dbca17aaf86ab417cf164ba2e59fc78e287e3ab2c74a527b26\
         696571dc084a211328cccbaa1104bef9fda812ffb5759eac2b9ff8c6e6071d77\
         79a25742e23c8623150453f0072f70e3595e92c2861e77f7036993d657a5f801",
        "762d08234c97d3cbeaec99a0de04b6ff4606224e9845d25c8f455a622f0b8727\
         3bc05c2bc86dfd8597c7c2046f7b850b3a3a6f3cff48d9da5917b17263eaf6a1\
         76850ceac4e36a34e9201cec88e21a04ee1b6fb845b7a2ca36d198e52ba006a9\
         842564f445f07f606ad97a34ba75da285148d894655631e4a0d91c4066b92214\
         850e308d4866f4ec0eee13b594d5688d5c0b512e177dc7fd27a06eceb59fa6be\
         8a3210cebc12c9df9c3cb43724275d12cbf85a449d2abe98c1dc10fd8e0db4d6\
         9598652e156b287f49a7072904b751b27385c96eb48b3bf71ddd20ed9172d556\
         871c809dc6af0115a285b9982379e16292457573689f30b9971784bb6f7d150d",
        "1964f9fa0d64757dce0b937bc364a89b3dab605d8f160d8bdf80c3f6b165f1f8\
         ba7f0e178aeaedc20cdfbe3dc039f21c2fbf32335a58ddb9b5347f97fe935731\
         0aa86b3f1e065d8aaec953bef8e0b9cab8a8965e8425890941114ece2a774a93\
         dc143f8c6144c18a2db6b2fec521a9a5d1c930b620de536c47d338490adadaa0\
         fa6cb866beabd198f3de90ee988f81e004defe2bd11d92f6c8660c91fc28b796\
         226eeb945bfb83a5a1d7263890c1195dd8678f7ee14a241b286700a1286a8d77\
         9a56b0c9a024a4aa704a2750a006c544d89e16154b611d3de788d4b34ad876ea\
         3db4d1eadf81287ffadd0427429d0af361067de946e5c6b497071ceb78f3b93b",
        "false",
        "",
        "256 2048"
    );

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("fips140_bigmod_smoke OK\n");
}
