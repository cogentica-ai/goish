// elliptic_unmarshal_ref_smoke — Unmarshal and UnmarshalCompressed
// across the shapes that must be rejected, against a running Go 1.25.5.
//
// Both functions begin with `curve.(unmarshaler)` and fall back to
// generic big.Int arithmetic when the assertion misses. In goish it
// always missed: `impl<Point: nistPoint> unmarshaler for
// nistCurve<Point>` existed, and none of the four instantiations was
// ever registered for it, so every call took the fallback.
//
// Nothing was WRONG — the fallback is Go's own generic code and agrees
// with Go on all nine lines below, before the fix as well as after.
// What it cost is which implementation runs: Go reaches nistec, whose
// field arithmetic is constant-time, and the fallback's is not. For
// Unmarshal the input is a public key, so this is not the sharpest
// side channel in the world; it is still not what Go does.
//
// The nine cases are the ones where a permissive decoder is dangerous:
// a wrong prefix, a truncated buffer, a point that is not on the
// curve, the point at infinity, and an x coordinate equal to the field
// modulus. All must come back nil, and do — on both paths.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::crypto::elliptic;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::types::{byte, int};

const GO: [&str; 9] = [
    "generator              x=6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296 y=4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    "bad-prefix             nil",
    "short                  nil",
    "empty                  nil",
    "not-on-curve           nil",
    "infinity               nil",
    "x-equals-p             nil",
    "compressed-gen         x=6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296 y=4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    "compressed-badprefix   nil=true",
];

static mut LN: usize = 0;

fn chk(got: &string) {
    let ln = unsafe { LN };
    if ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", ln as int + 1, got);
        unsafe { LN += 1 };
        return;
    }
    if got == GO[ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", ln as int + 1, got, GO[ln]);
    }
    unsafe { LN += 1 };
}

fn show(tag: &str, data: &slice<byte>) {
    let c = elliptic::P256();
    let (x, y, ok) = elliptic::Unmarshal(c, data);
    if !ok {
        chk(&fmt::Sprintf!("%-22s nil", tag));
        return;
    }
    chk(&fmt::Sprintf!("%-22s x=%s y=%s", tag, x.Text(16), y.Text(16)));
}

#[goish::main]
fn main() {

    let c = elliptic::P256();
    let params = c.Params();
    let good = elliptic::Marshal(c, &params.Gx, &params.Gy);
    show("generator", &good);

    let mut v: Vec<byte> = good.to_vec();
    v[0] = 5;
    show("bad-prefix", &slice::__from_vec(v));

    show("short", &good.slice(0, good.Len() - 1));
    show("empty", &slice::new());

    let mut v: Vec<byte> = good.to_vec();
    let n = v.len();
    v[n - 1] ^= 1;
    show("not-on-curve", &slice::__from_vec(v));

    let mut v: Vec<byte> = alloc::vec![0u8; good.Len() as usize];
    v[0] = 4;
    show("infinity", &slice::__from_vec(v));

    let mut v: Vec<byte> = good.to_vec();
    let pb = params.P.Bytes();
    for i in 0..pb.Len() as usize {
        v[1 + i] = pb[i];
    }
    show("x-equals-p", &slice::__from_vec(v));

    let comp = elliptic::MarshalCompressed(c, &params.Gx, &params.Gy);
    let (x, y, ok) = elliptic::UnmarshalCompressed(c, &comp);
    if ok {
        chk(&fmt::Sprintf!("%-22s x=%s y=%s", "compressed-gen", x.Text(16), y.Text(16)));
    } else {
        chk(&fmt::Sprintf!("%-22s nil", "compressed-gen"));
    }
    let mut v: Vec<byte> = comp.to_vec();
    v[0] = 4;
    let (_, _, ok) = elliptic::UnmarshalCompressed(c, &slice::__from_vec(v));
    chk(&fmt::Sprintf!("%-22s nil=%v", "compressed-badprefix", !ok));
    let done = unsafe { LN };
    if done != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", done as int, GO.len() as int);
    }
}
