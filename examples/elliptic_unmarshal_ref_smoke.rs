// elliptic_unmarshal_ref_smoke — what Unmarshal REFUSES.
//
// Reference: Go 1.25.5 crypto/elliptic, measured by
// tools/gen_elliptic_unmarshal_ref.go. Every GO[] line is Go's
// verbatim output.
//
// elliptic_smoke already checks that Unmarshal accepts a valid point
// and returns the right coordinates. This checks the other half, which
// is the half that matters for safety: an invalid-curve attack works
// by getting a peer to ACCEPT a point that is not on the curve and
// then do arithmetic with it, so a decoder that returns coordinates
// for off-curve input hands an attacker the whole primitive.
//
// Four rejections, each a different way to be wrong:
//
//   off-curve      — one flipped bit in X. Structurally perfect, and
//                    not a point on P-256.
//   short          — one byte missing, so the length check must fire
//                    before any coordinate is read.
//   compressed-tag — 0x02 in front of uncompressed data. The tag says
//                    one encoding and the body is another; accepting
//                    it reads Y from bytes that are not Y.
//   zero-point     — the uncompressed tag over all zeroes, i.e. (0,0),
//                    which is not on the curve and is what a lazy
//                    "did it decode?" check lets through.
//
// A NOTE ON THE PATH TAKEN. Go's nistCurve implements the private
// `unmarshaler` interface and Unmarshal dispatches to it; goish's
// nistCurve implements it too, but the type is never registered in the
// interface registry, so the cast always misses and the GENERIC
// fallback runs instead. The answers are identical to Go's on all five
// inputs — the fallback validates as thoroughly — so this is a path
// difference and not a defect. Recording it because the impl is
// otherwise dead code that looks live.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::crypto::elliptic;
use goish::fmt;
use goish::string;

// Go's verbatim output.
const GO: [&str; 5] = [
    "valid              ok=true  onCurve=true",
    "off-curve          ok=false onCurve=false",
    "short              ok=false onCurve=false",
    "compressed-tag     ok=false onCurve=false",
    "zero-point         ok=false onCurve=false",
];

static FAILED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static LN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn chk(got: goish::string) {
    use core::sync::atomic::Ordering;
    let i = LN.fetch_add(1, Ordering::Relaxed);
    let g: &str = got.as_ref();
    if i >= GO.len() {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("[!!] extra line %d: %s\n", i as i64, got);
        return;
    }
    if g == GO[i] {
        fmt::Printf!("ok   %s\n", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!(
            "[!!] line %d\n  got:  %s\n  want: %s\n",
            i as i64,
            got,
            goish::string(GO[i])
        );
    }
}

#[goish::main]
fn main() {
    let c = elliptic::P256();
    let (_priv, x, y, err) = elliptic::GenerateKey(c, &mut goish::crypto::rand::Reader);
    if !err.IsNil() {
        fmt::Printf!("genkey: %v\n", err);
        goish::os::Exit(1);
    }
    let good = elliptic::Marshal(c, &x, &y);

    let show = |tag: &str, b: goish::slice<goish::byte>| {
        let (gx, gy, ok) = elliptic::Unmarshal(c, &b);
        let on_curve = ok && c.IsOnCurve(&gx, &gy);
        chk(fmt::Sprintf!(
            "%-18s ok=%-5v onCurve=%v",
            goish::string::from_bytes(tag.as_bytes()),
            ok,
            on_curve
        ));
    };

    show("valid", good.clone());

    let mut bad: Vec<u8> = good.clone().__into_vec();
    bad[1] ^= 0x01;
    show("off-curve", goish::slice::<goish::byte>::__from_vec(bad));

    let gv = good.clone().__into_vec();
    show(
        "short",
        goish::slice::<goish::byte>::__from_vec(gv[..gv.len() - 1].to_vec()),
    );

    let mut comp: Vec<u8> = good.clone().__into_vec();
    comp[0] = 0x02;
    show(
        "compressed-tag",
        goish::slice::<goish::byte>::__from_vec(comp),
    );

    let mut z: Vec<u8> = alloc::vec![0u8; good.clone().__into_vec().len()];
    z[0] = 4;
    show("zero-point", goish::slice::<goish::byte>::__from_vec(z));

    let _ = string("");

    use core::sync::atomic::Ordering;
    let f = FAILED.load(Ordering::Relaxed);
    let n = LN.load(Ordering::Relaxed);
    if f == 0 && n == GO.len() {
        fmt::Printf!("\nok %d/%d\n", n as i64, GO.len() as i64);
        goish::os::Exit(0);
    }
    fmt::Printf!(
        "\nFAILED %d of %d (%d lines)\n",
        f as i64,
        GO.len() as i64,
        n as i64
    );
    goish::os::Exit(1);
}
