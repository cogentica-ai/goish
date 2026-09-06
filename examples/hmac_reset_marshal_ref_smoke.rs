// hmac_reset_marshal_ref_smoke — HMAC's cached ipad/opad path, for
// every marshalable hash, against Go 1.25.5.
//
// hmac.Reset caches the marshaled inner and outer states the first
// time it runs, then restores them on later Reset and Sum instead of
// rewriting ipad/opad. goish takes that shortcut through an interface
// assertion, and the two directions are NOT symmetric:
//
//   the state is CACHED behind `cast!(&*inner, marshalable)`  — &self
//   the state is RESTORED behind `cast!(&mut *inner, …)`      — &mut
//
// When the assertion MISSES, `marshaled` simply stays false and HMAC
// rewrites ipad/opad every time — same MAC, more work. That is why the
// MAC rows below cannot detect it: they were green before this was
// found and green after. Measured, not assumed — removing sha3's
// registration leaves all five MAC rows passing.
//
// So there are two sections. The rows compared against Go are a
// correctness check, and they matter because turning the cached path
// ON is a behaviour change: HMAC starts restoring a serialized sponge
// state instead of recomputing it, and it has to produce the same
// bytes. hmac_smoke exercises Reset for sha256 only; all five
// implementors are here because the wiring is per-type.
//
// The WIRING section below is goish-only — Go has no equivalent
// output, because in Go a type with the right methods satisfies the
// interface and there is nothing to register. It asserts what the MAC
// rows cannot: that the cached path is actually reachable for each
// hash. sha3 was FALSE there until `crypto::sha3::SHA3` — the wrapper
// `sha3::NewHash256` actually boxes, as against the fips140 Digest
// that was registered — gained its own `marshalable` impl.
//
// `stable` calls Sum twice through the cached path; `matches-fresh`
// compares against an HMAC that never took it.
//
// Reference: scripts/goref.sh crypto/hmac.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::boxed::Box;

use goish::hash::Hash;
use goish::crypto::internal::fips140::hmac::marshalable;
use goish::crypto::{hmac, md5, sha1, sha256, sha3, sha512};
use goish::goslice::slice;
use goish::gostring::string;
use goish::io::Writer;
use goish::types::byte;
use goish::{encoding::hex, fmt};

const GO: [&str; 5] = [
    "sha256    mac=01f721c70a32a3508e4bcc0bc7a16d3c727c63b1efadea3a110549bfe48ba5a8 stable=true matches-fresh=true size=32",
    "sha512    mac=c9b9533220946bcc115ca3921223cc5ad74610be573a78a95361f3c5f67dcb9f97b3cd584142eaf25281a8d850790595d2bba4510fa84b52d72b7c6f5367aecb stable=true matches-fresh=true size=64",
    "sha1      mac=95b9def977f377d0cc585d3cfb8bd12967913923 stable=true matches-fresh=true size=20",
    "md5       mac=357e7ea18b7c43bd68017b77ace01110 stable=true matches-fresh=true size=16",
    "sha3-256  mac=be769e24c9c4b758b4414d82000ed361a6fd58faeee5e507b6728a9eb9422c56 stable=true matches-fresh=true size=32",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line: %q\n", got);
        *ln += 1;
        return;
    }
    let want = string::from(GO[*ln]);
    if got.clone() == want {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] goish: %q\n", got);
        fmt::Printf!("     go   : %q\n", want);
    }
    *ln += 1;
}

fn b(x: &str) -> slice<byte> {
    slice::<byte>::__from_vec(x.as_bytes().to_vec())
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;
    let cases: [(&str, fn() -> Box<dyn Hash + Send + Sync>); 5] = [
        ("sha256", sha256::NewHash),
        ("sha512", sha512::NewHash),
        ("sha1", sha1::NewHash),
        ("md5", md5::NewHash),
        ("sha3-256", sha3::NewHash256),
    ];
    let key = b("key-for-hmac");
    for (name, ctor) in cases.iter() {
        let mut h = hmac::New(*ctor, key.clone());
        // First Reset caches the marshaled ipad/opad state.
        h.Reset();
        let _ = h.Write(b("garbage"));
        // Second Reset takes the marshaled branch — the &mut cast.
        h.Reset();
        let _ = h.Write(b("Hi There"));
        let mac1 = h.Sum(slice::<byte>::new());
        h.Reset();
        let _ = h.Write(b("Hi There"));
        let mac2 = h.Sum(slice::<byte>::new());
        let mut fresh = hmac::New(*ctor, key.clone());
        let _ = fresh.Write(b("Hi There"));
        let want = fresh.Sum(slice::<byte>::new());

        let h1 = hex::EncodeToString(mac1.as_ref());
        let h2 = hex::EncodeToString(mac2.as_ref());
        let hw = hex::EncodeToString(want.as_ref());
        chk(
            &mut ln,
            &fmt::Sprintf!(
                "%-9s mac=%s stable=%v matches-fresh=%v size=%d",
                string::from(*name),
                h1.clone(),
                h1.clone() == h2,
                h1 == hw,
                h.Size() as i64
            ),
        );
    }
    if ln != GO.len() {
        fmt::Printf!("[!!] line count mismatch with the Go reference\n");
    }

    // ── wiring: is the cached path reachable at all? ──────────────
    //
    // goish-only. The registry is filled by hmac::New, so this runs
    // after the loop above has constructed one — testing the casts on
    // a cold registry measures the registry, not the code.
    let mut bad = 0;
    for (name, ctor) in cases.iter() {
        let mut h = ctor();
        let (_, ok_ref) = goish::cast!(&*h, marshalable);
        let ok_mut = goish::cast!(&mut *h, marshalable).is_some();
        if ok_ref && ok_mut {
            fmt::Printf!("[ok] wiring    %-9s marshalable reachable\n", string::from(*name));
        } else {
            bad += 1;
            fmt::Printf!(
                "[!!] wiring    %-9s cast(&h)=%v cast(&mut h)=%v — HMAC cannot cache\n",
                string::from(*name), ok_ref, ok_mut
            );
        }
    }
    if bad != 0 {
        fmt::Printf!("[!!] %d hash(es) cannot take HMAC's cached path\n", bad as i64);
    }
    goish::os::Exit(0);
}
