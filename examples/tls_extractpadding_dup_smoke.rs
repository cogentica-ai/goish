// crypto/tls had TWO extractPaddings, and Go has one.
//
//   conn.rs::extractPadding      the anchored port of conn.go:281-314
//   record.rs::extract_padding   an invented second copy
//
// This is the CBC padding check. §1's 2026-09-04 audit of record.rs
// found a padding oracle in that file, which is the reason to care
// that its padding code and the ported one are the same function.
//
// The two are not even written alike. Go computes `t` in `uint` and
// then broadcasts with `byte(int32(^t) >> 31)` — a deliberate narrowing
// to 32 bits. conn.rs mirrors that exactly. record.rs used `i64` and
// `>> 63`, broadcasting bit 63 instead of bit 31. Both happen to be
// right, because `^t` is either all-high-bits-set or a small positive
// in every reachable case, so bits 31 and 63 agree — but "happens to
// agree" is what a table is for, not a comment.
//
// Every expected value came from Go 1.25.5's own extractPadding, which
// is unexported: `scripts/goref.sh crypto/tls` runs a TestGoishRef
// INSIDE a writable GOROOT copy so it can call it. Committed verbatim
// as examples/testdata/tls_extractpadding_ref.txt.
//
// The grid is the branch structure, not random inputs: every one-byte
// payload (all 256 declared padding lengths against a 1-byte buffer),
// well-formed padding of every length 1..258, each of those with a byte
// corrupted at the front and in the middle, paddingLen larger than the
// payload, and the exact-fit case where the payload is entirely
// padding. 1,041 rows.
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::crypto::tls;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::types::{byte, int};

const REF: &str = include_str!("testdata/tls_extractpadding_ref.txt");

static mut PASS: int = 0;
static mut FAIL: int = 0;
static mut ROWS: int = 0;

fn check(what: string, got_remove: int, got_good: int, want_remove: int, want_good: int) {
    unsafe {
        if got_remove == want_remove && got_good == want_good {
            PASS += 1;
        } else {
            FAIL += 1;
            fmt::Printf!(
                "FAIL %s: got (%v,%v) want (%v,%v)\n",
                what,
                got_remove,
                got_good,
                want_remove,
                want_good
            );
        }
    }
}

// Rebuild the payload the generator used, from the row's tag and length.
// The tags encode the shape, so the inputs are reproducible without
// shipping 300 bytes per row.
fn payload_for(tag: &str, len: int) -> Option<Vec<byte>> {
    let n = len as usize;
    if tag == "empty" {
        return Some(Vec::new());
    }
    if let Some(rest) = tag.strip_prefix("one_") {
        let b: i64 = rest.parse::<i64>().ok()?;
        return Some(alloc::vec![b as byte]);
    }
    let mk_ok = |k: usize| -> Vec<byte> {
        let mut p = alloc::vec![0x5au8; n];
        let mut i = 0usize;
        while i < k {
            p[n - 1 - i] = (k - 1) as byte;
            i += 1;
        }
        return p;
    };
    if let Some(rest) = tag.strip_prefix("ok_") {
        let k: usize = rest.parse::<usize>().ok()?;
        return Some(mk_ok(k));
    }
    if let Some(rest) = tag.strip_prefix("bad_first_") {
        let k: usize = rest.parse::<usize>().ok()?;
        let mut p = mk_ok(k);
        p[n - k] ^= 1;
        return Some(p);
    }
    if let Some(rest) = tag.strip_prefix("bad_mid_") {
        let k: usize = rest.parse::<usize>().ok()?;
        let mut p = mk_ok(k);
        p[n - 2] ^= 1;
        return Some(p);
    }
    if tag.starts_with("over_") {
        return Some(alloc::vec![0xffu8; n]);
    }
    if tag.starts_with("exact_") {
        return Some(alloc::vec![(n - 1) as byte; n]);
    }
    return None;
}

#[goish::main]
fn main() {
    for line in REF.split('\n') {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split(' ');
        let tag: &str = it.next().unwrap_or("");
        let len: int = it.next().unwrap_or("").parse::<i64>().unwrap_or(-1);
        let want_remove: int = it.next().unwrap_or("").parse::<i64>().unwrap_or(-1);
        let want_good: int = it.next().unwrap_or("").parse::<i64>().unwrap_or(-1);
        let payload = match payload_for(tag, len) {
            Some(p) => p,
            None => {
                fmt::Printf!("FAIL unrecognised reference tag\n");
                unsafe {
                    FAIL += 1;
                }
                continue;
            }
        };
        if len < 0 || want_remove < 0 || want_good < 0 || payload.len() != len as usize {
            fmt::Printf!("FAIL malformed reference row\n");
            unsafe {
                FAIL += 1;
            }
            continue;
        }
        unsafe {
            ROWS += 1;
        }
        let name = string::from_bytes(tag.as_bytes());

        // The anchored port.
        let (r1, g1) = tls::conn_extractPadding(slice::<byte>::__from_vec(payload.clone()));
        check(
            name.clone() + string::from_static(" ported"),
            r1,
            goish::int(g1),
            want_remove,
            want_good,
        );

        // The copy in record.rs.
        let (r2, g2) = tls::__extract_padding(&payload);
        check(
            name + string::from_static(" record"),
            goish::int(goish::int64(r2)),
            goish::int(g2),
            want_remove,
            want_good,
        );
    }

    unsafe {
        let rows = ROWS;
        if rows < 1000 {
            fmt::Printf!("FAIL only %v reference rows ran; expected >= 1000\n", rows);
            FAIL += 1;
        }
        let (pass, fail) = (PASS, FAIL);
        fmt::Printf!(
            "tls_extractpadding_dup_smoke: %v rows, %v checks, %v failed\n",
            rows,
            pass + fail,
            fail
        );
        if fail > 0 {
            goish::syscall::Exit(1);
        }
    }
}
