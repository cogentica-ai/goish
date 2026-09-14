// The Lucky13 countermeasure on record.rs's CBC decrypt path.
//
// Go's `tls10MAC` takes a trailing `extra` argument and, after taking
// the Sum, writes it into the same hash:
//
//     res := h.Sum(out)
//     if extra != nil { h.Write(extra) }
//
// conn.go passes the stripped PADDING there (conn.go:443), so the hash
// sees the same number of bytes — and does the same number of
// compression-function blocks — whatever padding length was removed.
// Without it, the MAC's cost tracks the padding, which is the timing
// signal Lucky13 reads to mount a padding oracle against CBC.
//
// conn.rs, the record layer `tls::Dial` actually runs, passes it.
// record.rs's invented copy had no `extra` parameter AT ALL, and §1's
// 2026-09-04 audit of that file fixed the padding ORACLE two lines
// below without noticing the padding TIMING here.
//
// WHAT THIS PINS, precisely, because it is easy to overclaim. It does
// not measure time — a timing test on a shared machine is a coin
// flip, and this tree does not run stress tests. It pins the STRUCTURAL
// property the countermeasure rests on: that the number of bytes handed
// to the hash does not move with the padding length. `__mac_split` is
// the live expression pair from decrypt_record — the function calls it
// rather than repeating the arithmetic — so a regression that dropped
// `extra` (making the second span empty) shows up here as a sum that
// varies.
//
// What it cannot see is someone changing tls10MAC itself to ignore its
// extra argument. That is conn.rs's guarantee too, and it is one
// function with one anchor.
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;

use goish::crypto::tls;
use goish::fmt;
use goish::types::int;

static mut PASS: int = 0;
static mut FAIL: int = 0;

fn check(what: &'static str, ok: bool) {
    unsafe {
        if ok {
            PASS += 1;
        } else {
            FAIL += 1;
            fmt::Printf!("FAIL %s\n", what);
        }
    }
}

#[goish::main]
fn main() {
    // A decrypted CBC block is plaintext || mac(20) || padding. For a
    // fixed block size, vary how much of it is padding and check that
    // what the hash is fed — plaintext plus the padding written after
    // the Sum — stays the same size.
    //
    // 256 bytes is a whole number of AES blocks. The upper bound is
    // 236, not 255: beyond that the block cannot still hold a 20-byte
    // MAC, and decrypt_record has already returned "bad record MAC" —
    // `__mac_split`'s precondition, and the reason it panics rather
    // than wrapping.
    let total: int = 256;
    let mut baseline: int = -1;
    let mut varied = false;
    let mut to_remove: int = 1;
    while to_remove <= 236 {
        let (mac_start, extra_start) = tls::__mac_split(total as usize, to_remove as usize);
        let plaintext_len = goish::int(goish::int64(mac_start));
        let extra_len = total - goish::int(goish::int64(extra_start));
        let hashed = plaintext_len + extra_len;

        if baseline < 0 {
            baseline = hashed;
        } else if hashed != baseline {
            varied = true;
            fmt::Printf!(
                "FAIL to_remove=%v: hashed %v bytes, baseline %v\n",
                to_remove,
                hashed,
                baseline
            );
        }

        // The two spans must also actually partition the block around
        // the MAC — a split that overlapped would hash bytes twice and
        // still keep the sum constant.
        check(
            "the MAC sits between the two hashed spans",
            extra_start == mac_start + 20,
        );
        // And the padding really is what lands in `extra`: everything
        // after the MAC is exactly the bytes that were stripped.
        check(
            "extra is exactly the stripped padding",
            total - goish::int(goish::int64(extra_start)) == to_remove,
        );

        to_remove += 1;
    }
    check("the hashed length does not vary with padding", !varied);

    // The baseline is the whole block minus the MAC, which is the
    // statement in its strongest form: every byte of the block except
    // the MAC goes through the hash, always.
    check(
        "every non-MAC byte of the block is hashed",
        baseline == total - 20,
    );

    unsafe {
        let (pass, fail) = (PASS, FAIL);
        // 236 iterations x 2 checks, plus the two summary rows.
        if pass + fail != 474 {
            fmt::Printf!("FAIL ran %v checks, expected 474\n", pass + fail);
            FAIL += 1;
        }
        let fail = FAIL;
        fmt::Printf!(
            "tls_lucky13_smoke: %v checks, %v failed\n",
            pass + fail,
            fail
        );
        if fail > 0 {
            goish::syscall::Exit(1);
        }
    }
}
