// ConstantTimeByteEq, exhaustively, across every implementation goish has.
//
// Go declares it twice — crypto/subtle and
// crypto/internal/fips140/subtle — and goish had THREE, the extra one a
// private hand-rolled body in edwards25519.rs under the note
// "edwards25519 needs only this one subtle primitive; ported inline".
// Go's tables.go does not inline it; it calls
// subtle.ConstantTimeByteEq. Found by scripts/dup_impl_check.py.
//
// Its two callers pick a point out of the precomputed table during
// scalar multiplication, which is exactly where a timing difference
// would leak the private scalar — so a third copy of the primitive is
// the last kind worth keeping, whether or not it agrees.
//
// It agreed, and this says so EXHAUSTIVELY rather than by sample:
// there are only 256x256 = 65,536 inputs, so every one of them is
// checked, against the definition (1 iff x == y) and not merely
// against a sibling implementation. A table that only cross-checked
// the copies would pass if all of them were wrong together.
//
// What this table does NOT cover, stated plainly: the edwards25519 copy
// is private and now delegates, so nothing here calls it. The
// assurance that the delegation preserved behaviour is that
// edwards25519's table selection feeds every scalar multiplication, so
// `ed25519_ref_smoke`, `fips_ed25519_smoke` and `crypto_ed25519_smoke`
// would all fail if it had not. That is measured, not assumed:
// perturbing the delegation to `ConstantTimeByteEq(x, y ^ 1)` turns
// both ref smokes red. This table's job is
// the narrower one: the primitive it now delegates TO is correct on
// every input, which is what makes delegating to it the right move.
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;

use goish::crypto::internal::fips140::subtle as fsubtle;
use goish::crypto::subtle;
use goish::fmt;
use goish::types::int;

static mut FAIL: int = 0;
static mut CHECKS: int = 0;

#[goish::main]
fn main() {
    let mut x: int = 0;
    while x < 256 {
        let mut y: int = 0;
        while y < 256 {
            // The definition, not another implementation of it.
            let want: int = if x == y { 1 } else { 0 };

            let a = subtle::ConstantTimeByteEq(x as u8, y as u8);
            let b = fsubtle::ConstantTimeByteEq(x as u8, y as u8);
            unsafe {
                CHECKS += 2;
                if a != want {
                    FAIL += 1;
                    fmt::Printf!("FAIL crypto/subtle x=%v y=%v got %v want %v\n", x, y, a, want);
                }
                if b != want {
                    FAIL += 1;
                    fmt::Printf!("FAIL fips140/subtle x=%v y=%v got %v want %v\n", x, y, b, want);
                }
            }
            y += 1;
        }
        x += 1;
    }

    unsafe {
        let (checks, fail) = (CHECKS, FAIL);
        // Rows-run gate: 2 x 65,536. A loop that did not run would
        // otherwise print 0 checks and read as a pass.
        if checks != 131072 {
            fmt::Printf!("FAIL ran %v checks, expected 131072\n", checks);
            FAIL += 1;
        }
        let fail = FAIL;
        fmt::Printf!("ed25519_ctbyteeq_smoke: %v checks, %v failed\n", checks, fail);
        if fail > 0 {
            goish::syscall::Exit(1);
        }
    }
}
