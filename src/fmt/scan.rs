// go: file fmt/scan.go decls: Sscan, Sscanf
//
// scan.go — Sscan and Sscanf.

extern crate alloc;
#[allow(unused_imports)]
use alloc::vec::Vec;

#[allow(unused_imports)]
use crate::convert::{
    byte as tobyte, int as toint, int32 as toint32, int64 as toint64, uint as touint,
    uint32 as touint32, uint64 as touint64,
};
#[allow(unused_imports)]
use crate::errors::nil;
#[allow(unused_imports)]
use crate::errors::{self, error, ErrorTrait};
#[allow(unused_imports)]
use crate::goslice::slice;
#[allow(unused_imports)]
use crate::gostring::string;
#[allow(unused_imports)]
use crate::io;
#[allow(unused_imports)]
use crate::os;
#[allow(unused_imports)]
use crate::types::{byte, int, rune};
#[allow(unused_imports)]
use crate::unicode::utf8;

#[allow(unused_imports)]
use super::*;

// ─── Sscanf ──────────────────────────────────────────────────────────
//
// Go's `fmt.Sscanf(input, format, args...)` scans values from `input`
// guided by `format` directives. v1 surfaces the limited subset that
// real ports exercise: a single scan target with a single directive
// (`%f`, `%d`, `%s`). The polymorphism is via the `ScanTarget` trait;
// each impl knows how to consume the trimmed input for its directive.
//
// The transpiler emits `&mut <target>` at call sites tagged with
// `Mutates: []int{2}` in stdlib_registry, so callers like
// `fmt.Sscanf(num, "%f", val)` lower to
// `fmt::Sscanf(num, string("%f"), &mut val)` — the receiver is borrowed
// mutably so the side effect on `val` is visible afterwards.

/// Anything that can be filled by `fmt::Sscanf` for a given directive
/// in `format`. The directive is the byte after `%` (e.g. `b'f'`).
pub trait ScanTarget {
    // go: none — goish idiom: Go's scanner is built on the `ScanState`/`Scanner`
    //     interfaces and a `ss` state machine; goish's `Sscan`/`Sscanf` take
    //     a typed target directly, and this is that target's own read.
    fn __scan_one(&mut self, input: &str, verb: u8) -> bool;
}

impl ScanTarget for crate::math::big::Rat {
    // go: none — goish idiom: Go's scanner is built on the `ScanState`/`Scanner`
    //     interfaces and a `ss` state machine; goish's `Sscan`/`Sscanf` take
    //     a typed target directly, and this is that target's own read.
    fn __scan_one(&mut self, input: &str, verb: u8) -> bool {
        return match verb {
            b'f' | b'g' | b'e' | b'v' => crate::math::big::parse_decimal_into_rat(input, self),
            _ => false,
        };
    }
}

impl ScanTarget for int {
    // go: none — goish idiom: Go's scanner is built on the `ScanState`/`Scanner`
    //     interfaces and a `ss` state machine; goish's `Sscan`/`Sscanf` take
    //     a typed target directly, and this is that target's own read.
    fn __scan_one(&mut self, input: &str, verb: u8) -> bool {
        return match verb {
            b'd' | b'v' => match input.trim().parse::<int>() {
                Ok(n) => {
                    *self = n;
                    true
                }
                Err(_) => false,
            },
            _ => false,
        };
    }
}

impl ScanTarget for f64 {
    // go: none — goish idiom: Go's scanner is built on the `ScanState`/`Scanner`
    //     interfaces and a `ss` state machine; goish's `Sscan`/`Sscanf` take
    //     a typed target directly, and this is that target's own read.
    fn __scan_one(&mut self, input: &str, verb: u8) -> bool {
        return match verb {
            b'f' | b'g' | b'e' | b'v' => match input.trim().parse::<f64>() {
                Ok(n) => {
                    *self = n;
                    true
                }
                Err(_) => false,
            },
            _ => false,
        };
    }
}

impl ScanTarget for string {
    // go: none — goish idiom: Go's scanner is built on the `ScanState`/`Scanner`
    //     interfaces and a `ss` state machine; goish's `Sscan`/`Sscanf` take
    //     a typed target directly, and this is that target's own read.
    fn __scan_one(&mut self, input: &str, verb: u8) -> bool {
        return match verb {
            b's' | b'v' => {
                *self = string::from(input.trim_start().split_whitespace().next().unwrap_or(""));
                true
            }
            _ => false,
        };
    }
}

// go: sdk 1.25.5 fmt/scan.go:113-115 Sscanf
/// `fmt.Sscanf(input, format, target)` — scan a single value from
/// `input` per the directive in `format`. Returns `(n, err)` where
/// `n` is 1 on success (matching Go's scanned-count contract) and
/// `err` is non-nil on parse failure or directive mismatch.
///
/// v1 limitation: only single-directive formats are supported. Real
/// Go's Sscanf walks multiple verbs over whitespace-separated tokens;
/// add multi-verb support when a port surfaces a real need.
pub fn Sscanf<S1, S2, T>(input: S1, format: S2, target: &mut T) -> (int, error)
where
    S1: Into<string>,
    S2: Into<string>,
    T: ScanTarget + ?Sized,
{
    let input = input.into();
    let format = format.into();
    let fb = format.as_bytes();
    // Find the `%X` directive. Skip any prefix-literal handling — Go
    // allows literal text in the format that must match the input;
    // v1 ports only exercise pure directive formats.
    let mut i = 0;
    while i < fb.len() && fb[i] != b'%' {
        i += 1;
    }
    if i + 1 >= fb.len() {
        return (
            0,
            errors::New(string::from("fmt::Sscanf: format has no directive")),
        );
    }
    let verb = fb[i + 1];
    let s: &str = input.as_ref();
    return if target.__scan_one(s, verb) {
        (1, crate::errors::nil.into())
    } else {
        (0, errors::New(string::from("fmt::Sscanf: parse error")))
    };
}

// go: sdk 1.25.5 fmt/scan.go:99-101 Sscan
/// `fmt.Sscan(input, args...)` — placeholder, defaults to a single
/// `%v` directive. Provided for forward symmetry; not yet exercised.
pub fn Sscan<S, T>(input: S, target: &mut T) -> (int, error)
where
    S: Into<string>,
    T: ScanTarget + ?Sized,
{
    let input = input.into();
    let s: &str = input.as_ref();
    return if target.__scan_one(s, b'v') {
        (1, crate::errors::nil.into())
    } else {
        (0, errors::New(string::from("fmt::Sscan: parse error")))
    };
}
