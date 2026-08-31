// go: file strings/compare.go decls: Compare
//
// strings/compare.go — one function.
//
// Go's comment is worth keeping: Compare is included only for symmetry
// with bytes.Compare. It is usually clearer and always faster to use
// the built-in comparison operators.

#![allow(non_snake_case)]

use crate::gostring::string;
use crate::types::int;

// go: sdk 1.25.5 strings/compare.go:15-17 Compare
/// `strings.Compare(a, b)` — `-1`/`0`/`+1`. Goish provides `==` and
/// `<`/`>` on `string` directly; this exists for API parity with Go.
pub fn Compare<S1: Into<string>, S2: Into<string>>(a: S1, b: S2) -> int {
    let a = a.into();
    let b = b.into();
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    return if ab < bb {
        -1
    } else if ab > bb {
        1
    } else {
        0
    };
}
