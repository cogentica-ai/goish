// cmp — Go's `cmp` package (Go 1.21+), ported.
//
// Provides type-generic comparison helpers used by `slices`, `maps`,
// and user code:
//
//   Go                                    goish
//   ───────────────────────────────────   ─────────────────────────────
//   ok := cmp.Less(a, b)                  let ok = cmp::Less(&a, &b);
//   c  := cmp.Compare(a, b)               let c  = cmp::Compare(&a, &b);
//   v  := cmp.Or(x, y, z)                 let v  = cmp::Or(&[x, y, z]);
//
// Slim deviation: floating-point NaN handling is omitted because the
// goish public API doesn't expose `f32`/`f64` types yet. When floats
// land they should follow Go's NaN rules (NaN < non-NaN, NaN == NaN
// for `Compare`).

#![allow(non_snake_case)]

use crate::types::int;

/// `cmp.Less(x, y)` (cmp.go:28) — true when `x < y`.
pub fn Less<T: PartialOrd>(x: &T, y: &T) -> bool {
    // Go: return (isNaN(x) && !isNaN(y)) || x < y
    // Slim: no NaN; just `x < y`.
    x < y
}

/// `cmp.Compare(x, y)` (cmp.go:40) — `-1`/`0`/`+1` for less/equal/greater.
pub fn Compare<T: Ord>(x: &T, y: &T) -> int {
    use core::cmp::Ordering::*;
    // Go: switch { x < y → -1; x > y → +1; default → 0 }
    match x.cmp(y) {
        Less => -1,
        Equal => 0,
        Greater => 1,
    }
}

/// `cmp.Or(vals...)` (cmp.go:69) — return the first argument that is
/// not equal to `T`'s zero value, or the zero value if none qualify.
/// Slim takes a borrowed slice rather than variadic since Rust lacks
/// Go's `...T` syntax.
pub fn Or<T: PartialEq + Default + Clone>(vals: &[T]) -> T {
    // Go: var zero T
    let zero = T::default();
    // Go: for _, val := range vals { if val != zero { return val } }
    for val in vals {
        if *val != zero {
            return val.clone();
        }
    }
    // Go: return zero
    zero
}
