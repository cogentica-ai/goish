// go: file cmp/cmp.go decls: isNaN, Less, Compare, Or
// goishlint:ignore GOISH021 Ordered — Go's `Ordered` is a type-set
//     constraint interface (`~int | ~int8 | … | ~string`), which Rust
//     spells as a trait bound. Every function here carries it as
//     `T: PartialOrd`, so there is nothing to declare separately.
//
// cmp.go — Less, Compare, Or, and the NaN rule behind the first two.
//
// Go's ordering of floats is neither Rust's `PartialOrd` nor IEEE
// comparison. `cmp.Less` puts a NaN BEFORE every non-NaN; `cmp.Compare`
// calls two NaNs equal; and -0.0 equals 0.0. Everything in the standard
// library that sorts or searches goes through these two, so the rule
// reaches `slices.Sort`, `sort.Float64s`, `slices.BinarySearch` and
// `slices.IsSorted` alike.
//
// goish had the rule written out as "omitted because the goish public
// API doesn't expose f32/f64 types yet" — which stopped being true a
// long time ago. Leaving NaN to `x < y` is not a mild divergence: `x <
// y` is FALSE in both directions for a NaN, so a comparison sort sees
// one as equal to everything and can leave the slice unsorted.

use crate::types::int;

// go: sdk 1.25.5 cmp/cmp.go:63-65 isNaN
/// Go: "isNaN reports whether x is a NaN without requiring the math
/// package. This will always return false if T is not floating-point."
///
/// `x != x` is true only for a NaN, and for an integer or a string it
/// is never true — which is exactly why Go writes it this way and why
/// one bound serves every ordered type.
pub fn isNaN<T: PartialOrd>(x: &T) -> bool {
    return x != x;
}

// go: sdk 1.25.5 cmp/cmp.go:28-30 Less
/// `cmp.Less(x, y)` — true when `x` sorts before `y`.
///
/// Go: `return (isNaN(x) && !isNaN(y)) || x < y`.
pub fn Less<T: PartialOrd>(x: &T, y: &T) -> bool {
    return (isNaN(x) && !isNaN(y)) || x < y;
}

// go: sdk 1.25.5 cmp/cmp.go:40-60 Compare
/// `cmp.Compare(x, y)` — `-1`/`0`/`+1` for less/equal/greater.
///
/// Go: "For floating-point types, a NaN is considered less than any
/// non-NaN, a NaN is considered equal to a NaN, and -0.0 is equal to
/// 0.0."
///
/// The bound was `T: Ord`, which no float satisfies in Rust, so this
/// could not be called on one at all.
pub fn Compare<T: PartialOrd>(x: &T, y: &T) -> int {
    // Go: xNaN := isNaN(x); yNaN := isNaN(y)
    let xNaN = isNaN(x);
    let yNaN = isNaN(y);
    if xNaN {
        if yNaN {
            return 0;
        }
        return -1;
    }
    if yNaN {
        return 1;
    }
    if x < y {
        return -1;
    }
    if x > y {
        return 1;
    }
    return 0;
}

// go: sdk 1.25.5 cmp/cmp.go:69-77 Or
/// `cmp.Or(vals...)` — return the first argument that is
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
    return zero;
}
