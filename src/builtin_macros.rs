// builtin_macros — Go's slice-shaped builtins as Rust macros.
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   make([]int, 5)                       make!([]int, 5)
//   make([]int, 0, 10)                   make!([]int, 0, 10)
//   make([]int, 5, 10)                   make!([]int, 5, 10)
//   s = append(s, x)                     s = append!(s, x)
//   s = append(s, x, y, z)               s = append!(s, x, y, z)
//   copy(dst, src)                       copy!(dst, src)        // → int
//   xs := []int{1, 2, 3}                 let xs = slice!([]int{1, 2, 3});
//
// Macros (rather than free functions) are needed because:
//   - `make` and `slice!` carry a *type argument* in Go-shaped `[]T` form
//   - `append` is variadic
//   - `copy` mutates `dst` in place; the macro avoids leaking `&mut` to
//     the call site.
//
// The trailing `!` is the only visible Rust giveaway — call sites are
// otherwise letter-for-letter Go.

// ─── slice!([]T{a, b, c}) — typed slice literal ───────────────────────

/// `slice!([]T{a, b, c})` — typed slice literal. Mirrors Go's
/// `[]T{a, b, c}` composite literal. Each element is `.into()`-converted,
/// so `&str` widens to `string`, integer literals widen to typed ints, etc.
///
///   let xs = slice!([]int{1, 2, 3});
///   let names = slice!([]string{"alice", "bob"});
#[macro_export]
macro_rules! slice {
    // Empty: slice!([]T{})
    ([] $t:ty { $(,)? }) => {
        {
            let v: $crate::slice<$t> = $crate::slice::__from_vec($crate::__macro_alloc::Vec::<$t>::new());
            v
        }
    };
    // []T{a, b, c} — typed elements. Use `.into()` so &str → string,
    // i32 literals → int, etc.
    ([] $t:ty { $($x:expr),+ $(,)? }) => {
        {
            let __v: $crate::__macro_alloc::Vec<$t> = $crate::__macro_alloc::vec![ $( <$t as ::core::convert::From<_>>::from($x) ),+ ];
            $crate::slice::__from_vec(__v)
        }
    };
}

// ─── make!([]T, ...) — empty/sized slice ──────────────────────────────

/// `make!([]T, len)` — Go's `make([]T, len)`. Returns a slice with the
/// requested length and matching capacity, zero-initialized. Requires
/// `T: Default`.
///
/// `make!([]T, len, cap)` — explicit capacity (cap ≥ len, like Go).
///
/// `make!([]T, 0)` and `make!([]T, 0, cap)` — empty slices (no
/// `Default` needed).
///
/// `make!(map[K]V)` / `make!(map[K]V, hint)` — Go's `make(map[K]V)`.
/// Hint is ignored for v1 (BTreeMap doesn't reserve); reserved for the
/// hashmap port.
#[macro_export]
macro_rules! make {
    // make!(map[K]V) — empty map (V: Default required at construction).
    (map[$kt:ty]$vt:ty) => {
        $crate::gomap::map::<$kt, $vt>::new()
    };
    // make!(map[K]V, hint) — hint accepted for parity, currently ignored.
    (map[$kt:ty]$vt:ty, $hint:expr) => {
        {
            let _ = $hint;
            $crate::gomap::map::<$kt, $vt>::new()
        }
    };
    // make!([]T, 0)  — empty, no Default needed.
    ([] $t:ty, 0) => {
        {
            let v: $crate::slice<$t> = $crate::slice::__from_vec($crate::__macro_alloc::Vec::<$t>::new());
            v
        }
    };
    // make!([]T, 0, cap)  — empty with capacity, no Default needed.
    ([] $t:ty, 0, $cap:expr) => {
        {
            let __cap: usize = $crate::builtin::__make_size($cap);
            let v: $crate::slice<$t> =
                $crate::slice::__from_vec($crate::__macro_alloc::Vec::<$t>::with_capacity(__cap));
            v
        }
    };
    // make!([]T, len, cap)
    ([] $t:ty, $len:expr, $cap:expr) => {
        {
            let __len: usize = $crate::builtin::__make_size($len);
            let __cap: usize = $crate::builtin::__make_size($cap);
            let mut __v: $crate::__macro_alloc::Vec<$t> = $crate::__macro_alloc::Vec::with_capacity(__cap);
            __v.resize_with(__len, <$t as ::core::default::Default>::default);
            $crate::slice::__from_vec(__v)
        }
    };
    // make!([]T, len)
    ([] $t:ty, $len:expr) => {
        {
            let __len: usize = $crate::builtin::__make_size($len);
            let mut __v: $crate::__macro_alloc::Vec<$t> = $crate::__macro_alloc::Vec::with_capacity(__len);
            __v.resize_with(__len, <$t as ::core::default::Default>::default);
            $crate::slice::__from_vec(__v)
        }
    };
}

// ─── append!(s, x, y, z) — variadic append ────────────────────────────

/// `append!(s, x[, y, z, ...])` — Go's `append(s, ...)` for slices.
/// Consumes `s`, pushes each element (with `.into()` so `&str` widens
/// to `string`, etc.), returns the modified slice. Mirror Go's
/// `s = append(s, x, y, z)` shape:
///
///   let xs = make!([]int, 0, 4);
///   let xs = append!(xs, 1, 2, 3);
#[macro_export]
macro_rules! append {
    ($s:expr $(, $x:expr)+ $(,)?) => {
        {
            let mut __v = $crate::slice::__into_vec($s);
            $( __v.push(($x).into()); )+
            $crate::slice::__from_vec(__v)
        }
    };
}

// ─── copy!(dst, src) — element copy, returns int ──────────────────────

/// `copy!(dst, src)` — copies `min(len(dst), len(src))` elements from
/// `src` into `dst`, returning the count as `int`. `dst` and `src` may
/// be `&mut slice<T>` and `&slice<T>` (or any slices that deref to
/// `[T]`). The macro takes them by name to avoid leaking `&mut` syntax
/// at the call site.
#[macro_export]
macro_rules! copy {
    ($dst:expr, $src:expr) => {{
        let __dst: &mut [_] = &mut $dst;
        let __src: &[_] = &$src;
        let __n = ::core::cmp::min(__dst.len(), __src.len());
        __dst[..__n].clone_from_slice(&__src[..__n]);
        __n as $crate::int
    }};
}

// ─── delete!(m, k) — Go's `delete(m, k)` builtin ──────────────────────

/// `delete!(m, k)` — remove key `k` from map `m`. Mirrors Go's
/// `delete(m, k)`. The macro takes `m` by name and applies `&mut`
/// internally to keep the call site bare.
#[macro_export]
macro_rules! delete {
    ($m:expr, $k:expr) => {{
        let __m = &mut $m;
        __m.Delete($k);
    }};
}
