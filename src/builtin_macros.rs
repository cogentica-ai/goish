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
    // make!(chan T) — unbuffered channel.
    (chan $t:ty) => {
        $crate::gochan::chan::<$t>::new_unbuffered()
    };
    // make!(chan T, cap) — buffered channel.
    (chan $t:ty, $cap:expr) => {
        $crate::gochan::chan::<$t>::new_buffered($crate::builtin::__make_size($cap))
    };
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

// ─── array!([N]T) / array!([N]T{...}) / array!([...]T{...}) ─────────
//
// Go's fixed-array composite literal forms, ported to a single macro.
// Note that `array!` covers what `make!` does NOT — Go's `make` rejects
// array types (only slice/map/chan), and `array!` mirrors that split.
//
//   var a [12]byte                 → let a = array!([12]byte);
//   a := [3]int{1, 2, 3}           → let a = array!([3]int{1, 2, 3});
//   a := [6]int{1, 2, 3, 5}        → let a = array!([6]int{1, 2, 3, 5});  // rest zero
//   a := [...]int{1, 2, 3}         → let a = array!([...]int{1, 2, 3});   // length inferred
//
// In **type position** users write `array<T, N>` directly — Rust macros
// can't appear in type slots, same as the `slice<T>` / `slice!` split.
// Sparse-keyed form `[N]T{2: 99}` is deferred (rare; can be added as a
// new arm without breaking the existing ones).

/// `array!([N]T)` — zero-valued fixed array of length `N`. Mirrors Go's
/// `var a [N]T` / `[N]T{}`. Requires `T: Default`.
///
/// `array!([N]T{e1, e2, ...})` — full or partial composite literal.
/// Trailing elements (if fewer than `N`) are zero-filled, matching Go.
///
/// `array!([...]T{e1, e2, ...})` — length inferred from the element
/// count. Mirrors Go's `[...]T{...}`.
#[macro_export]
macro_rules! array {
    // [...]T{e1, e2, ...} — length inferred from element count
    ([...] $t:ty { $($e:expr),* $(,)? }) => {{
        let __raw: [$t; $crate::__count_exprs!($($e),*)] = [
            $( <$t as ::core::convert::From<_>>::from($e) ),*
        ];
        $crate::goarray::array::__from_arr(__raw)
    }};
    // [N]T{} — empty literal == zero array
    ([$n:expr] $t:ty { $(,)? }) => {{
        let __a: $crate::goarray::array<$t, { $n }> =
            <$crate::goarray::array<$t, { $n }> as ::core::default::Default>::default();
        __a
    }};
    // [N]T{e1, e2, ...} — full or partial literal (rest zero-filled)
    ([$n:expr] $t:ty { $($e:expr),+ $(,)? }) => {{
        let mut __a: $crate::goarray::array<$t, { $n }> =
            <$crate::goarray::array<$t, { $n }> as ::core::default::Default>::default();
        let mut __i: $crate::int = 0;
        $(
            __a[__i] = <$t as ::core::convert::From<_>>::from($e);
            __i += 1;
        )+
        let _ = __i;
        __a
    }};
    // [N]T — bare type, zero-valued (Go: `var a [N]T`)
    ([$n:expr] $t:ty) => {{
        let __a: $crate::goarray::array<$t, { $n }> =
            <$crate::goarray::array<$t, { $n }> as ::core::default::Default>::default();
        __a
    }};
}

/// Internal helper for `array!([...]T{...})` — counts repetition tokens
/// at compile time so the result can be used as a const-generic `N`.
#[macro_export]
#[doc(hidden)]
macro_rules! __count_exprs {
    () => { 0usize };
    ($head:expr $(, $tail:expr)*) => { 1usize + $crate::__count_exprs!($($tail),*) };
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
    // Public entry. Tail-recurse through `__append_dispatch` to detect
    // a trailing `...` spread terminator anywhere in the input — Go's
    // `append(s, other...)` lowers verbatim to `append!(s, other...)`,
    // exactly mirroring the Go source.
    //
    // Why the muncher: Rust's macro grammar restricts what can follow
    // a `:expr` fragment to `=>`, `,`, or `;` — the literal `...`
    // token is rejected. So we slurp the rest as a stream of
    // `:tt` token-trees and decide based on the final token.
    ($s:expr, $($rest:tt)+) => {
        $crate::__append_dispatch!(($s) () $($rest)+)
    };
    // Single-arg call: just hand back the slice unchanged.
    ($s:expr $(,)?) => { $s };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __append_dispatch {
    // Spread terminator: input ends with literal `...`. Accumulator
    // holds the spread source as a single token-tree stream that
    // re-parses as one expression (`other`, `nested.errors`, …).
    (($s:expr) ($($acc:tt)+) ...) => {
        {
            let mut __v = $crate::slice::__into_vec($s);
            for __e in ($($acc)+).iter() {
                __v.push(__e.clone().into());
            }
            $crate::slice::__from_vec(__v)
        }
    };
    // Slurp one more token into the accumulator and recurse.
    (($s:expr) ($($acc:tt)*) $head:tt $($tail:tt)*) => {
        $crate::__append_dispatch!(($s) ($($acc)* $head) $($tail)*)
    };
    // Exhausted input with no spread `...` — accumulator is a
    // comma-separated list of expressions. Hand off to the per-element
    // pusher.
    (($s:expr) ($($acc:tt)+)) => {
        {
            let mut __v = $crate::slice::__into_vec($s);
            $crate::__append_push_each!(__v, $($acc)+ ,);
            $crate::slice::__from_vec(__v)
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __append_push_each {
    ($v:ident, $head:expr, $($rest:tt)*) => {
        $v.push(($head).into());
        $crate::__append_push_each!($v, $($rest)*);
    };
    ($v:ident,) => {};
    ($v:ident) => {};
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

// ─── go!(closure) — spawn a goroutine ────────────────────────────────

/// `go!(closure)` — Go's `go f()` statement. Schedules `closure` to
/// run as a new goroutine; returns immediately. The closure runs
/// when the scheduler dispatches it (cooperatively, on yield points
/// or after main returns).
///
/// Examples:
///
///   go!(|| {
///       println!("from a goroutine");
///   });
///
///   let x = 42;
///   go!(move || {
///       println!("captured x = {}", x);
///   });
/// Three forms (M28):
///
///   go!(|| work());                              // 2 KiB FIXED, no grow
///   go!(8 * KB, || tiny_helper());               // 8 KiB FIXED, no grow
///   go!(stack(2 * KB), || tiny_helper());        // 2 KiB FIXED, no grow (alias)
///
/// **No automatic growth in the macro.** This preserves the dense
/// memory model for 1M-goroutines workloads (every goroutine costs
/// only its carved stack, no mmap-per-G overhead) AND keeps every
/// goroutine on a single stack region — channel-park / Gosched
/// flows are unconditional safe regardless of the goroutine's
/// stack size.
///
/// **For deep recursion** that wouldn't fit in a fixed stack, call
/// `runtime::sched::maybe_grow(red_zone, size, || body)` explicitly
/// at the recursion site (mirrors how `stacker::maybe_grow` is used
/// in the Rust ecosystem). Avoid blocking I/O / channel ops from
/// inside the borrowed region.
///
/// `KB` / `MB` / `GB` are exported at the crate root. Sizes are
/// rounded up to the nearest 4 KiB page.
#[macro_export]
macro_rules! go {
    // Back-compat: `go!(stack(N), || body)`.
    (stack($size:expr), $closure:expr) => {{
        $crate::runtime::sched::newproc_with_stack(
            $size,
            $crate::__macro_alloc::Box::new($closure),
        );
    }};
    // Positional sized form: `go!(N, || body)`.
    ($size:expr, $closure:expr) => {{
        $crate::runtime::sched::newproc_with_stack(
            $size,
            $crate::__macro_alloc::Box::new($closure),
        );
    }};
    // Bare form: default-sized (2 KiB) stack, no grow.
    ($closure:expr) => {{
        $crate::runtime::sched::newproc(
            $crate::__macro_alloc::Box::new($closure),
        );
    }};
}

// ─── close!(ch) — close a channel ────────────────────────────────────

/// `close!(ch)` — Go's `close(ch)`. Closes the channel: parked
/// receivers wake with `(zero, false)`, parked senders panic, and
/// future operations behave per Go's semantics. Panics if `ch` is
/// already closed.
#[macro_export]
macro_rules! close {
    ($ch:expr) => {{
        ($ch).Close()
    }};
}

// ─── new!(T) — zero-valued T ─────────────────────────────────────────

/// `new!(T)` — Go's `new(T)`. Returns the zero value of `T`. In Go this
/// is `*T` (heap pointer); in Goish, methods auto-borrow `&self` /
/// `&mut self`, so the value-shape suffices and the call site reads the
/// same:
///
///   p := new(Counter)        →  let mut p = new!(Counter);
///   p.Increment()            →  p.Increment();
///
/// Requires `T: Default`. Goish primitives (`int`, `string`,
/// `slice<T>`, `map<K,V>`, `error`, …) all implement `Default`.
#[macro_export]
macro_rules! new {
    ($t:ty) => {
        <$t as ::core::default::Default>::default()
    };
}

// ─── goish::var! — package-level declaration block ──────────────────
//
// Mirrors Go's `var` (single-line and block forms). Per-decl dispatch:
//
//   pub EOF: error = "EOF";              → identity-stable lazy sentinel
//                                           (ZST + cached Arc, see
//                                           goish-macros::var_emit_error_marker)
//   pub MaxBuf: int = 4096;              → pub const MaxBuf: int = 4096;
//
// Use sites:
//   errors::Is(err, EOF)        // bare-symbol target
//   if err == EOF { ... }       // bare PartialEq
//   let e: error = EOF.into();  // From<Marker> for error
//
// See DISCUSSION_VAR.md for the doctrine choice and trade-offs.

#[macro_export]
macro_rules! var {
    ( $($decl:tt)* ) => { $crate::__var_munch!( $($decl)* ); };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __var_munch {
    // Base case — no more declarations.
    () => {};

    // ── error sentinel: string-literal payload ─────────────────────
    (
        $(#[$attr:meta])*
        $vis:vis $name:ident : error = $msg:literal ;
        $($rest:tt)*
    ) => {
        $(#[$attr])*
        $crate::__var_emit_error_marker!( $vis $name $msg );
        $crate::__var_munch!( $($rest)* );
    };

    // ── error sentinel: typed-payload (brace-grouped expr) ─────────
    //
    // Token-tree-bounded so the proc-macro receives a clean group; the
    // user writes `{ MyError { … } }` to disambiguate from string lit.
    (
        $(#[$attr:meta])*
        $vis:vis $name:ident : error = { $($expr:tt)* } ;
        $($rest:tt)*
    ) => {
        $(#[$attr])*
        $crate::__var_emit_error_marker!( $vis $name { $($expr)* } );
        $crate::__var_munch!( $($rest)* );
    };

    // ── plain const fallback ───────────────────────────────────────
    (
        $(#[$attr:meta])*
        $vis:vis $name:ident : $ty:ty = $val:expr ;
        $($rest:tt)*
    ) => {
        $(#[$attr])*
        $vis const $name: $ty = $val;
        $crate::__var_munch!( $($rest)* );
    };
}
