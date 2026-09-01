// go: package fmt
//
// fmt — Go's `fmt` package.
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   fmt.Println("hi", x)                  fmt::Println!("hi", x)
//   fmt.Printf("%d items\n", n)           fmt::Printf!("%d items\n", n)
//   s := fmt.Sprintf("%.2f", pi)          let s = fmt::Sprintf!("%.2f", pi);
//   fmt.Fprintf(w, "%s\n", n)             fmt::Fprintf!(w, "%s\n", n);
//   err := fmt.Errorf("bad: %w", e)       let err = fmt::Errorf!("bad: %w", e);
//
// Module root: one `.rs` per Go `.go`, the `pub use` surface, and the
// user-facing macros — which are `#[macro_export]`ed at the crate root
// and re-exported here so callers write `fmt::Println!`.
//
//   print.rs   fmt/print.go   — the Stringer/Formatter/State traits,
//                                the output buffer, the printer, and
//                                every Print/Sprint/Fprint entry point
//   format.rs  fmt/format.go  — the per-verb formatters
//   scan.rs    fmt/scan.go    — Sscan, Sscanf
//   errors.rs  fmt/errors.go  — Errorf and the errors it wraps
//
// Argument dispatch uses the autoref-spec trick (see `__fmt_arg`) so a
// single macro call site picks the right `FmtArg` variant per argument
// type at compile time:
//
//   - `error`           → FmtArg::Err      (carries the typed err for %w)
//   - any T: Stringer   → FmtArg::Stringer (calls T::String())
//   - any T: Format     → FmtArg::Val
//
// v1 differences from Go semantics:
//
//   * The '#' flag is not parsed at all, so `%#v` and `%#q` are junk.
//   * Formatter/State are declared but the printer does not dispatch
//     through them; a type customises its rendering by implementing
//     `Format` instead.

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;

#[path = "print.rs"]
mod print;
pub use print::*;

#[path = "format.rs"]
mod format;

#[path = "scan.rs"]
mod scan;
pub use scan::*;

#[path = "errors.rs"]
mod errors_go;
pub use errors_go::*;

// ─── User-facing macros ───────────────────────────────────────────────

/// Helper: collect args into a `&[FmtArg]` literal via autoref-spec.
#[macro_export]
#[doc(hidden)]
macro_rules! __fmt_args {
    ($($arg:expr),* $(,)?) => {
        &[ $( {
            use $crate::fmt::__fmt_arg::*;
            (Wrap(&$arg)).fmt_arg()
        } ),* ]
    };
}

/// `fmt::Println!(args...)` — print args separated by spaces, newline appended.
#[macro_export]
macro_rules! Println {
    ($($arg:expr),* $(,)?) => {
        $crate::fmt::println_impl($crate::__fmt_args!($($arg),*))
    };
}

/// `fmt::Print!(args...)` — concatenate (no newline).
#[macro_export]
macro_rules! Print {
    ($($arg:expr),* $(,)?) => {
        $crate::fmt::print_impl($crate::__fmt_args!($($arg),*))
    };
}

/// `fmt::Printf!(format, args...)` — formatted print to stdout.
#[macro_export]
macro_rules! Printf {
    ($fmt:expr $(, $arg:expr)* $(,)?) => {
        $crate::fmt::printf_impl(($fmt).as_bytes(), $crate::__fmt_args!($($arg),*))
    };
}

/// `fmt::Sprintf!(format, args...)` — return the formatted string.
#[macro_export]
macro_rules! Sprintf {
    ($fmt:expr $(, $arg:expr)* $(,)?) => {
        $crate::fmt::sprintf_impl(($fmt).as_bytes(), $crate::__fmt_args!($($arg),*))
    };
}

/// `fmt::Sprint!(args...)` — return the concatenated default-format string.
/// Mirrors `fmt.Sprint` (print.go:267).
#[macro_export]
macro_rules! Sprint {
    ($($arg:expr),* $(,)?) => {
        $crate::fmt::sprint_impl($crate::__fmt_args!($($arg),*))
    };
}

/// `fmt::Sprintln!(args...)` — return the default-format string with
/// spaces between args and a trailing newline. Mirrors `fmt.Sprintln`
/// (print.go:283).
#[macro_export]
macro_rules! Sprintln {
    ($($arg:expr),* $(,)?) => {
        $crate::fmt::sprintln_impl($crate::__fmt_args!($($arg),*))
    };
}

/// `fmt::Fprintf!(w, format, args...)` — formatted print to writer.
#[macro_export]
macro_rules! Fprintf {
    ($w:expr, $fmt:expr $(, $arg:expr)* $(,)?) => {
        $crate::fmt::fprintf_impl(&mut $w, ($fmt).as_bytes(), $crate::__fmt_args!($($arg),*))
    };
}

/// `fmt::Fprintln!(w, args...)` — println on writer.
#[macro_export]
macro_rules! Fprintln {
    ($w:expr $(, $arg:expr)* $(,)?) => {
        $crate::fmt::fprintln_impl(&mut $w, $crate::__fmt_args!($($arg),*))
    };
}

/// `fmt::Eprintln!(args...)` — Println on stderr (goish convenience).
#[macro_export]
macro_rules! Eprintln {
    ($($arg:expr),* $(,)?) => {{
        let mut __e = $crate::os::Stderr();
        $crate::fmt::fprintln_impl(&mut __e, $crate::__fmt_args!($($arg),*))
    }};
}

/// `fmt::Errorf!(format, args...)` — like Sprintf but returns `error`,
/// with `%w` capturing an inner error for `errors::Is` / `Unwrap`.
#[macro_export]
macro_rules! Errorf {
    ($fmt:expr $(, $arg:expr)* $(,)?) => {
        $crate::fmt::errorf_impl(($fmt).as_bytes(), $crate::__fmt_args!($($arg),*))
    };
}

// ─── Re-export macros under `fmt::` so callers write `fmt::Println!` ──
//
// `#[macro_export]` only registers macros at the crate root, but Go's
// idiom is `fmt.Println(...)` → `fmt::Println!(...)`. Re-exporting here
// makes the qualified path work: `use goish::fmt; fmt::Println!(…)`.
pub use crate::{
    Eprintln, Errorf, Fprintf, Fprintln, Print, Printf, Println, Sprint, Sprintf, Sprintln,
};
