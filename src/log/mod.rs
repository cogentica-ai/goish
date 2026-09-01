// go: package log
//
// log — Go's `log` package.
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   log.Println("starting", n)           log::Println!("starting", n);
//   log.Printf("count=%d\n", n)          log::Printf!("count=%d\n", n);
//   log.Fatal("oops", err)               log::Fatal!("oops", err);
//
// Module root: one `.rs` per Go `.go`, the `pub use` surface, and the
// user-facing macros (which are `#[macro_export]`ed at the crate root
// and re-exported here so callers write `log::Println!`).
//
//   log.rs   log/log.go   — the Logger, the flags, the standard logger
//                            and the Print/Fatal/Panic families
//
// v1 differences from Go semantics:
//
//   * There is no `runtime.Caller`, so `Lshortfile`/`Llongfile` render
//     the file as "???" and the line as 0.
//   * `Logger.Writer()` is not exposed — the output is held behind a
//     Mutex and handing it out would escape that.

#![allow(non_snake_case)]

pub mod slog;

#[path = "log.rs"]
mod log;
pub use log::*;

// ─── Macros (path-resolved as log::Println! etc.) ─────────────────────

#[macro_export]
#[doc(hidden)]
macro_rules! __goish_log_println {
    ($($arg:expr),* $(,)?) => {
        $crate::log::println_impl($crate::__fmt_args!($($arg),*))
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __goish_log_printf {
    ($fmt:expr $(, $arg:expr)* $(,)?) => {
        $crate::log::printf_impl(($fmt).as_bytes(), $crate::__fmt_args!($($arg),*))
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __goish_log_fatal {
    ($($arg:expr),* $(,)?) => {
        $crate::log::fatal_impl($crate::__fmt_args!($($arg),*))
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __goish_log_fatalf {
    ($fmt:expr $(, $arg:expr)* $(,)?) => {
        $crate::log::fatalf_impl(($fmt).as_bytes(), $crate::__fmt_args!($($arg),*))
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __goish_log_print {
    ($($arg:expr),* $(,)?) => {
        $crate::log::print_impl($crate::__fmt_args!($($arg),*))
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __goish_log_fatalln {
    ($($arg:expr),* $(,)?) => {
        $crate::log::fatalln_impl($crate::__fmt_args!($($arg),*))
    };
}

pub use crate::__goish_log_fatal as Fatal;
pub use crate::__goish_log_fatalf as Fatalf;
pub use crate::__goish_log_fatalln as Fatalln;
pub use crate::__goish_log_print as Print;
pub use crate::__goish_log_printf as Printf;
pub use crate::__goish_log_println as Println;
