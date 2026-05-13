// log — Go's `log` package, ported. Default logger writes to Stderr
// with a `YYYY/MM/DD HH:MM:SS ` prefix.
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   log.Println("starting", n)           log::Println!("starting", n);
//   log.Printf("count=%d\n", n)          log::Printf!("count=%d\n", n);
//   log.Fatal("oops", err)               log::Fatal!("oops", err);
//   log.Fatalf("die: %v\n", err)         log::Fatalf!("die: %v\n", err);
//
// v1 deviations from Go:
//   * Output is always Stderr; no SetOutput / SetFlags / SetPrefix.
//   * Default flags are date+time (Go's `log.LstdFlags`); no microseconds,
//     UTC, file:line, level prefix.
//   * log.Panic{f,ln} deferred (panic=abort makes recovery moot).

#![allow(non_snake_case)]

pub mod slog;

extern crate alloc;
use alloc::vec::Vec;

use crate::fmt;
use crate::io::Writer as _;
use crate::os;
use crate::time;
use crate::types::{byte, int};

// Internal — used only by `write_prefix_to_stderr` below. The `Vec`
// parameter is a per-call scratch buffer that never crosses the
// module boundary, so it doesn't violate the public-API rule
// against Rust container types.
pub(crate) fn write_prefix(buf: &mut Vec<byte>) {
    let t = time::Now();
    let (y, m, d) = t.Date();
    let (hh, mm, ss) = t.Clock();
    push_int_pad(buf, y, 4);
    buf.push(b'/');
    push_int_pad(buf, m, 2);
    buf.push(b'/');
    push_int_pad(buf, d, 2);
    buf.push(b' ');
    push_int_pad(buf, hh, 2);
    buf.push(b':');
    push_int_pad(buf, mm, 2);
    buf.push(b':');
    push_int_pad(buf, ss, 2);
    buf.push(b' ');
}

fn push_int_pad(buf: &mut Vec<byte>, n: int, width: usize) {
    let mut tmp = [0u8; 20];
    let mut idx = tmp.len();
    let mut v = if n < 0 { (-n) as u64 } else { n as u64 };
    if v == 0 {
        idx -= 1;
        tmp[idx] = b'0';
    } else {
        while v > 0 {
            idx -= 1;
            tmp[idx] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    }
    let digits = tmp.len() - idx;
    for _ in digits..width {
        buf.push(b'0');
    }
    buf.extend_from_slice(&tmp[idx..]);
}

fn write_prefix_to_stderr() {
    let mut buf: Vec<byte> = Vec::with_capacity(20);
    write_prefix(&mut buf);
    let mut e = os::Stderr();
    let _ = e.Write(crate::goslice::slice::__from_vec(buf));
}

#[doc(hidden)]
pub fn println_impl(args: &[fmt::FmtArg]) {
    write_prefix_to_stderr();
    let mut e = os::Stderr();
    let _ = fmt::fprintln_impl(&mut e, args);
}

#[doc(hidden)]
pub fn printf_impl(format: &[byte], args: &[fmt::FmtArg]) {
    write_prefix_to_stderr();
    let mut e = os::Stderr();
    let _ = fmt::fprintf_impl(&mut e, format, args);
}

#[doc(hidden)]
pub fn print_impl(args: &[fmt::FmtArg]) {
    // Go: log.Print (log.go:399) — std.output(0, 2, fmt.Append(b, v...))
    //     output() ensures a trailing newline if the appended bytes
    //     don't already end in one.
    write_prefix_to_stderr();
    let mut e = os::Stderr();
    // Go: fmt.Append behavior — concatenate args with default %v, no
    // separators or trailing newline. Reuse fmt::sprint_impl for the
    // body, then append a newline if missing.
    let body = fmt::sprint_impl(args);
    let body_bytes = body.as_bytes();
    let mut buf: Vec<byte> = Vec::with_capacity(body_bytes.len() + 1);
    buf.extend_from_slice(body_bytes);
    // Go: if len(*buf) == 0 || (*buf)[len(*buf)-1] != '\n' { *buf = append(*buf, '\n') }
    if buf.is_empty() || *buf.last().unwrap() != b'\n' {
        buf.push(b'\n');
    }
    let _ = e.Write(crate::goslice::slice::__from_vec(buf));
}

#[doc(hidden)]
pub fn fatal_impl(args: &[fmt::FmtArg]) -> ! {
    println_impl(args);
    os::Exit(1);
}

#[doc(hidden)]
pub fn fatalf_impl(format: &[byte], args: &[fmt::FmtArg]) -> ! {
    printf_impl(format, args);
    os::Exit(1);
}

#[doc(hidden)]
pub fn fatalln_impl(args: &[fmt::FmtArg]) -> ! {
    // Go: log.Fatalln (log.go:438) — Println followed by os.Exit(1).
    println_impl(args);
    os::Exit(1);
}

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
