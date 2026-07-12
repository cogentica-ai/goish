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
    let e = os::Stderr();
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
    let e = os::Stderr();
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

// ─── Logger (Go's log.Logger) ─────────────────────────────────────────
//
// Ported from Go SDK log/log.go. A Logger writes lines to an io.Writer,
// serializing access through a mutex. The flag bits below control the
// header prefixed to each line.
//
// KNOWN DIVERGENCE: goish has no `runtime.Caller`, so the Lshortfile /
// Llongfile flags cannot recover the caller's file:line. Output therefore
// always takes Go's own caller-failure fallback (file = "???", line = 0),
// rendering "???:0: " when either flag is set. Date/Time/Microseconds and
// the prefix are fully faithful.

use crate::gostring::string;
use crate::goslice::slice;
use crate::sync::Mutex;
use crate::errors::error;
use alloc::boxed::Box;

/// the date in the local time zone: 2009/01/23
pub const Ldate: int = 1 << 0;
/// the time in the local time zone: 01:23:23
pub const Ltime: int = 1 << 1;
/// microsecond resolution: 01:23:23.123123.  assumes Ltime.
pub const Lmicroseconds: int = 1 << 2;
/// full file name and line number: /a/b/c/d.go:23
pub const Llongfile: int = 1 << 3;
/// final file name element and line number: d.go:23. overrides Llongfile
pub const Lshortfile: int = 1 << 4;
/// if Ldate or Ltime is set, use UTC rather than the local time zone
pub const LUTC: int = 1 << 5;
/// move the "prefix" from the beginning of the line to before the message
pub const Lmsgprefix: int = 1 << 6;
/// initial values for the standard logger
pub const LstdFlags: int = Ldate | Ltime;

struct LoggerInner {
    prefix: string,
    flag: int,
    out: Box<dyn crate::io::Writer + Send + Sync>,
}

/// A Logger represents an active logging object that generates lines of
/// output to an io.Writer. (Go: log.Logger.)
pub struct Logger {
    inner: Mutex<LoggerInner>,
}

/// New creates a new Logger writing to `out`, with the given line `prefix`
/// and `flag` properties. (Go: log.New, log.go:60.)
pub fn New<S: Into<string>>(
    out: Box<dyn crate::io::Writer + Send + Sync>,
    prefix: S,
    flag: int,
) -> Logger {
    Logger {
        inner: Mutex::new(LoggerInner {
            prefix: prefix.into(),
            flag,
            out,
        }),
    }
}

// Cheap integer to fixed-width decimal ASCII (Go: log.go:itoa). A negative
// width avoids zero-padding.
fn itoa(buf: &mut Vec<byte>, mut i: int, mut wid: int) {
    let mut b = [0u8; 20];
    let mut bp = b.len() - 1;
    while i >= 10 || wid > 1 {
        wid -= 1;
        let q = i / 10;
        b[bp] = b'0' + (i - q * 10) as u8;
        bp -= 1;
        i = q;
    }
    b[bp] = b'0' + i as u8;
    buf.extend_from_slice(&b[bp..]);
}

impl LoggerInner {
    // Go: (*Logger).formatHeader, log.go:115.
    fn format_header(&self, buf: &mut Vec<byte>, t: time::Time, file: &str, line: int) {
        if self.flag & Lmsgprefix == 0 {
            buf.extend_from_slice(self.prefix.as_bytes());
        }
        if self.flag & (Ldate | Ltime | Lmicroseconds) != 0 {
            let t = if self.flag & LUTC != 0 { t.UTC() } else { t };
            if self.flag & Ldate != 0 {
                let (year, month, day) = t.Date();
                itoa(buf, year, 4);
                buf.push(b'/');
                itoa(buf, month, 2);
                buf.push(b'/');
                itoa(buf, day, 2);
                buf.push(b' ');
            }
            if self.flag & (Ltime | Lmicroseconds) != 0 {
                let (hour, min, sec) = t.Clock();
                itoa(buf, hour, 2);
                buf.push(b':');
                itoa(buf, min, 2);
                buf.push(b':');
                itoa(buf, sec, 2);
                if self.flag & Lmicroseconds != 0 {
                    buf.push(b'.');
                    itoa(buf, t.Nanosecond() / 1000, 6);
                }
                buf.push(b' ');
            }
        }
        if self.flag & (Lshortfile | Llongfile) != 0 {
            // KNOWN DIVERGENCE: no runtime.Caller — `file` is always "???".
            let short = if self.flag & Lshortfile != 0 {
                let bytes = file.as_bytes();
                let mut s = file;
                let mut i = bytes.len();
                while i > 0 {
                    i -= 1;
                    if i == 0 {
                        break;
                    }
                    if bytes[i] == b'/' {
                        s = &file[i + 1..];
                        break;
                    }
                }
                s
            } else {
                file
            };
            buf.extend_from_slice(short.as_bytes());
            buf.push(b':');
            itoa(buf, line, -1);
            buf.extend_from_slice(b": ");
        }
        if self.flag & Lmsgprefix != 0 {
            buf.extend_from_slice(self.prefix.as_bytes());
        }
    }
}

impl Logger {
    /// Output writes the output for a logging event. (Go: log.go:140.)
    /// `calldepth` is accepted for API compatibility; goish has no
    /// runtime.Caller so it is unused.
    pub fn Output<S: Into<string>>(&self, _calldepth: int, s: S) -> error {
        let s = s.into();
        let now = time::Now();
        let mut g = self.inner.Lock();
        let (file, line): (&str, int) =
            if g.flag & (Lshortfile | Llongfile) != 0 { ("???", 0) } else { ("", 0) };
        let mut buf: Vec<byte> = Vec::new();
        g.format_header(&mut buf, now, file, line);
        let sb = s.as_bytes();
        buf.extend_from_slice(sb);
        if sb.is_empty() || *buf.last().unwrap() != b'\n' {
            buf.push(b'\n');
        }
        let (_, err) = g.out.Write(slice::__from_vec(buf));
        err
    }

    /// SetOutput sets the destination for the logger. (Go: log.go:73.)
    pub fn SetOutput(&self, w: Box<dyn crate::io::Writer + Send + Sync>) {
        self.inner.Lock().out = w;
    }

    /// Flags returns the output flags for the logger. (Go: log.go:436.)
    pub fn Flags(&self) -> int {
        self.inner.Lock().flag
    }

    /// SetFlags sets the output flags for the logger. (Go: log.go:444.)
    pub fn SetFlags(&self, flag: int) {
        self.inner.Lock().flag = flag;
    }

    /// Prefix returns the output prefix for the logger. (Go: log.go:451.)
    pub fn Prefix(&self) -> string {
        self.inner.Lock().prefix.clone()
    }

    /// SetPrefix sets the output prefix for the logger. (Go: log.go:459.)
    pub fn SetPrefix<S: Into<string>>(&self, prefix: S) {
        self.inner.Lock().prefix = prefix.into();
    }

    /// Print calls Output to print to the logger. (Go: log.go:212.)
    pub fn Print(&self, args: slice<crate::Any>) {
        let _ = self.Output(2, fmt::Sprint(args));
    }

    /// Printf calls Output to print to the logger. (Go: log.go:203.)
    pub fn Printf<S: Into<string>>(&self, format: S, args: slice<crate::Any>) {
        let _ = self.Output(2, fmt::Sprintv(format.into(), args));
    }
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
