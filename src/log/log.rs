// go: file log/log.go decls: formatHeader, Println, Printf, Print, Fatal, Fatalf, Fatalln, New, Default, SetOutput, Flags, SetFlags, Prefix, SetPrefix, Output, itoa, formatHeader, Logger.Output, Logger.SetOutput, Logger.Flags, Logger.SetFlags, Logger.Prefix, Logger.SetPrefix, Logger.Print, Logger.Printf, Logger.Println, Logger.Fatal, Logger.Fatalf, Logger.Fatalln, Logger.Panic, Logger.Panicf, Logger.Panicln
// goishlint:ignore GOISH018 getBuffer, putBuffer, init, Writer — Go
// pools the header buffer through a sync.Pool (`bufferPool`,
// `getBuffer`, `putBuffer`, and the `init` that seeds it); goish
// allocates one per Output call, which is the same output at a
// different cost. `Writer` hands the destination io.Writer back out;
// goish holds it behind a Mutex, and handing it out would escape that.
// goishlint:ignore GOISH021 bufferPool — same.
//
// log.go — the Logger, its flags and header format, the standard
// logger every package-level function writes through, and the
// Print/Fatal/Panic families.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::convert::byte as tobyte;
use crate::fmt;
use crate::os;
use crate::time;
use crate::types::{byte, int};

// go: sdk 1.25.5 log/log.go:415-419 Println
/// `log.Println` — Print to the standard logger. Arguments are handled
/// in the manner of `fmt::Println`.
// goishlint:ignore GOISH014 println_impl — the anchor names Go's
// `Println`; goish spells the caller-facing half as a macro, so the
// Rust function that carries the body cannot take that name.
#[doc(hidden)]
pub fn println_impl(args: &[fmt::FmtArg]) {
    // Go: log.Println (log.go line 407) — std.Output(2, fmt.Sprintln(v...)).
    let _ = STD.get().Output(2, fmt::sprintln_impl(args));
}

// go: sdk 1.25.5 log/log.go:407-411 Printf
// goishlint:ignore GOISH014 printf_impl — see the note on
// `println_impl`.
#[doc(hidden)]
pub fn printf_impl(format: &[byte], args: &[fmt::FmtArg]) {
    // Go: log.Printf (log.go line 400) — std.Output(2, fmt.Sprintf(...)).
    // Output supplies the trailing newline, which goish's old
    // straight-to-Stderr path did not: `log.Printf("x=%d", 7)` came out
    // with no newline at all.
    let _ = STD.get().Output(2, fmt::sprintf_impl(format, args));
}

// go: sdk 1.25.5 log/log.go:399-403 Print
// goishlint:ignore GOISH014 print_impl — see the note on
// `println_impl`.
#[doc(hidden)]
pub fn print_impl(args: &[fmt::FmtArg]) {
    // Go: log.Print (log.go line 394) — std.Output(2, fmt.Sprint(v...)).
    let _ = STD.get().Output(2, fmt::sprint_impl(args));
}

// go: sdk 1.25.5 log/log.go:422-427 Fatal
// goishlint:ignore GOISH014 fatal_impl — see the note on
// `println_impl`.
#[doc(hidden)]
pub fn fatal_impl(args: &[fmt::FmtArg]) -> ! {
    // Go: log.Fatal (log.go line 414) — Print then os.Exit(1).
    print_impl(args);
    os::Exit(1);
}

// go: sdk 1.25.5 log/log.go:430-435 Fatalf
// goishlint:ignore GOISH014 fatalf_impl — see the note on
// `println_impl`.
#[doc(hidden)]
pub fn fatalf_impl(format: &[byte], args: &[fmt::FmtArg]) -> ! {
    printf_impl(format, args);
    os::Exit(1);
}

// go: sdk 1.25.5 log/log.go:438-443 Fatalln
// goishlint:ignore GOISH014 fatalln_impl — see the note on
// `println_impl`.
#[doc(hidden)]
pub fn fatalln_impl(args: &[fmt::FmtArg]) -> ! {
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

use crate::errors::error;
use crate::goslice::slice;
use crate::gostring::string;
use crate::sync::Mutex;
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

// go: sdk 1.25.5 log/log.go:71-77 New
/// New creates a new Logger writing to `out`, with the given line `prefix`
/// and `flag` properties. (Go: log.New, log.go:60.)
pub fn New<S: Into<string>>(
    out: Box<dyn crate::io::Writer + Send + Sync>,
    prefix: S,
    flag: int,
) -> Logger {
    return Logger {
        inner: Mutex::new(LoggerInner {
            prefix: prefix.into(),
            flag,
            out,
        }),
    };
}

/// Go's `std` — the standard logger, which every package-level
/// function writes through. goish's package-level Print family used to
/// write a hard-coded `YYYY/MM/DD HH:MM:SS ` header straight to
/// Stderr, so `SetFlags`, `SetPrefix` and `SetOutput` could not reach
/// it: there was nothing to reach.
static STD: crate::lazy::Lazy<Logger> =
    crate::lazy::Lazy::new(|| New(Box::new(os::Stderr()), "", LstdFlags));

// go: sdk 1.25.5 log/log.go:90-90 Default
/// `log.Default()` — the standard logger used by the package-level
/// output functions.
pub fn Default() -> &'static Logger {
    return STD.get();
}

// go: sdk 1.25.5 log/log.go:361-367 SetOutput
/// `log.SetOutput` — set the output destination for the standard logger.
pub fn SetOutput(w: Box<dyn crate::io::Writer + Send + Sync>) {
    STD.get().SetOutput(w);
}

// go: sdk 1.25.5 log/log.go:369-372 Flags
/// `log.Flags` — the output flags for the standard logger.
pub fn Flags() -> int {
    return STD.get().Flags();
}

// go: sdk 1.25.5 log/log.go:374-377 SetFlags
/// `log.SetFlags` — set the output flags for the standard logger.
pub fn SetFlags(flag: int) {
    STD.get().SetFlags(flag);
}

// go: sdk 1.25.5 log/log.go:379-382 Prefix
/// `log.Prefix` — the output prefix for the standard logger.
pub fn Prefix() -> string {
    return STD.get().Prefix();
}

// go: sdk 1.25.5 log/log.go:384-387 SetPrefix
/// `log.SetPrefix` — set the output prefix for the standard logger.
pub fn SetPrefix<S: Into<string>>(prefix: S) {
    STD.get().SetPrefix(prefix);
}

// go: sdk 1.25.5 log/log.go:475-482 Output
/// `log.Output` — write the output for a logging event through the
/// standard logger.
pub fn Output<S: Into<string>>(calldepth: int, s: S) -> error {
    return STD.get().Output(calldepth + 1, s);
}

// go: sdk 1.25.5 log/log.go:93-107 itoa
// Cheap integer to fixed-width decimal ASCII (Go: log.go itoa). A negative
// width avoids zero-padding.
fn itoa(buf: &mut Vec<byte>, mut i: int, mut wid: int) {
    let mut b = [0u8; 20];
    let mut bp = b.len() - 1;
    while i >= 10 || wid > 1 {
        wid -= 1;
        let q = i / 10;
        b[bp] = b'0' + tobyte(i - q * 10);
        bp -= 1;
        i = q;
    }
    b[bp] = b'0' + tobyte(i);
    buf.extend_from_slice(&b[bp..]);
}

// goishlint:ignore GOISH020 formatHeader — Go's `formatHeader` is a
// free function taking the prefix and flags as parameters; goish's is a
// method on the LoggerInner that already holds both, so two of Go's six
// arguments are `self`.

impl LoggerInner {
    // go: sdk 1.25.5 log/log.go:114-164 formatHeader
    fn formatHeader(&self, buf: &mut Vec<byte>, t: time::Time, file: &str, line: int) {
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
    // go: sdk 1.25.5 log/log.go:193-197 Logger.Output
    /// Output writes the output for a logging event.
    ///
    /// `calldepth` names the frame whose file and line the
    /// `Lshortfile` / `Llongfile` flags report — 2 from a helper like
    /// `Println`, which is why those pass 2.
    ///
    /// This used to say "goish has no runtime.Caller so it is unused"
    /// and hard-code `???:0`. runtime::Caller has existed for a while
    /// — net/http's `relevantCaller` walks frames with it — so the
    /// claim was false and every `log.SetFlags(log.Lshortfile)` in a
    /// goish program printed `???:0:` where Go prints the file and
    /// line. Go falls back to exactly that pair, but only when
    /// runtime.Caller says it could not recover the frame.
    pub fn Output<S: Into<string>>(&self, calldepth: int, s: S) -> error {
        let s = s.into();
        let now = time::Now();
        // Go resolves the caller BEFORE taking the lock (log.go:230),
        // "to avoid holding it while the (relatively expensive) caller
        // lookup runs". The flag read needs the lock, so this takes a
        // peek at it and drops it again.
        let want_caller = { self.inner.Lock().flag & (Lshortfile | Llongfile) != 0 };
        let mut caller_file = crate::gostring::string::from_static("");
        let mut caller_line: int = 0;
        if want_caller {
            let (_pc, f, l, ok) = crate::runtime::Caller(calldepth);
            if ok && f.Len() > 0 {
                caller_file = f;
                caller_line = l;
            } else {
                // Go: `file = "???"; line = 0` when Caller fails.
                caller_file = crate::gostring::string::from_static("???");
                caller_line = 0;
            }
        }
        let mut g = self.inner.Lock();
        let short = g.flag & Lshortfile != 0;
        let rendered: &str = caller_file.as_ref();
        let rendered = if short && !rendered.is_empty() {
            // Go: keep only the last path element.
            match rendered.rfind('/') {
                Some(i) => &rendered[i + 1..],
                None => rendered,
            }
        } else {
            rendered
        };
        let (file, line): (&str, int) = if want_caller {
            (rendered, caller_line)
        } else {
            ("", 0)
        };
        let mut buf: Vec<byte> = Vec::new();
        g.formatHeader(&mut buf, now, file, line);
        let sb = s.as_bytes();
        buf.extend_from_slice(sb);
        if sb.is_empty() || *buf.last().unwrap() != b'\n' {
            buf.push(b'\n');
        }
        let (_, err) = g.out.Write(slice::__from_vec(buf));
        return err;
    }

    // go: sdk 1.25.5 log/log.go:80-85 Logger.SetOutput
    /// SetOutput sets the destination for the logger. (Go: log.go 73.)
    pub fn SetOutput(&self, w: Box<dyn crate::io::Writer + Send + Sync>) {
        self.inner.Lock().out = w;
    }

    // go: sdk 1.25.5 log/log.go:333-335 Logger.Flags
    /// Flags returns the output flags for the logger. (Go: log.go 436.)
    pub fn Flags(&self) -> int {
        return self.inner.Lock().flag;
    }

    // go: sdk 1.25.5 log/log.go:339-341 Logger.SetFlags
    /// SetFlags sets the output flags for the logger. (Go: log.go 444.)
    pub fn SetFlags(&self, flag: int) {
        self.inner.Lock().flag = flag;
    }

    // go: sdk 1.25.5 log/log.go:344-349 Logger.Prefix
    /// Prefix returns the output prefix for the logger. (Go: log.go 451.)
    pub fn Prefix(&self) -> string {
        return self.inner.Lock().prefix.clone();
    }

    // go: sdk 1.25.5 log/log.go:352-354 Logger.SetPrefix
    /// SetPrefix sets the output prefix for the logger. (Go: log.go 459.)
    pub fn SetPrefix<S: Into<string>>(&self, prefix: S) {
        self.inner.Lock().prefix = prefix.into();
    }

    // go: sdk 1.25.5 log/log.go:258-262 Logger.Print
    /// Print calls Output to print to the logger. (Go: log.go 212.)
    pub fn Print(&self, args: slice<crate::Any>) {
        let _ = self.Output(2, fmt::Sprint(args));
    }

    // go: sdk 1.25.5 log/log.go:266-270 Logger.Printf
    /// Printf calls Output to print to the logger. (Go: log.go 203.)
    pub fn Printf<S: Into<string>>(&self, format: S, args: slice<crate::Any>) {
        let _ = self.Output(2, fmt::Sprintv(format.into(), args));
    }

    // go: sdk 1.25.5 log/log.go:274-278 Logger.Println
    /// Println calls Output to print to the logger. Arguments are
    /// handled in the manner of `fmt::Println`. (Go: log.go 219.)
    pub fn Println(&self, args: slice<crate::Any>) {
        let _ = self.Output(2, fmt::Sprintln(args));
    }

    // go: sdk 1.25.5 log/log.go:281-286 Logger.Fatal
    /// Fatal is equivalent to Print followed by a call to
    /// `os::Exit(1)`. (Go: log.go 224.)
    pub fn Fatal(&self, args: slice<crate::Any>) -> ! {
        let _ = self.Output(2, fmt::Sprint(args));
        os::Exit(1);
    }

    // go: sdk 1.25.5 log/log.go:289-294 Logger.Fatalf
    /// Fatalf is equivalent to Printf followed by `os::Exit(1)`.
    /// (Go: log.go 230.)
    pub fn Fatalf<S: Into<string>>(&self, format: S, args: slice<crate::Any>) -> ! {
        let _ = self.Output(2, fmt::Sprintv(format.into(), args));
        os::Exit(1);
    }

    // go: sdk 1.25.5 log/log.go:297-302 Logger.Fatalln
    /// Fatalln is equivalent to Println followed by `os::Exit(1)`.
    /// (Go: log.go 236.)
    pub fn Fatalln(&self, args: slice<crate::Any>) -> ! {
        let _ = self.Output(2, fmt::Sprintln(args));
        os::Exit(1);
    }

    // go: sdk 1.25.5 log/log.go:305-311 Logger.Panic
    /// Panic is equivalent to Print followed by a panic.
    /// (Go: log.go 242.)
    pub fn Panic(&self, args: slice<crate::Any>) -> ! {
        let s = fmt::Sprint(args);
        let _ = self.Output(2, s.clone());
        panic!("{}", s);
    }

    // go: sdk 1.25.5 log/log.go:314-320 Logger.Panicf
    /// Panicf is equivalent to Printf followed by a panic.
    /// (Go: log.go 249.)
    pub fn Panicf<S: Into<string>>(&self, format: S, args: slice<crate::Any>) -> ! {
        let s = fmt::Sprintv(format.into(), args);
        let _ = self.Output(2, s.clone());
        panic!("{}", s);
    }

    // go: sdk 1.25.5 log/log.go:323-329 Logger.Panicln
    /// Panicln is equivalent to Println followed by a panic.
    /// (Go: log.go 256.)
    pub fn Panicln(&self, args: slice<crate::Any>) -> ! {
        let s = fmt::Sprintln(args);
        let _ = self.Output(2, s.clone());
        panic!("{}", s);
    }
}
