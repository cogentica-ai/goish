// os_chtimes_ref_smoke — pre-1970 timestamps, against Go 1.25.5.
//
// os.Chtimes converts each time with syscall.NsecToTimespec, whose
// whole job beyond the division is one correction:
//
//     sec := nsec / 1e9
//     nsec = nsec % 1e9
//     if nsec < 0 { nsec += 1e9; sec-- }
//
// goish did the division and skipped the correction. Rust's `%` (like
// Go's) truncates toward zero, so any pre-1970 time with a fractional
// part produced a NEGATIVE tv_nsec, and utimensat rejects a tv_nsec
// outside [0, 999999999] with EINVAL. Chtimes failed outright on a
// timestamp Go writes without complaint — the case an archive
// extractor hits restoring old mtimes from a tar.
//
// A whole-second pre-1970 time has remainder 0 and was always fine,
// which is why the bug needed the fractional row to show up.
//
// The omit row pins the other half: a zero time.Time is UTIME_OMIT,
// "leave this timestamp alone", so the fix cannot regress it into
// writing the epoch.
//
// Reference: tools/gen_os_chtimes_ref.go via scripts/goref.sh.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use goish::gostring::string;
use goish::{fmt, int, os, time};

const GO: [&str; 5] = [
    "pre-epoch-frac         mtime=1969-12-31T23:59:59.5Z",
    "pre-epoch-whole        mtime=1969-12-31T23:59:58Z",
    "post-epoch-frac        mtime=1970-01-01T00:00:01.5Z",
    "epoch                  mtime=1970-01-01T00:00:00Z",
    "omit-mtime             mtime=1970-01-12T13:46:40Z",
];

static mut BAD: usize = 0;

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line: %q\n", got);
        unsafe { BAD += 1 };
        *ln += 1;
        return;
    }
    let want = string::from(GO[*ln]);
    if got.clone() == want {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        unsafe { BAD += 1 };
        fmt::Printf!("[!!] goish: %q\n", got);
        fmt::Printf!("     go   : %q\n", want);
    }
    *ln += 1;
}

const PATH: &str = "/tmp/goish_os_chtimes_ref";

fn show(ln: &mut usize, name: &str, at: time::Time, mt: time::Time) {
    let _ = os::Remove(string::from(PATH));
    let werr = os::WriteFile(string::from(PATH), b"x", 0o644 as int);
    if !werr.IsNil() {
        fmt::Printf!("[!!] setup write: %v\n", werr);
        unsafe { BAD += 1 };
        return;
    }
    // A known starting point, so the OMIT row is visible as "unchanged".
    let base = time::Unix(1000000, 0).UTC();
    let berr = os::Chtimes(string::from(PATH), base.clone(), base);
    if !berr.IsNil() {
        fmt::Printf!("[!!] setup chtimes: %v\n", berr);
        unsafe { BAD += 1 };
        return;
    }
    let err = os::Chtimes(string::from(PATH), at, mt);
    if !err.IsNil() {
        chk(ln, &fmt::Sprintf!("%-22s err", string::from(name)));
        return;
    }
    let (fi, serr) = os::Stat(string::from(PATH));
    if !serr.IsNil() {
        chk(ln, &fmt::Sprintf!("%-22s staterr", string::from(name)));
        return;
    }
    chk(
        ln,
        &fmt::Sprintf!(
            "%-22s mtime=%s",
            string::from(name),
            fi.ModTime().UTC().Format(time::RFC3339Nano)
        ),
    );
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;
    show(&mut ln, "pre-epoch-frac", time::Unix(-1, 500000000), time::Unix(-1, 500000000));
    show(&mut ln, "pre-epoch-whole", time::Unix(-2, 0), time::Unix(-2, 0));
    show(&mut ln, "post-epoch-frac", time::Unix(1, 500000000), time::Unix(1, 500000000));
    show(&mut ln, "epoch", time::Unix(0, 0), time::Unix(0, 0));
    show(&mut ln, "omit-mtime", time::Unix(5, 0), time::Time::default());
    let _ = os::Remove(string::from(PATH));

    if ln != GO.len() {
        fmt::Printf!("[!!] line count mismatch with the Go reference\n");
        unsafe { BAD += 1 };
    }
    let bad = unsafe { BAD };
    if bad != 0 {
        fmt::Printf!("[!!] %d row(s) diverge from Go\n", bad as i64);
        os::Exit(1);
    }
    os::Exit(0);
}
