// os_readfile_ref_smoke — os.ReadFile must read to EOF, not to the
// stat size, against Go 1.25.5.
//
// Go's readFileContents (os/file.go) takes the stat size as a CAPACITY
// HINT and then loops until EOF, growing the buffer. Its own comment
// says why:
//
//     files in Linux's /proc claim size 0 but then do not work right
//     if read in small pieces
//
// goish sized a buffer to `Stat().Size()` and read exactly that many
// bytes. For every file whose stat size is 0 but which yields data —
// all of /proc and /sys — that returned EMPTY where Go returns the
// contents. It also truncated any file that grew between the stat and
// the read.
//
// /proc/sys/kernel/ostype is the probe: stat reports 0 and the contents
// are "Linux\n" on every Linux, so the row is machine-independent and
// safe on CI. The statsize row is pinned too, so the divergence is
// legible here rather than only in this comment — if that file ever
// starts reporting a real size, this smoke says so instead of quietly
// passing for the wrong reason.
//
// Reference: tools/gen_os_readfile_ref.go via scripts/goref.sh.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use goish::gostring::string;
use goish::{fmt, int, os};

const GO: [&str; 5] = [
    "regular        len=12 \"hello\\nworld\\n\"",
    "empty          len=0 \"\"",
    "proc-ostype    len=6 \"Linux\\n\"",
    "missing        err",
    "proc-statsize  statsize=0",
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

fn show(ln: &mut usize, name: &str, path: &str) {
    let (b, err) = os::ReadFile(string::from(path));
    if !err.IsNil() {
        chk(ln, &fmt::Sprintf!("%-14s err", string::from(name)));
        return;
    }
    chk(
        ln,
        &fmt::Sprintf!(
            "%-14s len=%d %q",
            string::from(name),
            b.Len(),
            string::from_bytes(&b.__into_vec())
        ),
    );
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;
    let reg = "/tmp/goish_os_readfile_ref_regular";
    let empty = "/tmp/goish_os_readfile_ref_empty";
    let missing = "/tmp/goish_os_readfile_ref_nope";

    let e1 = os::WriteFile(string::from(reg), b"hello\nworld\n", 0o644 as int);
    let e2 = os::WriteFile(string::from(empty), b"", 0o644 as int);
    if !e1.IsNil() || !e2.IsNil() {
        fmt::Printf!("[!!] setup: %v %v\n", e1, e2);
        os::Exit(1);
    }
    let _ = os::Remove(string::from(missing));

    show(&mut ln, "regular", reg);
    show(&mut ln, "empty", empty);
    show(&mut ln, "proc-ostype", "/proc/sys/kernel/ostype");
    show(&mut ln, "missing", missing);

    let (fi, serr) = os::Stat(string::from("/proc/sys/kernel/ostype"));
    if serr.IsNil() {
        chk(
            &mut ln,
            &fmt::Sprintf!("%-14s statsize=%d", string::from("proc-statsize"), fi.Size()),
        );
    }

    let _ = os::Remove(string::from(reg));
    let _ = os::Remove(string::from(empty));

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
