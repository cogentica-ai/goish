//! Pinned against Go 1.25.5: os.File's Seek, ReadAt, WriteAt and
//! Truncate contract.
//!
//! Eight os reference smokes exist — env, dirent, link, path, samefile,
//! tempfile, copyfs, error — and none covers the file OFFSET
//! operations. Two defects were hiding there:
//!
//!   * **ReadAt returned nil on a SHORT read.** Go loops until the
//!     buffer is full or an error stops it (os/file.go:161-170), so a
//!     read that hits the end reports io.EOF alongside the bytes it
//!     did get. io.ReaderAt's contract is explicit: "ReadAt returns a
//!     non-nil error when n < len(p)". Returning nil tells a caller
//!     looping on `n < len(p)` that the buffer is full when it is
//!     not — an infinite loop, or a truncated record read as
//!     complete.
//!   * **Close twice returned nil.** Go answers
//!     "close NAME: file already closed". Same defect and same shape
//!     as net's TCPConn.Close, fixed in 3eb368e this morning; nothing
//!     had checked the file half.
//!
//! The rest measured clean and is pinned because it is where file I/O
//! surprises people:
//!
//!   * Seeking PAST the end is legal and does NOT extend the file —
//!     the size stays 11 after seeking to 100.
//!   * A NEGATIVE seek is "invalid argument" and leaves the offset at
//!     0; a negative Truncate is likewise an error rather than a
//!     silent no-op.
//!   * ReadAt does not move the file offset — checked explicitly,
//!     since sharing the offset is the obvious implementation and it
//!     is wrong.
//!   * WriteAt past the end extends with NUL bytes, and Truncate up
//!     pads with them.
//!
//! Reference generated with:
//!   CGO_ENABLED=0 scripts/goref.sh os <osfile_ref_test.go>
//! The temp path is rewritten to PATH before comparing.
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::string::String;
use goish::io::{Closer, Writer};
use goish::types::byte;
use goish::{fmt, io, make, os, slice, string};
fn es(e: goish::error) -> string {
    if e.IsNil() {
        string("<nil>")
    } else {
        e.Error()
    }
}
static mut P: Option<String> = None;
fn norm(s: string) -> string {
    let p = unsafe { P.clone().unwrap_or_default() };
    let raw: &str = s.as_ref();
    return string::from_bytes(raw.replace(p.as_str(), "PATH").as_bytes());
}
fn q(s: string) -> string {
    fmt::Sprintf!("%q", norm(s))
}
fn n(v: i64) -> string {
    fmt::Sprintf!("%d", v)
}
/// Go's output, verbatim.
const GO: [&str; 22] = [
    "create                   [\"<nil>\"]",
    "write                    [11 \"<nil>\"]",
    "seek-start               [0 \"<nil>\"]",
    "seek-6                   [6 \"<nil>\"]",
    "seek-cur                 [8 \"<nil>\"]",
    "seek-end                 [6 \"<nil>\"]",
    "seek-negative            [0 \"seek PATH: invalid argument\"]",
    "seek-past-end            [100 \"<nil>\"]",
    "size-after-seek          [11]",
    "readat                   [5 \"world\" \"<nil>\" \"offset-now\" 0]",
    "readat-short             [2 \"ld\" \"EOF\"]",
    "readat-past              [0 \"EOF\"]",
    "writeat-past             [2 \"<nil>\"]",
    "size-after-writeat       [15]",
    "content                  [\"hello world\\x00\\x00XY\"]",
    "truncate-5               [\"<nil>\"]",
    "size-after-trunc         [5]",
    "truncate-8               [\"<nil>\"]",
    "content-after-grow       [\"hello\\x00\\x00\\x00\" 8]",
    "truncate-neg             [\"truncate PATH: invalid argument\"]",
    "write-closed             [\"write PATH: file already closed\"]",
    "close-twice              [\"close PATH: file already closed\"]",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;

fn line(tag: &'static str, parts: alloc::vec::Vec<string>) {
    let mut out = string("");
    for (i, x) in parts.iter().enumerate() {
        if i > 0 {
            out = out + string(" ");
        }
        out = out + x.clone();
    }
    chk(fmt::Sprintf!("%-24s [%s]", string::from_static(tag), out));
}

/// Compare one rendered line against the Go reference, in order.
fn chk(got: string) {
    let i = unsafe { LINE };
    unsafe { LINE += 1 };
    let want = string::from_static(GO[i]);
    if got == want {
        return;
    }
    fmt::Printf!("DIFF go   : %s\n", want);
    fmt::Printf!("     goish: %s\n", got);
    unsafe { FAILED += 1 };
}
#[goish::main]
fn main() {
    let dir = string("/tmp/goish-osfile-probe");
    let _ = os::MkdirAll(dir.clone(), os::FileMode(0o755));
    let p = dir.clone() + string("/f");
    let _ = os::Remove(p.clone());
    unsafe { P = Some(String::from(<goish::string as AsRef<str>>::as_ref(&p))) };

    let (fo, err) = os::Create(p.clone());
    let mut f = fo.MustTake();
    line("create", alloc::vec![q(es(err))]);
    let (wn, werr) = f.Write(goish::convert::bytes(string("hello world")));
    line("write", alloc::vec![n(wn as i64), q(es(werr))]);

    let (o, e) = f.Seek(0 as goish::int, io::SeekStart);
    line("seek-start", alloc::vec![n(o as i64), q(es(e))]);
    let (o, e) = f.Seek(6 as goish::int, io::SeekStart);
    line("seek-6", alloc::vec![n(o as i64), q(es(e))]);
    let (o, e) = f.Seek(2 as goish::int, io::SeekCurrent);
    line("seek-cur", alloc::vec![n(o as i64), q(es(e))]);
    let (o, e) = f.Seek(-5 as goish::int, io::SeekEnd);
    line("seek-end", alloc::vec![n(o as i64), q(es(e))]);
    let (o, e) = f.Seek(-1 as goish::int, io::SeekStart);
    line("seek-negative", alloc::vec![n(o as i64), q(es(e))]);
    let (o, e) = f.Seek(100 as goish::int, io::SeekStart);
    line("seek-past-end", alloc::vec![n(o as i64), q(es(e))]);
    let (st, _) = f.Stat();
    line("size-after-seek", alloc::vec![n(st.Size() as i64)]);

    let mut buf = make!([]byte, 5);
    let _ = f.Seek(0 as goish::int, io::SeekStart);
    let (rn, re) = f.ReadAt(&mut buf, 6);
    let (cur, _) = f.Seek(0 as goish::int, io::SeekCurrent);
    line(
        "readat",
        alloc::vec![
            n(rn as i64),
            q(string::from_bytes(&buf.slice(0, rn as i64).to_vec())),
            q(es(re)),
            q(string("offset-now")),
            n(cur as i64)
        ],
    );
    let (rn, re) = f.ReadAt(&mut buf, 9);
    line(
        "readat-short",
        alloc::vec![
            n(rn as i64),
            q(string::from_bytes(&buf.slice(0, rn as i64).to_vec())),
            q(es(re))
        ],
    );
    let (rn, re) = f.ReadAt(&mut buf, 100);
    line("readat-past", alloc::vec![n(rn as i64), q(es(re))]);

    let (an, ae) = f.WriteAt(goish::convert::bytes(string("XY")), 13);
    line("writeat-past", alloc::vec![n(an as i64), q(es(ae))]);
    let (st, _) = f.Stat();
    line("size-after-writeat", alloc::vec![n(st.Size() as i64)]);
    let (all, _) = os::ReadFile(p.clone());
    line("content", alloc::vec![q(string::from_bytes(&all.to_vec()))]);

    line(
        "truncate-5",
        alloc::vec![q(es(f.Truncate(5 as goish::int)))],
    );
    let (st, _) = f.Stat();
    line("size-after-trunc", alloc::vec![n(st.Size() as i64)]);
    line(
        "truncate-8",
        alloc::vec![q(es(f.Truncate(8 as goish::int)))],
    );
    let (all, _) = os::ReadFile(p.clone());
    line(
        "content-after-grow",
        alloc::vec![q(string::from_bytes(&all.to_vec())), n(all.Len() as i64)],
    );
    line(
        "truncate-neg",
        alloc::vec![q(es(f.Truncate(-1 as goish::int)))],
    );

    let _ = f.Close();
    let (_wn, we) = f.Write(goish::convert::bytes(string("x")));
    line("write-closed", alloc::vec![q(es(we))]);
    line("close-twice", alloc::vec![q(es(f.Close()))]);
    let _ = os::Remove(p);

    let failed = unsafe { FAILED };
    let n = GO.len() as i64;
    if failed == 0 {
        fmt::Printf!("os.File offsets: %d/%d match Go\n", n, n);
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d/%d diverge\n", failed, n);
    goish::os::Exit(1);
}
