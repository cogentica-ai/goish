// tar_fileinfo_smoke — Header.FileInfo against a running Go.
// (archive/tar/common.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_tar_fileinfo_ref.go` run in
// `package tar_test` by `scripts/goref.sh`.
//
// `Header.FileInfo().Mode()` reads the file type from TWO places: the
// Unix type bits in `Header.Mode`, and `Header.Typeflag`. This port
// consulted only Typeflag — the whole
// `switch m := fs.FileMode(fi.h.Mode) &^ 07777` arm was missing — so a
// header written by anything that fills Mode from a stat(2) came back
// as a regular file. `IsDir()` is defined as `Mode().IsDir()`, so it
// went wrong with it, and so did every caller that branched on it.
//
// The grid below crosses twelve Mode values with six type flags, so
// the two sources are exercised together and apart. The rows where
// they disagree — `mode dir, flag Symlink` is `dLrwxr-xr-x`, both bits
// set — are the ones that were wrong.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::archive::tar;
use goish::gostring::string;
use goish::io::fs;
use goish::types::{byte, int};
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// go: none — goish idiom: the smokes print one PASS/FAIL line per
//     numbered check; this is that line, hoisted.
fn report(failed: &mut int, ok: bool, n: &str, what: &str) {
    if ok {
        fmt::Println!("[", n, "]", what, "PASS");
    } else {
        fmt::Println!("[", n, "]", what, "FAIL");
        *failed += 1;
    }
}

fn modeBits(label: &str) -> i64 {
    let mut i = 0usize;
    while i < MODES.len() {
        if MODES[i].0 == label {
            return MODES[i].1;
        }
        i += 1;
    }
    return 0;
}

fn flagOf(label: &str) -> byte {
    return match label {
        "Reg" => tar::TypeReg,
        "Dir" => tar::TypeDir,
        "Symlink" => tar::TypeSymlink,
        "Char" => tar::TypeChar,
        "Block" => tar::TypeBlock,
        _ => tar::TypeFifo,
    };
}

const MODES: [(&str, i64); 12] = [
    ("none", 0o644),
    ("dir", 0o40755),
    ("fifo", 0o10644),
    ("reg", 0o100644),
    ("lnk", 0o120777),
    ("blk", 0o60660),
    ("chr", 0o20666),
    ("sock", 0o140755),
    ("setuid", 0o4755),
    ("setgid", 0o2755),
    ("sticky", 0o1755),
    ("all-suid", 0o47755),
];

// (mode label, flag label, want mode string, want isdir, want perm)
const GRID: [(&str, &str, &str, bool, u32); 72] = [
    ("none", "Reg", "-rw-r--r--", false, 0o644),
    ("none", "Dir", "drw-r--r--", true, 0o644),
    ("none", "Symlink", "Lrw-r--r--", false, 0o644),
    ("none", "Char", "Dcrw-r--r--", false, 0o644),
    ("none", "Block", "Drw-r--r--", false, 0o644),
    ("none", "Fifo", "prw-r--r--", false, 0o644),
    ("dir", "Reg", "drwxr-xr-x", true, 0o755),
    ("dir", "Dir", "drwxr-xr-x", true, 0o755),
    ("dir", "Symlink", "dLrwxr-xr-x", true, 0o755),
    ("dir", "Char", "dDcrwxr-xr-x", true, 0o755),
    ("dir", "Block", "dDrwxr-xr-x", true, 0o755),
    ("dir", "Fifo", "dprwxr-xr-x", true, 0o755),
    ("fifo", "Reg", "prw-r--r--", false, 0o644),
    ("fifo", "Dir", "dprw-r--r--", true, 0o644),
    ("fifo", "Symlink", "Lprw-r--r--", false, 0o644),
    ("fifo", "Char", "Dpcrw-r--r--", false, 0o644),
    ("fifo", "Block", "Dprw-r--r--", false, 0o644),
    ("fifo", "Fifo", "prw-r--r--", false, 0o644),
    ("reg", "Reg", "-rw-r--r--", false, 0o644),
    ("reg", "Dir", "drw-r--r--", true, 0o644),
    ("reg", "Symlink", "Lrw-r--r--", false, 0o644),
    ("reg", "Char", "Dcrw-r--r--", false, 0o644),
    ("reg", "Block", "Drw-r--r--", false, 0o644),
    ("reg", "Fifo", "prw-r--r--", false, 0o644),
    ("lnk", "Reg", "Lrwxrwxrwx", false, 0o777),
    ("lnk", "Dir", "dLrwxrwxrwx", true, 0o777),
    ("lnk", "Symlink", "Lrwxrwxrwx", false, 0o777),
    ("lnk", "Char", "LDcrwxrwxrwx", false, 0o777),
    ("lnk", "Block", "LDrwxrwxrwx", false, 0o777),
    ("lnk", "Fifo", "Lprwxrwxrwx", false, 0o777),
    ("blk", "Reg", "Drw-rw----", false, 0o660),
    ("blk", "Dir", "dDrw-rw----", true, 0o660),
    ("blk", "Symlink", "LDrw-rw----", false, 0o660),
    ("blk", "Char", "Dcrw-rw----", false, 0o660),
    ("blk", "Block", "Drw-rw----", false, 0o660),
    ("blk", "Fifo", "Dprw-rw----", false, 0o660),
    ("chr", "Reg", "Dcrw-rw-rw-", false, 0o666),
    ("chr", "Dir", "dDcrw-rw-rw-", true, 0o666),
    ("chr", "Symlink", "LDcrw-rw-rw-", false, 0o666),
    ("chr", "Char", "Dcrw-rw-rw-", false, 0o666),
    ("chr", "Block", "Dcrw-rw-rw-", false, 0o666),
    ("chr", "Fifo", "Dpcrw-rw-rw-", false, 0o666),
    ("sock", "Reg", "Srwxr-xr-x", false, 0o755),
    ("sock", "Dir", "dSrwxr-xr-x", true, 0o755),
    ("sock", "Symlink", "LSrwxr-xr-x", false, 0o755),
    ("sock", "Char", "DScrwxr-xr-x", false, 0o755),
    ("sock", "Block", "DSrwxr-xr-x", false, 0o755),
    ("sock", "Fifo", "pSrwxr-xr-x", false, 0o755),
    ("setuid", "Reg", "urwxr-xr-x", false, 0o755),
    ("setuid", "Dir", "durwxr-xr-x", true, 0o755),
    ("setuid", "Symlink", "Lurwxr-xr-x", false, 0o755),
    ("setuid", "Char", "Ducrwxr-xr-x", false, 0o755),
    ("setuid", "Block", "Durwxr-xr-x", false, 0o755),
    ("setuid", "Fifo", "purwxr-xr-x", false, 0o755),
    ("setgid", "Reg", "grwxr-xr-x", false, 0o755),
    ("setgid", "Dir", "dgrwxr-xr-x", true, 0o755),
    ("setgid", "Symlink", "Lgrwxr-xr-x", false, 0o755),
    ("setgid", "Char", "Dgcrwxr-xr-x", false, 0o755),
    ("setgid", "Block", "Dgrwxr-xr-x", false, 0o755),
    ("setgid", "Fifo", "pgrwxr-xr-x", false, 0o755),
    ("sticky", "Reg", "trwxr-xr-x", false, 0o755),
    ("sticky", "Dir", "dtrwxr-xr-x", true, 0o755),
    ("sticky", "Symlink", "Ltrwxr-xr-x", false, 0o755),
    ("sticky", "Char", "Dctrwxr-xr-x", false, 0o755),
    ("sticky", "Block", "Dtrwxr-xr-x", false, 0o755),
    ("sticky", "Fifo", "ptrwxr-xr-x", false, 0o755),
    ("all-suid", "Reg", "dugtrwxr-xr-x", true, 0o755),
    ("all-suid", "Dir", "dugtrwxr-xr-x", true, 0o755),
    ("all-suid", "Symlink", "dLugtrwxr-xr-x", true, 0o755),
    ("all-suid", "Char", "dDugctrwxr-xr-x", true, 0o755),
    ("all-suid", "Block", "dDugtrwxr-xr-x", true, 0o755),
    ("all-suid", "Fifo", "dpugtrwxr-xr-x", true, 0o755),
];

// (is_reg_header, input name, want base name)
const NAMES: [(bool, &str, &str); 12] = [
    (false, "a.txt", "a.txt"),
    (true, "a.txt", "a.txt"),
    (false, "d/", "d"),
    (true, "d/", "d"),
    (false, "d/e/", "e"),
    (true, "d/e/", "e"),
    (false, "d/e/f.txt", "f.txt"),
    (true, "d/e/f.txt", "f.txt"),
    (false, "/", "/"),
    (true, "/", "/"),
    (false, ".", "."),
    (true, ".", "."),
];

// (mode label, want FormatFileInfo)
const FORMATS: [(&str, &str); 8] = [
    ("none", "-rw-r--r-- 3 0001-01-01 00:00:00 x"),
    ("dir", "drwxr-xr-x 3 0001-01-01 00:00:00 x/"),
    ("fifo", "prw-r--r-- 3 0001-01-01 00:00:00 x"),
    ("reg", "-rw-r--r-- 3 0001-01-01 00:00:00 x"),
    ("lnk", "Lrwxrwxrwx 3 0001-01-01 00:00:00 x"),
    ("blk", "Drw-rw---- 3 0001-01-01 00:00:00 x"),
    ("chr", "Dcrw-rw-rw- 3 0001-01-01 00:00:00 x"),
    ("sock", "Srwxr-xr-x 3 0001-01-01 00:00:00 x"),
];

// (mode label, want mode, want flag, want name, want size, want err)
const ROUNDTRIP: [(&str, i64, u8, &str, i64, &str); 12] = [
    ("none", 0o644, b'0', "x", 3, ""),
    ("dir", 0o755, b'5', "x/", 0, ""),
    ("fifo", 0o644, b'6', "x", 0, ""),
    ("reg", 0o644, b'0', "x", 3, ""),
    ("lnk", 0o777, b'2', "x", 0, ""),
    ("blk", 0o660, b'4', "x", 0, ""),
    ("chr", 0o666, b'3', "x", 0, ""),
    ("sock", 0, 0, "", 0, "archive/tar: sockets not supported"),
    ("setuid", 0o4755, b'0', "x", 3, ""),
    ("setgid", 0o2755, b'0', "x", 3, ""),
    ("sticky", 0o1755, b'0', "x", 3, ""),
    ("all-suid", 0o7755, b'5', "x/", 0, ""),
];
#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. The grid: twelve Mode values crossed with six type flags.
    //    `mode dir, flag Symlink` is `dLrwxr-xr-x` — Go sets BOTH bits,
    //    because the two sources are independent and neither wins.
    {
        let mut ok = true;
        let mut i = 0;
        while i < GRID.len() {
            let (mlabel, flabel, want, want_dir, want_perm) = GRID[i];
            let mut h = tar::Header::new();
            h.Name = s("x");
            h.Mode = modeBits(mlabel);
            h.Typeflag = flagOf(flabel);
            h.Size = 7;
            let fi = h.FileInfo();
            if fi.Mode().String() != s(want) {
                ok = false;
            }
            if fi.IsDir() != want_dir {
                ok = false;
            }
            if fi.Mode().Perm().Bits() != want_perm {
                ok = false;
            }
            if fi.Name() != s("x") || fi.Size() != 7 {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 1", "FileInfo().Mode() x72");
    }

    // 2. The Unix type bits ALONE decide, with Typeflag left at Reg.
    //    Stated on its own because it is the arm that was missing: every
    //    one of these came back `-rw-r--r--` before.
    {
        let mut ok = true;
        let cases: [(&str, &str, bool); 7] = [
            ("dir", "drwxr-xr-x", true),
            ("fifo", "prw-r--r--", false),
            ("reg", "-rw-r--r--", false),
            ("lnk", "Lrwxrwxrwx", false),
            ("blk", "Drw-rw----", false),
            ("chr", "Dcrw-rw-rw-", false),
            ("sock", "Srwxr-xr-x", false),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (mlabel, want, want_dir) = cases[i];
            let mut h = tar::Header::new();
            h.Name = s("x");
            h.Mode = modeBits(mlabel);
            h.Typeflag = tar::TypeReg;
            let fi = h.FileInfo();
            if fi.Mode().String() != s(want) || fi.IsDir() != want_dir {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 2", "Mode's type bits alone decide");
    }

    // 3. setuid / setgid / sticky, which were already read, still are.
    {
        let mut ok = true;
        let cases: [(&str, &str); 4] = [
            ("setuid", "urwxr-xr-x"),
            ("setgid", "grwxr-xr-x"),
            ("sticky", "trwxr-xr-x"),
            ("all-suid", "dugtrwxr-xr-x"),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (mlabel, want) = cases[i];
            let mut h = tar::Header::new();
            h.Name = s("x");
            h.Mode = modeBits(mlabel);
            h.Typeflag = tar::TypeReg;
            if h.FileInfo().Mode().String() != s(want) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 3", "setuid/setgid/sticky");
    }

    // 4. Name(): a directory header's trailing slash is cleaned away
    //    before the base name is taken, so "d/e/" is "e", not "".
    {
        let mut ok = true;
        let mut i = 0;
        while i < NAMES.len() {
            let (isReg, input, want) = NAMES[i];
            let mut h = tar::Header::new();
            h.Name = s(input);
            if isReg {
                h.Mode = 0o644;
                h.Typeflag = tar::TypeReg;
            } else {
                h.Mode = 0o40755;
                h.Typeflag = tar::TypeDir;
            }
            if h.FileInfo().Name() != s(want) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 4", "FileInfo().Name()");
    }

    // 5. FormatFileInfo over a Header's FileInfo — what
    //    headerFileInfo.String() returns.
    //
    //    ONE STATED DEVIATION, and it is not tar's: Go prints a zero
    //    time.Time as 0001-01-01, because Go's Time counts from the
    //    absolute zero year. goish's Time holds Unix seconds, so its
    //    zero is the epoch and this prints 1970-01-01. Everything else
    //    in the line — the mode letters, the size, the column order,
    //    the trailing slash on a directory — is byte-for-byte Go's.
    {
        let mut ok = true;
        let mut i = 0;
        while i < FORMATS.len() {
            let (mlabel, want) = FORMATS[i];
            let mut h = tar::Header::new();
            h.Name = s("x");
            h.Mode = modeBits(mlabel);
            h.Typeflag = tar::TypeReg;
            h.Size = 3;
            let got = fs::FormatFileInfo(&*h.FileInfo());
            if got != s(want) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 5", "FormatFileInfo (zero-Time noted)");
    }

    // 6. FileInfoHeader round-trips the type back out: a Mode carrying
    //    the directory bit comes back as Typeflag Dir with a trailing
    //    slash on the name and Size zeroed, and a socket is refused.
    {
        let mut ok = true;
        let mut i = 0;
        while i < ROUNDTRIP.len() {
            let (mlabel, want_mode, want_flag, want_name, want_size, want_err) = ROUNDTRIP[i];
            let mut h = tar::Header::new();
            h.Name = s("x");
            h.Mode = modeBits(mlabel);
            h.Typeflag = tar::TypeReg;
            h.Size = 3;
            let fi = h.FileInfo();
            let (h2, err) = tar::FileInfoHeader(&*fi, &s(""));
            if want_err != "" {
                if err.IsNil() || err.Error() != s(want_err) {
                    ok = false;
                }
                i += 1;
                continue;
            }
            if !err.IsNil() {
                ok = false;
                i += 1;
                continue;
            }
            if h2.Mode != want_mode || h2.Typeflag != want_flag {
                ok = false;
            }
            if h2.Name != s(want_name) || h2.Size != want_size {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 6", "FileInfoHeader round-trip");
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
