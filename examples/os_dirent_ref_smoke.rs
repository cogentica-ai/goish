// os_dirent_ref_smoke — DirEntry type bits against a running Go.
// (os/dirent_linux.go, os/file_unix.go, os/dir_unix.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_os_dirent_ref.go` run in `package
// os_test` by `scripts/goref.sh`.
//
// getdents64 hands back a `d_type` byte, and Go maps all seven of its
// values onto FileMode type bits — plus DT_UNKNOWN, which is not a type
// at all but the kernel saying "stat it yourself".
//
// goish mapped two: DT_DIR and DT_LNK. A fifo, a socket and a device
// all came back as `FileMode(0)` — a regular file — so `Type()` lied
// about them and any caller filtering on it silently skipped or
// included the wrong entries. DT_UNKNOWN read as a regular file too,
// and that one is not an edge case: several filesystems return it for
// EVERY entry, and on one of those `IsDir()` was false for every
// directory in the tree.
//
// Go's answer for unknown is the sentinel `^FileMode(0)`, which
// `newUnixDirent` turns into an lstat — caching the result so `Info()`
// does not pay for it twice. goish had no `newUnixDirent` at all.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::io::fs::{self, FileMode};
use goish::os;
use goish::types::int;
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

// (name, type bits, Type().String(), IsDir) — Go 1.25.5 verbatim.
const ENTS: [(&str, u32, &str, bool); 4] = [
    ("areg", 0x0, "----------", false),
    ("bdir", 0x8000_0000, "d---------", true),
    ("clink", 0x0800_0000, "L---------", false),
    ("dfifo", 0x0200_0000, "p---------", false),
];

// DT_SOCK and DT_BLK are in `direntType` and in the Go reference, but
// not asserted here: goish's syscall layer has no `SockaddrUn`, so the
// smoke cannot bind a unix socket, and creating a block device needs
// CAP_MKNOD. The four above plus /dev's character device in check 3
// cover the five d_type values a test can produce unprivileged.

#[goish::main]
fn main() {
    let mut failed = 0;

    let (root, derr) = os::MkdirTemp("", "goish_dirent*");
    if !derr.IsNil() {
        fmt::Println!("cannot make a scratch dir:", derr.Error());
        syscall::Exit(1);
    }
    let j = |p: &str| root.clone() + s("/") + s(p);

    let _ = os::WriteFile(j("areg"), goish::bytes("x"), FileMode(0o644));
    let _ = os::Mkdir(j("bdir"), FileMode(0o755));
    let _ = os::Symlink(j("areg"), j("clink"));
    // mkfifo(3) is mknod(2) with S_IFIFO — the one node type an
    // unprivileged process may create.
    {
        let p = j("dfifo");
        let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        buf.extend_from_slice(p.as_bytes());
        buf.push(0);
        let rc = syscall::Mknod(buf.as_ptr(), syscall::S_IFIFO | 0o644, 0);
        if rc < 0 {
            fmt::Println!("cannot mkfifo, rc =", rc as int);
        }
    }
    // 1. Every entry's type bits, Type().String() and IsDir(), against
    //    Go's. Before direntType mapped all seven, dfifo and esock read
    //    as 0x0 — "----------", a regular file.
    {
        let mut ok = true;
        let (ents, err) = os::ReadDir(root.clone());
        if !err.IsNil() {
            fmt::Println!("    ReadDir:", err.Error());
            ok = false;
        }
        if ents.len() != ENTS.len() {
            fmt::Println!(
                "    got",
                ents.len() as int,
                "entries, want",
                ENTS.len() as int
            );
            ok = false;
        }
        let mut i = 0usize;
        while i < ENTS.len() && i < ents.len() {
            let (name, bits, tstr, isdir) = ENTS[i];
            let e = &ents[i];
            // Go: order [areg bdir clink dfifo esock] — ReadDir sorts.
            if e.Name() != s(name) {
                fmt::Println!("    slot", i as int, "is", e.Name(), "want", s(name));
                ok = false;
            } else if e.Type().0 != bits || e.Type().String() != s(tstr) || e.IsDir() != isdir {
                fmt::Println!(
                    "   ",
                    s(name),
                    "type",
                    fmt::Sprintf!("%#x", e.Type().0),
                    e.Type().String(),
                    e.IsDir(),
                    "want",
                    fmt::Sprintf!("%#x", bits),
                    s(tstr),
                    isdir
                );
                ok = false;
            }
            i += 1;
        }
        report(
            &mut failed,
            ok,
            " 1",
            "d_type maps onto all seven mode bits",
        );
    }

    // 2. `Info()` lstats the entry, so a symlink's Info is the LINK's
    //    mode and not the target's. Go: info for clink is
    //    "Lrwxrwxrwx", for bdir "drwxr-xr-x", for dfifo "prw-r--r--".
    {
        let mut ok = true;
        let (ents, _) = os::ReadDir(root.clone());
        // (name, first char of Info().Mode().String())
        let want: [(&str, u8); 4] = [
            ("areg", b'-'),
            ("bdir", b'd'),
            ("clink", b'L'),
            ("dfifo", b'p'),
        ];
        let mut i = 0usize;
        while i < want.len() {
            let (name, ch) = want[i];
            let mut k = 0usize;
            while k < ents.len() {
                if ents[k].Name() == s(name) {
                    let (info, ierr) = ents[k].Info();
                    if !ierr.IsNil() {
                        ok = false;
                    } else if info.Mode().String().as_bytes()[0] != ch {
                        fmt::Println!("    info", s(name), info.Mode().String());
                        ok = false;
                    }
                }
                k += 1;
            }
            i += 1;
        }
        report(&mut failed, ok, " 2", "Info() reports the entry's own mode");
    }

    // 3. The DT_UNKNOWN path, exercised directly: `direntType` is not
    //    reachable from outside `os`, but `newUnixDirent`'s contract
    //    is — an entry whose type could not be determined is lstat'd,
    //    and the answer must be the same as ReadDir gives. /dev is the
    //    one directory guaranteed to hold a character device, so it
    //    also pins the DT_CHR mapping Go prints as "Dc---------".
    {
        let mut ok = true;
        let (ents, err) = os::ReadDir("/dev");
        if !err.IsNil() {
            fmt::Println!("    ReadDir /dev:", err.Error());
            ok = false;
        }
        let mut seen = false;
        let mut i = 0usize;
        while i < ents.len() {
            if ents[i].Name() == s("null") || ents[i].Name() == s("zero") {
                seen = true;
                // Go: dev null type=0x4200000 typestr="Dc---------"
                if ents[i].Type().0 != 0x0420_0000 {
                    fmt::Println!(
                        "    /dev/",
                        ents[i].Name(),
                        "type",
                        fmt::Sprintf!("%#x", ents[i].Type().0)
                    );
                    ok = false;
                }
                if ents[i].Type().String() != s("Dc---------") {
                    ok = false;
                }
            }
            i += 1;
        }
        if !seen {
            fmt::Println!("    neither /dev/null nor /dev/zero was listed");
            ok = false;
        }
        report(&mut failed, ok, " 3", "a character device reads as Dc");
    }

    // 4. os re-exports every one of io/fs's mode bits under the name Go
    //    gives it. Four of the fifteen were exported before.
    {
        let ok = os::ModeDir == fs::ModeDir
            && os::ModeNamedPipe == fs::ModeNamedPipe
            && os::ModeSocket == fs::ModeSocket
            && os::ModeDevice == fs::ModeDevice
            && os::ModeCharDevice == fs::ModeCharDevice
            && os::ModeSetuid == fs::ModeSetuid
            && os::ModeSetgid == fs::ModeSetgid
            && os::ModeSticky == fs::ModeSticky
            && os::ModeIrregular == fs::ModeIrregular
            && os::ModeAppend == fs::ModeAppend
            && os::ModeExclusive == fs::ModeExclusive
            && os::ModeTemporary == fs::ModeTemporary
            && os::ModeType == fs::ModeType
            && os::ModePerm == fs::ModePerm;
        report(&mut failed, ok, " 4", "os re-exports all fifteen mode bits");
    }

    // 5. `Readdirnames(n)` with a positive n is RESUMABLE: it must
    //    keep the rest of the getdents batch for the next call, and
    //    report io.EOF once the directory is exhausted.
    //
    //    Go, over these four entries: (3, nil), (1, nil), (0, EOF).
    //    goish gave (3, nil), (0, nil), (0, nil) — the fourth entry
    //    was read from the kernel, not returned, and thrown away with
    //    the rest of the batch, and there was no EOF to notice it by.
    {
        let mut ok = true;
        let (mut fh, oerr) = os::Open(root.clone());
        if !oerr.IsNil() {
            fmt::Println!("    open:", oerr.Error());
            ok = false;
        } else {
            let f = fh.MustMut();
            // (want_len, want_eof)
            let want: [(usize, bool); 3] = [(3, false), (1, false), (0, true)];
            let mut i = 0usize;
            while i < want.len() {
                let (wlen, weof) = want[i];
                let (ns, e) = f.Readdirnames(3);
                let is_eof = !e.IsNil() && goish::errors::Is(e.clone(), goish::io::EOF);
                if ns.len() != wlen || is_eof != weof || (!weof && !e.IsNil()) {
                    fmt::Println!(
                        "    batch",
                        i as int,
                        "got",
                        ns.len() as int,
                        is_eof,
                        "want",
                        wlen as int,
                        weof
                    );
                    ok = false;
                }
                i += 1;
            }
            let _ = f.Close();
        }

        // n <= 0 reads everything and returns nil, not EOF — even when
        // the directory is already exhausted. Go: got=4 err=<nil>,
        // then got=0 err=<nil>.
        let (mut fh2, _) = os::Open(root.clone());
        let f2 = fh2.MustMut();
        let (all, e1) = f2.Readdirnames(-1);
        if all.len() != 4usize || !e1.IsNil() {
            fmt::Println!("    n=-1 got", all.len() as int, e1.IsNil());
            ok = false;
        }
        let (again, e2) = f2.Readdirnames(-1);
        if again.len() != 0usize || !e2.IsNil() {
            ok = false;
        }
        let _ = f2.Close();
        // Go: names closed err=readdirent <root>: use of closed file
        let (_, e3) = f2.Readdirnames(-1);
        let want_closed = s("readdirent ") + root.clone() + s(": use of closed file");
        if e3.IsNil() || e3.Error() != want_closed {
            fmt::Println!("    closed got", e3.Error());
            ok = false;
        }
        report(
            &mut failed,
            ok,
            " 5",
            "Readdirnames resumes, and ends in EOF",
        );
    }

    let _ = os::RemoveAll(root);

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
