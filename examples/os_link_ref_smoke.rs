// os_link_ref_smoke — os's structured errors against a running Go.
// (os/file.go, os/file_posix.go, os/file_unix.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_os_link_ref.go` run in `package os_test`
// by `scripts/goref.sh`, with the scratch directory replaced by <root>.
//
// Every error-returning entry point in Go's os names the operation and
// the path, through one of two structured types: `*PathError` for the
// one-path calls and `*LinkError` for the two-path ones.
//
// goish returned a flat string from all of them — "chdir failed",
// "symlink failed", "rename failed", "link failed", "truncate failed",
// "chown failed", "readlink failed", "chtimes failed", and from the
// `*File` methods "read failed", "seek failed", "fstat failed". None
// named the file. None carried the errno, so `os::IsNotExist` on any of
// them was false. And `LinkError` did not exist at all, so the three
// two-path calls had nowhere to put their second path even in
// principle.
//
// The `*File` methods needed Go's `wrapErr` for the same reason: a
// method on a closed file answered with the bare `ErrClosed` sentinel,
// "file already closed", where Go says `seek <path>: file already
// closed`.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::errors;
use goish::gostring::string;
use goish::io::fs::{self, FileMode};
use goish::os;
use goish::types::{byte, int};
use goish::{error, fmt, syscall};

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

// go: none — goish idiom: replace the scratch root with "<root>" so the
//     vectors do not depend on where the smoke happens to run.
fn strip(msg: &string, root: &string) -> string {
    let mb = msg.as_bytes();
    let rb = root.as_bytes();
    let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let mut i = 0usize;
    while i < mb.len() {
        if i + rb.len() <= mb.len() && &mb[i..i + rb.len()] == rb {
            out.extend_from_slice(b"<root>");
            i += rb.len();
            continue;
        }
        out.push(mb[i]);
        i += 1;
    }
    return string::__from_vec(out);
}

// (tag, want_text, want_notexist, want_exist) — Go 1.25.5 verbatim,
// with the scratch root replaced by <root>. An empty want means Go
// returned nil.
const CASES: [(&str, &str, bool, bool); 20] = [
    (
        "chdir/missing",
        "chdir <root>/nope: no such file or directory",
        true,
        false,
    ),
    (
        "chdir/file",
        "chdir <root>/f: not a directory",
        false,
        false,
    ),
    (
        "chmod/missing",
        "chmod <root>/nope: no such file or directory",
        true,
        false,
    ),
    ("chmod/ok", "", false, false),
    (
        "chown/missing",
        "chown <root>/nope: no such file or directory",
        true,
        false,
    ),
    (
        "lchown/missing",
        "lchown <root>/nope: no such file or directory",
        true,
        false,
    ),
    (
        "truncate/missing",
        "truncate <root>/nope: no such file or directory",
        true,
        false,
    ),
    ("truncate/ok", "", false, false),
    (
        "readlink/notlink",
        "readlink <root>/f: invalid argument",
        false,
        false,
    ),
    (
        "readlink/missing",
        "readlink <root>/nope: no such file or directory",
        true,
        false,
    ),
    (
        "chtimes/missing",
        "chtimes <root>/nope: no such file or directory",
        true,
        false,
    ),
    (
        "symlink/exists",
        "symlink <root>/f <root>/l: file exists",
        false,
        true,
    ),
    (
        "symlink/badnew",
        "symlink <root>/f <root>/nodir/x: no such file or directory",
        true,
        false,
    ),
    (
        "link/missing",
        "link <root>/nope <root>/l2: no such file or directory",
        true,
        false,
    ),
    (
        "link/exists",
        "link <root>/f <root>/f: file exists",
        false,
        true,
    ),
    (
        "rename/missing",
        "rename <root>/nope <root>/f2: no such file or directory",
        true,
        false,
    ),
    (
        "rename/dirover",
        "rename <root>/f <root>/d: file exists",
        false,
        true,
    ),
    // newname is an existing dir AND oldname does not exist. Go re-stats
    // oldname and reports THAT error, not EEXIST — "prioritize returning
    // the oldname error because that's what we did historically"
    // (os/file_unix.go). Returning EEXIST as soon as a directory is seen
    // at newname passes rename/dirover above and fails this.
    (
        "rename/missingoverdir",
        "rename <root>/nope <root>/d: no such file or directory",
        true,
        false,
    ),
    ("rename/ok", "", false, false),
    (
        "remove/missing",
        "remove <root>/nope: no such file or directory",
        true,
        false,
    ),
];

#[goish::main]
fn main() {
    let mut failed = 0;

    let (root, derr) = os::MkdirTemp("", "goish_link*");
    if !derr.IsNil() {
        fmt::Println!("cannot make a scratch dir:", derr.Error());
        syscall::Exit(1);
    }
    let j = |p: &str| root.clone() + s("/") + s(p);

    let _ = os::WriteFile(j("f"), goish::bytes("x"), FileMode(0o644));
    let _ = os::Mkdir(j("d"), FileMode(0o755));
    let _ = os::Symlink(j("f"), j("l"));

    let mut got: alloc::vec::Vec<(string, string, bool, bool)> = alloc::vec::Vec::new();
    let mut push = |tag: &str, e: error| {
        let text = if e.IsNil() {
            string::new()
        } else {
            strip(&e.Error(), &root)
        };
        got.push((
            s(tag),
            text,
            os::IsNotExist(e.clone()),
            os::IsExist(e.clone()),
        ));
    };

    push("chdir/missing", os::Chdir(j("nope")));
    push("chdir/file", os::Chdir(j("f")));
    push("chmod/missing", os::Chmod(j("nope"), FileMode(0o644)));
    push("chmod/ok", os::Chmod(j("f"), FileMode(0o644)));
    push("chown/missing", os::Chown(j("nope"), -1, -1));
    push("lchown/missing", os::Lchown(j("nope"), -1, -1));
    push("truncate/missing", os::Truncate(j("nope"), 0));
    push("truncate/ok", os::Truncate(j("f"), 1));
    let (_, rl1) = os::Readlink(j("f"));
    push("readlink/notlink", rl1);
    let (_, rl2) = os::Readlink(j("nope"));
    push("readlink/missing", rl2);
    let now = goish::time::Now();
    push("chtimes/missing", os::Chtimes(j("nope"), now, now));
    push("symlink/exists", os::Symlink(j("f"), j("l")));
    push("symlink/badnew", os::Symlink(j("f"), j("nodir/x")));
    push("link/missing", os::Link(j("nope"), j("l2")));
    push("link/exists", os::Link(j("f"), j("f")));
    push("rename/missing", os::Rename(j("nope"), j("f2")));
    push("rename/dirover", os::Rename(j("f"), j("d")));
    push("rename/missingoverdir", os::Rename(j("nope"), j("d")));
    push("rename/ok", os::Rename(j("f"), j("f2")));
    push("remove/missing", os::Remove(j("nope")));

    // 1. Every operation, text and classification, against Go's.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < CASES.len() {
            let (tag, want, wn, we) = CASES[i];
            let mut found = false;
            let mut k = 0usize;
            while k < got.len() {
                if got[k].0 == s(tag) {
                    found = true;
                    if got[k].1 != s(want) || got[k].2 != wn || got[k].3 != we {
                        fmt::Println!(
                            "   ",
                            s(tag),
                            "want",
                            fmt::Sprintf!("%q", s(want)),
                            wn,
                            we,
                            "got",
                            fmt::Sprintf!("%q", got[k].1.clone()),
                            got[k].2,
                            got[k].3
                        );
                        ok = false;
                    }
                }
                k += 1;
            }
            if !found {
                fmt::Println!("   ", s(tag), "missing");
                ok = false;
            }
            i += 1;
        }
        report(
            &mut failed,
            ok,
            " 1",
            "every os op names its operation and path",
        );
    }

    // 2. The structured types are reachable. `errors::As` on a failed
    //    rename must find a *LinkError carrying BOTH paths, and on a
    //    failed chmod a *PathError — the whole point of returning a
    //    type rather than a string.
    {
        let mut ok = true;
        let re = os::Rename(j("nope"), j("f3"));
        match errors::As::<os::LinkError>(re) {
            Some(le) => {
                if le.Op != s("rename") || le.Old != j("nope") || le.New != j("f3") {
                    ok = false;
                }
                if !errors::Is(le.Err.clone(), fs::ErrNotExist) {
                    ok = false;
                }
            }
            None => ok = false,
        }
        let ce = os::Chmod(j("nope"), FileMode(0o644));
        match errors::As::<fs::PathError>(ce) {
            Some(pe) => {
                if pe.Op != s("chmod") || pe.Path != j("nope") {
                    ok = false;
                }
            }
            None => ok = false,
        }
        report(
            &mut failed,
            ok,
            " 2",
            "As reaches *LinkError and *PathError",
        );
    }

    // 3. LinkError renders "Op Old New: err" and unwraps to it.
    //    Go: linkerror text="rename a b: file already exists"
    //    unwrap="file already exists" isexist=true.
    {
        let mut ok = true;
        let le = errors::Wrap(os::LinkError {
            Op: s("rename"),
            Old: s("a"),
            New: s("b"),
            Err: fs::ErrExist.into(),
        });
        if le.Error() != s("rename a b: file already exists") {
            fmt::Println!("    got", le.Error());
            ok = false;
        }
        if errors::Unwrap(le.clone()).Error() != s("file already exists") {
            ok = false;
        }
        if !os::IsExist(le) {
            ok = false;
        }
        report(&mut failed, ok, " 3", "LinkError names both paths");
    }

    // 4. A closed *File. Go: seek/stat/read each answer
    //    "<op> <path>: file already closed", and errors.Is finds
    //    fs.ErrClosed underneath. goish answered with the bare
    //    sentinel — "file already closed", naming no file — and
    //    `Stat` did not check the descriptor at all, so it reported
    //    the raw EBADF from fstat instead.
    {
        let mut ok = true;
        let (mut f, oerr) = os::Open(j("f2"));
        if !oerr.IsNil() {
            fmt::Println!("    cannot open:", oerr.Error());
            ok = false;
        } else {
            let f = f.MustMut();
            let _ = f.Close();
            let (_, e1) = f.Seek(0, 0);
            let (_, e2) = f.Stat();
            let mut b = goish::make!([]byte, 1);
            let (_, e3) = f.Read(&mut b);
            let want: [(&str, &error); 3] = [("seek", &e1), ("stat", &e2), ("read", &e3)];
            let mut i = 0usize;
            while i < want.len() {
                let (op, e) = want[i];
                let expect = s(op) + s(" ") + j("f2") + s(": file already closed");
                if e.IsNil() || e.Error() != expect {
                    fmt::Println!("    closed", s(op), "got", e.Error());
                    ok = false;
                }
                if !errors::Is(e.clone(), fs::ErrClosed) {
                    ok = false;
                }
                i += 1;
            }
        }
        report(&mut failed, ok, " 4", "a closed File names the file");
    }

    let _ = os::RemoveAll(root);

    if failed == 0 {
        fmt::Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 4");
        syscall::Exit(1);
    }
}
