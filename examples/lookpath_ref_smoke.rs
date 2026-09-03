// lookpath_ref_smoke — os/exec's LookPath against a running Go.
// (os/exec/lp_unix.go, os/exec/exec.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_lookpath_ref.go` run in
// `package exec_test` by `scripts/goref.sh`. Everything runs against a
// $PATH and a directory tree the test builds, so no answer depends on
// what the machine happens to have installed.
//
// LookPath decides WHICH binary runs. Everything about a program's
// behaviour follows from that answer, so its rules are a security
// surface even though nothing in the API says so. Four of them were
// wrong.
//
//   * NO ErrDot. Go 1.19 made a name that resolves through a RELATIVE
//     $PATH entry return this error alongside the path it found,
//     because running whatever happens to sit in the current directory
//     is how a build tool becomes an arbitrary-code-execution vector
//     (CVE-2022-30580 and siblings). goish returned the path with no
//     error at all. Note that Go still RETURNS the path: the caller is
//     told what was found and left to decide, which is why the error
//     has to be checked rather than assumed absent.
//   * AN EMPTY $PATH ENTRY IS ".". Unix shells read it that way and so
//     does Go, which is the same hazard spelled with nothing at all —
//     "PATH=:/usr/bin" searches the current directory first. goish
//     SKIPPED empty elements, which is safer but not Go, and quietly
//     so: the difference only shows when a binary of that name is
//     sitting in the working directory.
//   * A NON-EXECUTABLE FILE COUNTED AS FOUND. goish stopped at "is
//     there a regular file here", with a comment reasoning that "$PATH
//     lookups by definition target executables" — which is the
//     assumption the check exists to test. A non-executable file
//     EARLIER on $PATH shadowed the real binary later on it, so the
//     lookup selected the wrong file and the exec failed. Go asks the
//     kernel through Eaccess(X_OK); goish reads the mode bits against
//     the caller's identity, which is stricter than Go in the
//     supplementary-group and capability cases, never looser.
//   * A NAME WITH A SLASH WAS RETURNED UNCHECKED. Go skips the SEARCH
//     for such a name, not the CHECK — "/nonexistent/xyz" is an error,
//     not a path. A caller reading a successful LookPath as "this is
//     runnable" was wrong for every name containing a slash.
//
// A fifth, smaller: every failure is wrapped in exec.Error, whose
// message quotes the name — `exec: "missing": executable file not
// found in $PATH`. goish returned the bare sentinel, so the name was
// lost and every message differed from Go's. errors.Is still reaches
// the sentinel through Unwrap, which is what the `kind` column checks.
//
// The last section pins the property all of this exists to protect:
// arguments reach the executable DIRECTLY. There is no shell, so
// "$HOME", "a; echo pwned", "`echo pwned`" and "$(echo pwned)" are
// each passed through as literal text. Stdout is captured through an
// explicit buffer rather than Output(), because goish's os/exec is a
// documented minimal port without it — what is being measured is the
// argv, not the convenience wrapper.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::vec::Vec;
use goish::bytes;
use goish::errors;
use goish::errors::error;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::os;
use goish::os::exec;
use goish::path::filepath;
use goish::strings;
use goish::syscall;
use goish::types::int;
const GO: [&str; 34] = [
    "look abs-path:tool              -> path=\"bin/tool\"             kind=<nil>         err=\"<nil>\"",
    "look abs-path:only-other        -> path=\"other/only-other\"     kind=<nil>         err=\"<nil>\"",
    "look abs-path:plain             -> path=\"\"                     kind=ErrNotFound   err=\"exec: \\\"plain\\\": executable file not found in $PATH\"",
    "look abs-path:adir              -> path=\"\"                     kind=ErrNotFound   err=\"exec: \\\"adir\\\": executable file not found in $PATH\"",
    "look abs-path:missing           -> path=\"\"                     kind=ErrNotFound   err=\"exec: \\\"missing\\\": executable file not found in $PATH\"",
    "look abs-path:<empty>           -> path=\"\"                     kind=ErrNotFound   err=\"exec: \\\"\\\": executable file not found in $PATH\"",
    "look abs-path:./cwdtool         -> path=\"./cwdtool\"            kind=<nil>         err=\"<nil>\"",
    "look abs-path:cwdtool           -> path=\"\"                     kind=ErrNotFound   err=\"exec: \\\"cwdtool\\\": executable file not found in $PATH\"",
    "look abs-path:reldir/reltool    -> path=\"reldir/reltool\"       kind=<nil>         err=\"<nil>\"",
    "look abs-path:/bin/sh           -> path=\"/bin/sh\"              kind=<nil>         err=\"<nil>\"",
    "look abs-path:/nonexistent/xyz  -> path=\"\"                     kind=other         err=\"exec: \\\"/nonexistent/xyz\\\": stat /nonexistent/xyz: no such file or directory\"",
    "look abs-path:bin/tool          -> path=\"bin/tool\"             kind=<nil>         err=\"<nil>\"",
    "look abs-path:../base/bin/tool  -> path=\"\"                     kind=other         err=\"exec: \\\"../base/bin/tool\\\": stat ../base/bin/tool: no such file or directory\"",
    "look rel-path:reltool           -> path=\"reldir/reltool\"       kind=ErrDot        err=\"exec: \\\"reltool\\\": cannot run executable found relative to current directory\"",
    "look rel-path:tool              -> path=\"\"                     kind=ErrNotFound   err=\"exec: \\\"tool\\\": executable file not found in $PATH\"",
    "look rel-path:missing           -> path=\"\"                     kind=ErrNotFound   err=\"exec: \\\"missing\\\": executable file not found in $PATH\"",
    "look empty-entry:cwdtool        -> path=\"cwdtool\"              kind=ErrDot        err=\"exec: \\\"cwdtool\\\": cannot run executable found relative to current directory\"",
    "look empty-entry:tool           -> path=\"bin/tool\"             kind=<nil>         err=\"<nil>\"",
    "look trailing-entry:cwdtool     -> path=\"cwdtool\"              kind=ErrDot        err=\"exec: \\\"cwdtool\\\": cannot run executable found relative to current directory\"",
    "look trailing-entry:tool        -> path=\"bin/tool\"             kind=<nil>         err=\"<nil>\"",
    "look empty-PATH:tool            -> path=\"\"                     kind=ErrNotFound   err=\"exec: \\\"tool\\\": executable file not found in $PATH\"",
    "look empty-PATH:cwdtool         -> path=\"\"                     kind=ErrNotFound   err=\"exec: \\\"cwdtool\\\": executable file not found in $PATH\"",
    "look empty-PATH:/bin/sh         -> path=\"/bin/sh\"              kind=<nil>         err=\"<nil>\"",
    "look empty-dir:tool             -> path=\"\"                     kind=ErrNotFound   err=\"exec: \\\"tool\\\": executable file not found in $PATH\"",
    "look missing-dir-first:tool     -> path=\"bin/tool\"             kind=<nil>         err=\"<nil>\"",
    "noshell \"hello\"            -> out=\"hello\\n\" err=<nil>",
    "noshell \"$HOME\"            -> out=\"$HOME\\n\" err=<nil>",
    "noshell \"a; echo pwned\"    -> out=\"a; echo pwned\\n\" err=<nil>",
    "noshell \"a && echo pwned\"  -> out=\"a && echo pwned\\n\" err=<nil>",
    "noshell \"*\"                -> out=\"*\\n\" err=<nil>",
    "noshell \"`echo pwned`\"     -> out=\"`echo pwned`\\n\" err=<nil>",
    "noshell \"$(echo pwned)\"    -> out=\"$(echo pwned)\\n\" err=<nil>",
    "noshell \"a\\nb\"             -> out=\"a\\nb\\n\" err=<nil>",
    "noshell \"a b|c\"            -> out=\"a b c\\n\" err=<nil>",
];

fn chk(failed: &mut int, ln: &mut int, got: string) {
    if *ln >= GO.len() as int {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln + 1, got);
        *failed += 1;
        *ln += 1;
        return;
    }
    let want = s(GO[*ln as usize]);
    *ln += 1;
    if got == want {
        return;
    }
    fmt::Printf!("[!!] line %d FAIL\n  got  %q\n  want %q\n", *ln, got, want);
    *failed += 1;
}

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn errText(err: error) -> string {
    if err == goish::nil {
        return s("<nil>");
    }
    return err.Error();
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    let (base, terr) = os::MkdirTemp(string::new(), s("goish-lookpath"));
    if terr != goish::nil {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("[!!] tempdir: %q", terr.Error()),
        );
        return;
    }
    let binDir = filepath::Join(slice::__from_vec(alloc::vec![base.clone(), s("bin")]));
    let otherDir = filepath::Join(slice::__from_vec(alloc::vec![base.clone(), s("other")]));
    let emptyDir = filepath::Join(slice::__from_vec(alloc::vec![base.clone(), s("emptydir")]));
    let relDir = filepath::Join(slice::__from_vec(alloc::vec![base.clone(), s("reldir")]));
    for d in [
        binDir.clone(),
        otherDir.clone(),
        emptyDir.clone(),
        relDir.clone(),
    ] {
        let _ = os::MkdirAll(d, os::FileMode(0o755));
    }
    let _ = os::MkdirAll(
        filepath::Join(slice::__from_vec(alloc::vec![binDir.clone(), s("adir")])),
        os::FileMode(0o755),
    );
    let body = b"#!/bin/sh\nexit 0\n";
    let write = |p: string, mode: u32| {
        let _ = os::WriteFile(p, &body[..], os::FileMode(mode));
    };
    let j = |a: &string, b: &str| -> string {
        return filepath::Join(slice::__from_vec(alloc::vec![a.clone(), s(b)]));
    };
    write(j(&binDir, "tool"), 0o755);
    write(j(&binDir, "plain"), 0o644);
    write(j(&otherDir, "tool"), 0o755);
    write(j(&otherDir, "only-other"), 0o755);
    write(j(&relDir, "reltool"), 0o755);
    write(j(&base, "cwdtool"), 0o755);
    let (cwd, _) = os::Getwd();
    let _ = os::Chdir(base.clone());
    let norm = |x: string| -> string {
        let a = strings::ReplaceAll(x, base.clone() + "/", string::new());
        return strings::ReplaceAll(a, base.clone(), s("<tmp>"));
    };
    let mut show = |label: string, path: string, err: error| {
        let mut kind = s("<nil>");
        if err != goish::nil {
            kind = s("other");
            if errors::Is(err.clone(), exec::ErrDot) {
                kind = s("ErrDot");
            } else if errors::Is(err.clone(), exec::ErrNotFound) {
                kind = s("ErrNotFound");
            } else if errors::Is(err.clone(), os::ErrPermission) {
                kind = s("ErrPermission");
            }
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "look %-26s -> path=%-22q kind=%-13s err=%q",
                label,
                norm(path),
                kind,
                norm(errText(err))
            ),
        );
    };
    let _ = os::Setenv(s("PATH"), binDir.clone() + ":" + otherDir.clone());
    for name in [
        "tool",
        "only-other",
        "plain",
        "adir",
        "missing",
        "",
        "./cwdtool",
        "cwdtool",
        "reldir/reltool",
        "/bin/sh",
        "/nonexistent/xyz",
        "bin/tool",
        "../base/bin/tool",
    ] {
        let (p, e) = exec::LookPath(s(name));
        let shown = if name == "" { s("<empty>") } else { s(name) };
        show(string::from("abs-path:") + shown, p, e);
    }
    let _ = os::Setenv(s("PATH"), s("reldir"));
    for name in ["reltool", "tool", "missing"] {
        let (p, e) = exec::LookPath(s(name));
        show(string::from("rel-path:") + s(name), p, e);
    }
    let _ = os::Setenv(s("PATH"), string::from(":") + binDir.clone());
    for name in ["cwdtool", "tool"] {
        let (p, e) = exec::LookPath(s(name));
        show(string::from("empty-entry:") + s(name), p, e);
    }
    let _ = os::Setenv(s("PATH"), binDir.clone() + ":");
    for name in ["cwdtool", "tool"] {
        let (p, e) = exec::LookPath(s(name));
        show(string::from("trailing-entry:") + s(name), p, e);
    }
    let _ = os::Setenv(s("PATH"), string::new());
    for name in ["tool", "cwdtool", "/bin/sh"] {
        let (p, e) = exec::LookPath(s(name));
        show(string::from("empty-PATH:") + s(name), p, e);
    }
    let _ = os::Setenv(s("PATH"), emptyDir.clone());
    let (p, e) = exec::LookPath(s("tool"));
    show(s("empty-dir:tool"), p, e);
    let _ = os::Setenv(s("PATH"), string::from("/no/such/dir:") + binDir.clone());
    let (p, e) = exec::LookPath(s("tool"));
    show(s("missing-dir-first:tool"), p, e);
    let _ = os::Setenv(s("PATH"), s("/usr/bin:/bin"));
    let argsets: [&[&str]; 9] = [
        &["hello"],
        &["$HOME"],
        &["a; echo pwned"],
        &["a && echo pwned"],
        &["*"],
        &["`echo pwned`"],
        &["$(echo pwned)"],
        &["a\nb"],
        &["a b", "c"],
    ];
    for args in argsets.iter() {
        let mut v: Vec<string> = Vec::new();
        for a in args.iter() {
            v.push(s(a));
        }
        let joined = strings::Join(slice::<string>::__from_vec(v.clone()), s("|"));
        let mut c = exec::Command(s("echo"), slice::<string>::__from_vec(v));
        let buf = bytes::Buffer::new();
        let shared = alloc::sync::Arc::new(goish::sync::Mutex::new(buf));
        c.SetStdout(SharedBuf(shared.clone()));
        let e = c.Run();
        let out = shared.Lock().String();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("noshell %-18q -> out=%q err=%s", joined, out, errText(e)),
        );
    }
    let _ = os::Chdir(cwd);
    let _ = os::RemoveAll(base);
    if ln != GO.len() as int {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln, GO.len() as int);
        failed += 1;
    }
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", ln, ln);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, ln);
    syscall::Exit(1);
}
// A Writer the probe can read back after Run returns.
struct SharedBuf(alloc::sync::Arc<goish::sync::Mutex<bytes::Buffer>>);
impl goish::io::Writer for SharedBuf {
    fn Write(&mut self, p: slice<goish::types::byte>) -> (int, error) {
        return self.0.Lock().Write(p);
    }
}
