// os_error_ref_smoke — os's error predicates against a running Go.
// (os/error.go, syscall/syscall_unix.go, internal/poll/fd.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_os_error_ref.go` run in `package os_test`
// by `scripts/goref.sh`.
//
// `os.IsNotExist` and its two siblings are not equality tests. Each
// calls `underlyingErrorIs`, which peels one layer off the error-
// wrapping types os itself builds and then, for a `syscall.Errno`,
// consults `Errno.Is` — the table that says ENOENT means ErrNotExist,
// EEXIST or ENOTEMPTY mean ErrExist, EACCES or EPERM mean ErrPermission.
//
// goish had written all three as `err == ErrNotExist`. That is false
// for every error os itself returns, because os returns *PathError. It
// only ever answered true because goish's own Stat and Open returned
// the bare sentinel instead of a *PathError — two bugs that cancelled
// on one path and on no other. `Lstat` returned a flat "lstat failed"
// for every errno, so the same missing path was IsNotExist through
// `Stat` and not through `Lstat`.
//
// What was missing outright: `Errno.Is`, `Errno.Timeout`,
// `Errno.Temporary`, `SyscallError`, `NewSyscallError`, `IsTimeout`,
// `ErrDeadlineExceeded`, `ErrNoDeadline` — and, less visibly,
// `os::PathError` was a SECOND struct rather than Go's `type PathError
// = fs.PathError`, so the tree carried two unrelated types with the
// same three fields and an assertion for one missed the other.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::errors;
use goish::gostring::string;
use goish::io::fs;
use goish::os;
use goish::syscall;
use goish::types::int;
use goish::{error, fmt};

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

fn pathErr(op: &str, path: &str, e: error) -> error {
    return errors::Wrap(fs::PathError {
        Op: s(op),
        Path: s(path),
        Err: e,
    });
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. os.IsExist / IsNotExist / IsPermission / IsTimeout, over every
    //    error shape Go's own reference walks. Columns are Go's, verbatim.
    //
    //    (name, err, exist, notexist, perm, timeout)
    {
        let mut ok = true;
        let cases: [(&str, error, bool, bool, bool, bool); 26] = [
            ("nil", errors::nil, false, false, false, false),
            (
                "ErrNotExist",
                fs::ErrNotExist.into(),
                false,
                true,
                false,
                false,
            ),
            ("ErrExist", fs::ErrExist.into(), true, false, false, false),
            (
                "ErrPermission",
                fs::ErrPermission.into(),
                false,
                false,
                true,
                false,
            ),
            (
                "ErrClosed",
                fs::ErrClosed.into(),
                false,
                false,
                false,
                false,
            ),
            (
                "ErrInvalid",
                fs::ErrInvalid.into(),
                false,
                false,
                false,
                false,
            ),
            ("ENOENT", syscall::ENOENT.into(), false, true, false, false),
            ("EEXIST", syscall::EEXIST.into(), true, false, false, false),
            (
                "ENOTEMPTY",
                syscall::ENOTEMPTY.into(),
                true,
                false,
                false,
                false,
            ),
            ("EACCES", syscall::EACCES.into(), false, false, true, false),
            ("EPERM", syscall::EPERM.into(), false, false, true, false),
            (
                "ENOTDIR",
                syscall::ENOTDIR.into(),
                false,
                false,
                false,
                false,
            ),
            ("EINVAL", syscall::EINVAL.into(), false, false, false, false),
            ("EAGAIN", syscall::EAGAIN.into(), false, false, false, true),
            (
                "ETIMEDOUT",
                syscall::ETIMEDOUT.into(),
                false,
                false,
                false,
                true,
            ),
            ("ENOSYS", syscall::ENOSYS.into(), false, false, false, false),
            (
                "path/ENOENT",
                pathErr("open", "/x", syscall::ENOENT.into()),
                false,
                true,
                false,
                false,
            ),
            (
                "path/EEXIST",
                pathErr("mkdir", "/x", syscall::EEXIST.into()),
                true,
                false,
                false,
                false,
            ),
            (
                "path/EACCES",
                pathErr("open", "/x", syscall::EACCES.into()),
                false,
                false,
                true,
                false,
            ),
            (
                "path/ErrNotExist",
                pathErr("stat", "/x", fs::ErrNotExist.into()),
                false,
                true,
                false,
                false,
            ),
            (
                "path/ErrClosed",
                pathErr("read", "/x", fs::ErrClosed.into()),
                false,
                false,
                false,
                false,
            ),
            (
                "syscallerr/ENOENT",
                os::NewSyscallError("open", syscall::ENOENT.into()),
                false,
                true,
                false,
                false,
            ),
            (
                "syscallerr/ETIMEDOUT",
                os::NewSyscallError("read", syscall::ETIMEDOUT.into()),
                false,
                false,
                false,
                true,
            ),
            (
                "deadline",
                os::ErrDeadlineExceeded.into(),
                false,
                false,
                false,
                true,
            ),
            (
                "nodeadline",
                os::ErrNoDeadline.into(),
                false,
                false,
                false,
                false,
            ),
            ("plain", errors::New("plain"), false, false, false, false),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (name, ref e, we, wn, wp, wt) = cases[i];
            if os::IsExist(e.clone()) != we
                || os::IsNotExist(e.clone()) != wn
                || os::IsPermission(e.clone()) != wp
                || os::IsTimeout(e.clone()) != wt
            {
                fmt::Println!(
                    "   ",
                    s(name),
                    "got",
                    os::IsExist(e.clone()),
                    os::IsNotExist(e.clone()),
                    os::IsPermission(e.clone()),
                    os::IsTimeout(e.clone()),
                    "want",
                    we,
                    wn,
                    wp,
                    wt
                );
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 1", "os.Is* over every error shape");
    }

    // 2. `errors.Is` is the modern spelling, and it agrees with the
    //    predicates above everywhere except one place — see check 3.
    //    None of this worked before `Errno.Is` existed.
    {
        let mut ok = true;
        // (errno, notexist, exist, perm, unsupported)
        let cases: [(syscall::Errno, bool, bool, bool, bool); 10] = [
            (syscall::ENOENT, true, false, false, false),
            (syscall::EEXIST, false, true, false, false),
            (syscall::ENOTEMPTY, false, true, false, false),
            (syscall::EACCES, false, false, true, false),
            (syscall::EPERM, false, false, true, false),
            (syscall::ENOTDIR, false, false, false, false),
            (syscall::EINVAL, false, false, false, false),
            (syscall::EAGAIN, false, false, false, false),
            (syscall::ETIMEDOUT, false, false, false, false),
            (syscall::ENOSYS, false, false, false, true),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (e, wn, we, wp, wu) = cases[i];
            let err: error = e.into();
            if errors::Is(err.clone(), fs::ErrNotExist) != wn
                || errors::Is(err.clone(), fs::ErrExist) != we
                || errors::Is(err.clone(), fs::ErrPermission) != wp
                || errors::Is(err.clone(), errors::ErrUnsupported) != wu
            {
                fmt::Println!("    errno", e.0, "row differs");
                ok = false;
            }
            i += 1;
        }
        // And through a PathError, which errors.Is walks and the
        // historical predicates peel.
        let pe = pathErr("open", "/x", syscall::ENOENT.into());
        if !errors::Is(pe, fs::ErrNotExist) {
            ok = false;
        }
        report(&mut failed, ok, " 2", "errors.Is reaches the errno table");
    }

    // 3. The one place the two spellings disagree. Go's comment is
    //    explicit that it is deliberate: "underlyingError only unwraps
    //    the specific error-wrapping types that it historically did,
    //    not all errors implementing Unwrap()."
    //
    //    Go: is wrapped-fmt notexist=false / errorsis wrapped-fmt
    //    notexist=true.
    {
        let wrapped = fmt::Errorf!("ctx: %w", errors::error::from(syscall::ENOENT));
        let ok = !os::IsNotExist(wrapped.clone()) && errors::Is(wrapped, fs::ErrNotExist);
        report(
            &mut failed,
            ok,
            " 3",
            "IsNotExist does not walk %w; errors.Is does",
        );
    }

    // 4. Errno's own predicates, and the messages behind them.
    //    (errno, timeout, temporary, text)
    {
        let mut ok = true;
        let cases: [(syscall::Errno, bool, bool, &str); 9] = [
            (
                syscall::EAGAIN,
                true,
                true,
                "resource temporarily unavailable",
            ),
            (
                syscall::EWOULDBLOCK,
                true,
                true,
                "resource temporarily unavailable",
            ),
            (syscall::ETIMEDOUT, true, true, "connection timed out"),
            (syscall::EINTR, false, true, "interrupted system call"),
            (syscall::EMFILE, false, true, "too many open files"),
            (
                syscall::ENFILE,
                false,
                true,
                "too many open files in system",
            ),
            (syscall::ENOENT, false, false, "no such file or directory"),
            (syscall::ENOSYS, false, false, "function not implemented"),
            (syscall::ENOTSUP, false, false, "operation not supported"),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (e, wt, wp, text) = cases[i];
            if e.Timeout() != wt || e.Temporary() != wp || e.Error() != s(text) {
                fmt::Println!("    errno", e.0, "differs:", e.Error());
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 4", "Errno.Timeout/.Temporary/.Error");
    }

    // 5. SyscallError. Go: text="pipe2: too many open files",
    //    unwrap="too many open files", nil-in-nil-out, and errors.As
    //    finds it with Syscall="pipe2".
    {
        let mut ok = true;
        let se = os::NewSyscallError("pipe2", syscall::EMFILE.into());
        if se.Error() != s("pipe2: too many open files") {
            ok = false;
        }
        if errors::Unwrap(se.clone()).Error() != s("too many open files") {
            ok = false;
        }
        if !os::NewSyscallError("x", errors::nil).IsNil() {
            ok = false;
        }
        let (target, hit) = se.As::<os::SyscallError>();
        if !hit || target.Syscall != s("pipe2") {
            ok = false;
        }
        // Go: `(*SyscallError).Timeout` asserts `timeout` on the error
        // it wraps, so an ETIMEDOUT inside one is a timeout and an
        // ENOENT is not. Go: is syscallerr/ETIMEDOUT timeout=true,
        // is syscallerr/ENOENT timeout=false.
        let (te, hit_t) =
            os::NewSyscallError("read", syscall::ETIMEDOUT.into()).As::<os::SyscallError>();
        if !hit_t || !te.Timeout() {
            ok = false;
        }
        let (ne, hit_n) =
            os::NewSyscallError("open", syscall::ENOENT.into()).As::<os::SyscallError>();
        if !hit_n || ne.Timeout() {
            ok = false;
        }
        report(
            &mut failed,
            ok,
            " 5",
            "SyscallError (text, unwrap, nil, As)",
        );
    }

    // 6. os.Setenv's three rejections are one wrapped EINVAL in Go, so
    //    all three read "setenv: invalid argument". goish had three
    //    hand-written strings, one of which ("setenv: key is empty") Go
    //    never produces.
    {
        let mut ok = true;
        let cases: [(&str, &str, bool); 5] = [
            ("", "x", false),
            ("a=b", "x", false),
            ("a\u{0}b", "x", false),
            ("k", "v\u{0}w", false),
            ("k", "v", true),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (k, v, want_nil) = cases[i];
            let e = os::Setenv(s(k), s(v));
            if e.IsNil() != want_nil {
                ok = false;
            } else if !want_nil && e.Error() != s("setenv: invalid argument") {
                fmt::Println!("    setenv", s(k), "got", e.Error());
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 6", "Setenv wraps EINVAL, once");
    }

    // 7. End to end. Go: open text="open /definitely/not/here: no such
    //    file or directory" isnotexist=true errorsis=true, and
    //    errors.As reaches the *PathError with Op="open".
    //
    //    goish returned the bare ErrNotExist sentinel here — "file does
    //    not exist", naming no file — and Lstat returned "lstat failed"
    //    for every errno at all.
    {
        let mut ok = true;
        let (_, err) = os::Open("/definitely/not/here");
        if err.Error() != s("open /definitely/not/here: no such file or directory") {
            fmt::Println!("    open got", err.Error());
            ok = false;
        }
        if !os::IsNotExist(err.clone()) || !errors::Is(err.clone(), fs::ErrNotExist) {
            ok = false;
        }
        match errors::As::<fs::PathError>(err) {
            Some(pe) => {
                if pe.Op != s("open") {
                    ok = false;
                }
            }
            None => ok = false,
        }
        // Stat and Lstat agree with each other and with Go's wording.
        let (_, se) = os::Stat("/definitely/not/here");
        if se.Error() != s("stat /definitely/not/here: no such file or directory") {
            fmt::Println!("    stat got", se.Error());
            ok = false;
        }
        let (_, le) = os::Lstat("/definitely/not/here");
        if le.Error() != s("lstat /definitely/not/here: no such file or directory") {
            fmt::Println!("    lstat got", le.Error());
            ok = false;
        }
        if !os::IsNotExist(se) || !os::IsNotExist(le) {
            ok = false;
        }
        report(&mut failed, ok, " 7", "Open/Stat/Lstat return *PathError");
    }

    if failed == 0 {
        fmt::Println!("ok 7/7");
        goish::syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 7");
        goish::syscall::Exit(1);
    }
}
