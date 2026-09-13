// nul_path_ref_smoke — a path carrying an embedded NUL must be REFUSED,
// not silently truncated at it.
//
// Appending a C terminator to a string that already contains one hands
// the kernel a SHORTER path than the caller wrote, so the call succeeds
// against a different file. Measured on goish before this landed:
//
//     os::ReadFile("<dir>/f\0junk")     err=<nil> data="SECRET"
//     Root::ReadFile("f\0junk")         err=<nil> data="SECRET"
//
// Both read `f`. A caller that builds a path from untrusted input and
// checks the *suffix* — ".txt", ".png", a per-user prefix — passes the
// check on the full string and then opens whatever is before the NUL.
// The same shape in `os::exec` is worse: it execs a different binary.
//
// Go closes this at one chokepoint, `syscall.BytePtrFromString`, which
// every wrapper routes through; goish now has `syscall::ByteSliceFromString`
// and does the same. This pins the RESULT of that at every entry point
// Go rejects, because a chokepoint only helps where it is called: the
// table below is what a caller sees, one line per operation.
//
// Every expected line is Go 1.25.5's own output, transcribed from a
// reference program rather than retyped. `$D` stands for the temporary
// directory and `<NUL>` for the byte itself, both substituted on each
// side, so the comparison never carries a raw NUL through a pipe.
//
// Three of these are not the shape you would guess, which is why they
// are measured and not assumed:
//
//   os.RemoveAll     op is "unlinkat", not "remove"
//   Root.RemoveAll   op is "RemoveAll" — capitalised, a Go quirk
//   exec.dir.envnil  reports the ENV error, because Go appends
//                    `PWD=<abs Dir>` when Env is nil and `dedupEnv`
//                    rejects the NUL there before the chdir is reached;
//                    with Env set, the same Dir gives "chdir …".

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use goish::os::exec;
use goish::types::int;
use goish::{fmt, os, string, strings, time};

static mut FAILED: int = 0;
static mut RUN: int = 0;

const GO: [&str; 49] = [
    "os.Open                err=open $D/f<NUL>junk: invalid argument",
    "os.OpenFile            err=open $D/f<NUL>junk: invalid argument",
    "os.Stat                err=stat $D/f<NUL>junk: invalid argument",
    "os.Lstat               err=lstat $D/f<NUL>junk: invalid argument",
    "os.Chdir               err=chdir $D/sub<NUL>junk: invalid argument",
    "os.Chmod               err=chmod $D/f<NUL>junk: invalid argument",
    "os.Symlink.new         err=symlink $D/f $D/f<NUL>junk: invalid argument",
    "os.Symlink.old         err=symlink $D/f<NUL>junk $D/lnk: invalid argument",
    "os.Readlink            err=readlink $D/f<NUL>junk: invalid argument",
    "os.Chtimes             err=chtimes $D/f<NUL>junk: invalid argument",
    "os.Rename.old          err=rename $D/f<NUL>junk $D/g: invalid argument",
    "os.Rename.new          err=rename $D/f $D/f<NUL>junk: invalid argument",
    "os.Link                err=link $D/f<NUL>junk $D/h: invalid argument",
    "os.Truncate            err=truncate $D/f<NUL>junk: invalid argument",
    "os.Chown               err=chown $D/f<NUL>junk: invalid argument",
    "os.Lchown              err=lchown $D/f<NUL>junk: invalid argument",
    "os.Mkdir               err=mkdir $D/f<NUL>junk: invalid argument",
    "os.Remove              err=remove $D/f<NUL>junk: invalid argument",
    "os.ReadFile            err=open $D/f<NUL>junk: invalid argument",
    "os.ReadFile.data       data=\"\"",
    "os.WriteFile           err=open $D/f<NUL>junk: invalid argument",
    "os.MkdirAll            err=mkdir $D/f<NUL>junk: invalid argument",
    "os.RemoveAll           err=unlinkat $D/f<NUL>junk: invalid argument",
    "Root.Open              err=openat f<NUL>junk: invalid argument",
    "Root.Stat              err=statat f<NUL>junk: invalid argument",
    "Root.Lstat             err=statat f<NUL>junk: invalid argument",
    "Root.Mkdir             err=mkdirat f<NUL>junk: invalid argument",
    "Root.Remove            err=removeat f<NUL>junk: invalid argument",
    "Root.Readlink          err=readlinkat f<NUL>junk: invalid argument",
    "Root.ReadFile          err=openat f<NUL>junk: invalid argument",
    "Root.ReadFile.data     data=\"\"",
    "Root.WriteFile         err=openat f<NUL>junk: invalid argument",
    "Root.Chmod             err=chmodat f<NUL>junk: invalid argument",
    "Root.Chown             err=chownat f<NUL>junk: invalid argument",
    "Root.Lchown            err=lchownat f<NUL>junk: invalid argument",
    "Root.Chtimes           err=chtimesat f<NUL>junk: invalid argument",
    "Root.Rename.old        err=renameat f<NUL>junk g: invalid argument",
    "Root.Rename.new        err=renameat f f<NUL>junk: invalid argument",
    "Root.Link              err=linkat f<NUL>junk h: invalid argument",
    "Root.Symlink.new       err=symlinkat f f<NUL>junk: invalid argument",
    "Root.MkdirAll          err=mkdirat f<NUL>junk: invalid argument",
    "Root.RemoveAll         err=RemoveAll f<NUL>junk: invalid argument",
    "Root.OpenRoot          err=openat sub<NUL>junk: invalid argument",
    "exec.path              err=fork/exec /bin/echo<NUL>junk: invalid argument",
    "exec.argv              err=fork/exec /bin/echo: invalid argument",
    "exec.env               err=exec: environment variable contains NUL",
    "exec.dir.envnil        err=exec: environment variable contains NUL",
    "exec.dir.envset        err=chdir $D/sub<NUL>junk: invalid argument",
    "exec.LookPath          err=exec: \"ec\\x00ho\": executable file not found in $PATH",
];

/// `dir + head + '\0' + tail` — the byte itself, not an escape.
fn nulpath(dir: &string, head: &'static str, tail: &'static str) -> string {
    let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    v.extend_from_slice(dir.as_bytes());
    v.extend_from_slice(head.as_bytes());
    v.push(0);
    v.extend_from_slice(tail.as_bytes());
    return string::from_bytes(&v);
}

/// The same substitutions the Go reference applied: the temporary
/// directory becomes `$D`, and a raw NUL becomes `<NUL>` so no line
/// carries one.
fn norm(dir: &string, s: string) -> string {
    let s = strings::ReplaceAll(s, dir.clone(), string::from_static("$D"));
    return strings::ReplaceAll(
        s,
        string::from_bytes(&[0u8]),
        string::from_static("<NUL>"),
    );
}

fn pad(label: &'static str) -> string {
    let mut out = string::from_static(label);
    while out.Len() < 22 {
        out = out + string::from_static(" ");
    }
    return out;
}

fn line(ln: &mut usize, got: string) {
    unsafe { RUN += 1 };
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        unsafe { FAILED += 1 };
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!(
            "[!!] line %d\n  got  %q\n  want %q\n",
            *ln as int + 1,
            got,
            GO[*ln]
        );
        unsafe { FAILED += 1 };
    }
    *ln += 1;
}

fn err_line(ln: &mut usize, dir: &string, label: &'static str, e: goish::errors::error) {
    let body = if e.IsNil() {
        string::from_static("<nil>")
    } else {
        norm(dir, e.Error())
    };
    line(ln, pad(label) + string::from_static(" err=") + body);
}

/// The assertion the whole fix exists for: the refused call must not
/// have returned another file's bytes.
fn data_line(
    ln: &mut usize,
    dir: &string,
    label: &'static str,
    b: goish::goslice::slice<u8>,
    e: goish::errors::error,
) {
    err_line(ln, dir, label, e);
    let mut got = string::from_static("");
    let n = goish::len(&b);
    let mut i: int = 0;
    while i < n {
        got = got + string::from_bytes(&[b[i]]);
        i += 1;
    }
    let mut lbl = string::from_static(label) + string::from_static(".data");
    while lbl.Len() < 22 {
        lbl = lbl + string::from_static(" ");
    }
    line(
        ln,
        lbl + fmt::Sprintf!(" data=%q", norm(dir, got)),
    );
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;
    let dir = os::TempDir() + string::from_static("/goish_nul_path");
    let _ = os::RemoveAll(dir.clone());
    let _ = os::MkdirAll(dir.clone(), os::FileMode(0o755));
    let _ = os::WriteFile(
        dir.clone() + string::from_static("/f"),
        b"SECRET".as_ref(),
        os::FileMode(0o644),
    );
    let _ = os::Mkdir(
        dir.clone() + string::from_static("/sub"),
        os::FileMode(0o755),
    );

    let bad = nulpath(&dir, "/f", "junk");
    let badsub = nulpath(&dir, "/sub", "junk");
    let good = dir.clone() + string::from_static("/f");
    let z = time::Unix(0, 0);

    // ── plain os ────────────────────────────────────────────────────
    let (_, e) = os::Open(bad.clone());
    err_line(&mut ln, &dir, "os.Open", e);
    let (_, e) = os::OpenFile(bad.clone(), os::O_RDONLY, os::FileMode(0));
    err_line(&mut ln, &dir, "os.OpenFile", e);
    let (_, e) = os::Stat(bad.clone());
    err_line(&mut ln, &dir, "os.Stat", e);
    let (_, e) = os::Lstat(bad.clone());
    err_line(&mut ln, &dir, "os.Lstat", e);
    err_line(&mut ln, &dir, "os.Chdir", os::Chdir(badsub.clone()));
    err_line(
        &mut ln,
        &dir,
        "os.Chmod",
        os::Chmod(bad.clone(), os::FileMode(0o644)),
    );
    err_line(
        &mut ln,
        &dir,
        "os.Symlink.new",
        os::Symlink(good.clone(), bad.clone()),
    );
    err_line(
        &mut ln,
        &dir,
        "os.Symlink.old",
        os::Symlink(bad.clone(), dir.clone() + string::from_static("/lnk")),
    );
    let (_, e) = os::Readlink(bad.clone());
    err_line(&mut ln, &dir, "os.Readlink", e);
    err_line(
        &mut ln,
        &dir,
        "os.Chtimes",
        os::Chtimes(bad.clone(), z.clone(), z.clone()),
    );
    err_line(
        &mut ln,
        &dir,
        "os.Rename.old",
        os::Rename(bad.clone(), dir.clone() + string::from_static("/g")),
    );
    err_line(
        &mut ln,
        &dir,
        "os.Rename.new",
        os::Rename(good.clone(), bad.clone()),
    );
    err_line(
        &mut ln,
        &dir,
        "os.Link",
        os::Link(bad.clone(), dir.clone() + string::from_static("/h")),
    );
    err_line(&mut ln, &dir, "os.Truncate", os::Truncate(bad.clone(), 0));
    err_line(&mut ln, &dir, "os.Chown", os::Chown(bad.clone(), -1, -1));
    err_line(&mut ln, &dir, "os.Lchown", os::Lchown(bad.clone(), -1, -1));
    err_line(
        &mut ln,
        &dir,
        "os.Mkdir",
        os::Mkdir(bad.clone(), os::FileMode(0o755)),
    );
    err_line(&mut ln, &dir, "os.Remove", os::Remove(bad.clone()));
    let (b, e) = os::ReadFile(bad.clone());
    data_line(&mut ln, &dir, "os.ReadFile", b, e);
    err_line(
        &mut ln,
        &dir,
        "os.WriteFile",
        os::WriteFile(bad.clone(), b"x".as_ref(), os::FileMode(0o644)),
    );
    err_line(
        &mut ln,
        &dir,
        "os.MkdirAll",
        os::MkdirAll(bad.clone(), os::FileMode(0o755)),
    );
    err_line(&mut ln, &dir, "os.RemoveAll", os::RemoveAll(bad.clone()));

    // ── Root ────────────────────────────────────────────────────────
    let (r, oerr) = os::OpenRoot(dir.clone());
    if !oerr.IsNil() {
        fmt::Printf!("[!!] OpenRoot: %s\n", oerr.Error());
        os::Exit(1);
    }
    let r = r.MustTake();
    let rbad = nulpath(&string::from_static(""), "f", "junk");
    let rsub = nulpath(&string::from_static(""), "sub", "junk");

    let (_, e) = r.Open(rbad.clone());
    err_line(&mut ln, &dir, "Root.Open", e);
    let (_, e) = r.Stat(rbad.clone());
    err_line(&mut ln, &dir, "Root.Stat", e);
    let (_, e) = r.Lstat(rbad.clone());
    err_line(&mut ln, &dir, "Root.Lstat", e);
    err_line(
        &mut ln,
        &dir,
        "Root.Mkdir",
        r.Mkdir(rbad.clone(), os::FileMode(0o755)),
    );
    err_line(&mut ln, &dir, "Root.Remove", r.Remove(rbad.clone()));
    let (_, e) = r.Readlink(rbad.clone());
    err_line(&mut ln, &dir, "Root.Readlink", e);
    let (b, e) = r.ReadFile(rbad.clone());
    data_line(&mut ln, &dir, "Root.ReadFile", b, e);
    err_line(
        &mut ln,
        &dir,
        "Root.WriteFile",
        r.WriteFile(rbad.clone(), b"x".as_ref(), os::FileMode(0o644)),
    );
    err_line(
        &mut ln,
        &dir,
        "Root.Chmod",
        r.Chmod(rbad.clone(), os::FileMode(0o644)),
    );
    err_line(&mut ln, &dir, "Root.Chown", r.Chown(rbad.clone(), -1, -1));
    err_line(&mut ln, &dir, "Root.Lchown", r.Lchown(rbad.clone(), -1, -1));
    err_line(
        &mut ln,
        &dir,
        "Root.Chtimes",
        r.Chtimes(rbad.clone(), z.clone(), z.clone()),
    );
    err_line(
        &mut ln,
        &dir,
        "Root.Rename.old",
        r.Rename(rbad.clone(), string::from_static("g")),
    );
    err_line(
        &mut ln,
        &dir,
        "Root.Rename.new",
        r.Rename(string::from_static("f"), rbad.clone()),
    );
    err_line(
        &mut ln,
        &dir,
        "Root.Link",
        r.Link(rbad.clone(), string::from_static("h")),
    );
    err_line(
        &mut ln,
        &dir,
        "Root.Symlink.new",
        r.Symlink(string::from_static("f"), rbad.clone()),
    );
    err_line(
        &mut ln,
        &dir,
        "Root.MkdirAll",
        r.MkdirAll(rbad.clone(), os::FileMode(0o755)),
    );
    err_line(&mut ln, &dir, "Root.RemoveAll", r.RemoveAll(rbad.clone()));
    let (_, e) = r.OpenRoot(rsub.clone());
    err_line(&mut ln, &dir, "Root.OpenRoot", e);
    let _ = r.Close();

    // ── os/exec ─────────────────────────────────────────────────────
    let sh = string::from_static("/bin/echo");
    let hi = goish::slice!([]string{string::from_static("hi")});

    let mut c = exec::Command(
        nulpath(&string::from_static(""), "/bin/echo", "junk"),
        hi.clone(),
    );
    err_line(&mut ln, &dir, "exec.path", c.Run());

    let mut c = exec::Command(
        sh.clone(),
        goish::slice!([]string{nulpath(&string::from_static(""), "hi", "junk")}),
    );
    err_line(&mut ln, &dir, "exec.argv", c.Run());

    let mut c = exec::Command(sh.clone(), hi.clone());
    c.Env = goish::slice!([]string{nulpath(&string::from_static(""), "A=b", "c")});
    err_line(&mut ln, &dir, "exec.env", c.Run());

    let mut c = exec::Command(sh.clone(), hi.clone());
    c.Dir = badsub.clone();
    err_line(&mut ln, &dir, "exec.dir.envnil", c.Run());

    let mut c = exec::Command(sh.clone(), hi.clone());
    c.Dir = badsub.clone();
    c.Env = goish::slice!([]string{string::from_static("A=b")});
    err_line(&mut ln, &dir, "exec.dir.envset", c.Run());

    let (_, e) = exec::LookPath(nulpath(&string::from_static(""), "ec", "ho"));
    err_line(&mut ln, &dir, "exec.LookPath", e);

    let _ = os::RemoveAll(dir.clone());

    let run = unsafe { RUN };
    let f = unsafe { FAILED };
    if run != GO.len() as int {
        fmt::Printf!("\nFAIL ran %d of %d rows\n", run, GO.len() as int);
        os::Exit(1);
    }
    if f == 0 {
        fmt::Printf!("\nok %d/%d\n", run, run);
        os::Exit(0);
    }
    fmt::Printf!("\nFAIL %d\n", f);
    os::Exit(1);
}
