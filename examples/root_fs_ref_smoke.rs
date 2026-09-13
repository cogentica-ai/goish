// root_fs_ref_smoke — `Root.FS()` and the `rootFS` adapter (§2q), and
// the `dirFS.Lstat`/`dirFS.ReadLink` pair Go 1.25 added for
// `io/fs.ReadLinkFS`.
//
// Two file systems that look alike and are not: `Root.FS()` is a
// BOUNDARY and `os::DirFS` is a prefix. The last row says it plainly —
// the same symlink out of the tree is refused by one
// (`statat escape: path escapes from parent`) and followed by the other
// (`data="SECRET"`). Both are Go's answers; the difference is the point
// of `Root`.
//
// Three things the reference pins that are easy to get wrong:
//
//   * The guard's op is the METHOD's, the failure's op is the WALK's.
//     `Open("/ok.txt")` is refused by `isValidRootFSPath` and says
//     `open`; `Open("nope.txt")` reaches the walk and says `openat`.
//     Six methods, six guard ops — `open readfile readdir readlink
//     stat lstat` — and none of them is the op you see once the name
//     is valid.
//   * `ValidPath(".")` is TRUE, so `Open(".")` succeeds and
//     `ReadDir(".")` is how you list a root. `"./ok.txt"`, `"sub/"`
//     and `"sub//deep.txt"` are all invalid.
//   * `dirFS` rewrites the error's Path back to the caller's name in
//     five methods and NOT in `ReadLink`, which returns
//     `Readlink(fullname)` verbatim. So `dirFS.Lstat` of a missing name
//     says `lstat nope: …` while `dirFS.ReadLink` of a non-link says
//     `readlink $D/inside/ok.txt: …`. goish did none of the five.
//
// Every expected line is Go 1.25.5's own output, transcribed from a
// reference program rather than retyped. `$D` stands for the temporary
// directory and `<NUL>` for the byte itself.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use goish::io::fs;
use goish::types::int;
use goish::{os, string, strings};

static mut FAILED: int = 0;
static mut RUN: int = 0;

const GO: [&str; 77] = [
    "ifaces                       StatFS=true ReadFileFS=true ReadDirFS=true ReadLinkFS=true",
    "Open:                        err=open : invalid argument",
    "Open:/ok.txt                 err=open /ok.txt: invalid argument",
    "Open:../secret.txt           err=open ../secret.txt: invalid argument",
    "Open:./ok.txt                err=open ./ok.txt: invalid argument",
    "Open:sub/                    err=open sub/: invalid argument",
    "Open:sub//deep.txt           err=open sub//deep.txt: invalid argument",
    "Open:.                       err=<nil>",
    "ValidPath(.)                 true",
    "Open:ok.txt                  err=<nil>",
    "Open:nope.txt                err=openat nope.txt: no such file or directory",
    "Open:escape                  err=openat escape: path escapes from parent",
    "ReadFile:ok.txt              err=<nil>",
    "ReadFile:ok.txt.v            val=\"hello\"",
    "ReadFile:/ok.txt             err=readfile /ok.txt: invalid argument",
    "ReadFile:/ok.txt.v           val=\"\"",
    "ReadFile:escape              err=openat escape: path escapes from parent",
    "ReadFile:escape.v            val=\"\"",
    "ReadFile:link                err=<nil>",
    "ReadFile:link.v              val=\"hello\"",
    "Stat:ok.txt                  err=<nil>",
    "Stat:ok.txt.m                dir=false mode=-rw-r--r--",
    "Stat:..                      err=stat ..: invalid argument",
    "Stat:link                    err=<nil>",
    "Stat:link.m                  symlink=false",
    "Lstat:link                   err=<nil>",
    "Lstat:link.m                 symlink=true",
    "Lstat:..                     err=lstat ..: invalid argument",
    "Stat:escape                  err=statat escape: path escapes from parent",
    "Lstat:escape                 err=<nil>",
    "Lstat:escape.m               symlink=true",
    "ReadLink:link                err=<nil>",
    "ReadLink:link.v              val=\"ok.txt\"",
    "ReadLink:escape              err=<nil>",
    "ReadLink:escape.v            val=\"../secret.txt\"",
    "ReadLink:ok.txt              err=readlinkat ok.txt: invalid argument",
    "ReadLink:ok.txt.v            val=\"\"",
    "ReadLink:..                  err=readlink ..: invalid argument",
    "ReadLink:...v                val=\"\"",
    "ReadDir:.                    err=<nil>",
    "ReadDir:..n                  dangling,dirlink,escape,link,ok.txt,sub",
    "ReadDir:ok.txt               err=readdirent $D/inside/ok.txt: not a directory",
    "ReadDir:/                    err=readdir /: invalid argument",
    "ReadDir:sub                  err=<nil>",
    "ReadDir:sub.n                deep.txt",
    "ReadFile:NUL                 err=openat ok<NUL>junk: invalid argument",
    "ReadFile:NUL.v               val=\"\"",
    "dirFS.ifaces                 StatFS=true ReadLinkFS=true",
    "dirFS.Lstat:link             err=<nil>",
    "dirFS.Lstat:link.m           symlink=true name=\"link\"",
    "dirFS.Lstat:nope             err=lstat nope: no such file or directory",
    "dirFS.Lstat:/abs             err=lstat /abs: invalid argument",
    "dirFS.ReadLink:link          err=<nil>",
    "dirFS.ReadLink:link.v        val=\"ok.txt\"",
    "dirFS.ReadLink:escape        err=<nil>",
    "dirFS.ReadLink:escape.v      val=\"../secret.txt\"",
    "dirFS.ReadLink:ok.txt        err=readlink $D/inside/ok.txt: invalid argument",
    "dirFS.ReadLink:ok.txt.v      val=\"\"",
    "dirFS.ReadLink:/abs          err=readlink /abs: invalid argument",
    "dirFS.ReadLink:/abs.v        val=\"\"",
    "dirFS.Open:nope              err=open nope: no such file or directory",
    "dirFS.ReadFile:nope          err=open nope: no such file or directory",
    "dirFS.ReadFile:nope.v        val=\"\"",
    "dirFS.ReadDir:nope           err=open nope: no such file or directory",
    "dirFS.ReadDir:ok.txt         err=open ok.txt: not a directory",
    "dirFS.Stat:nope              err=stat nope: no such file or directory",
    "dirFS.Open:/abs              err=open /abs: invalid argument",
    "dirFS.ReadFile:/abs          err=readfile /abs: invalid argument",
    "dirFS.ReadFile:/abs.v        val=\"\"",
    "dirFS.ReadDir:/abs           err=readdir /abs: invalid argument",
    "dirFS.Stat:/abs              err=stat /abs: invalid argument",
    "emptyDirFS.Open              err=open etc/passwd: os: DirFS with empty root",
    "emptyDirFS.Lstat             err=lstat etc/passwd: os: DirFS with empty root",
    "emptyDirFS.ReadLink          err=readlink etc/passwd: os: DirFS with empty root",
    "emptyDirFS.ReadLink.v        val=\"\"",
    "dirFS.ReadFile:escape        err=<nil>",
    "dirFS.ReadFile:escape.v      val=\"SECRET\"",
];

fn norm(dir: &string, s: string) -> string {
    let s = strings::ReplaceAll(s, dir.clone(), string::from_static("$D"));
    return strings::ReplaceAll(
        s,
        string::from_bytes(&[0u8]),
        string::from_static("<NUL>"),
    );
}

fn pad(label: string) -> string {
    let mut out = label;
    while out.Len() < 28 {
        out = out + string::from_static(" ");
    }
    return out;
}

fn line(ln: &mut usize, got: string) {
    unsafe { RUN += 1 };
    if *ln >= GO.len() {
        goish::fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        unsafe { FAILED += 1 };
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        goish::fmt::Printf!("[ok] %s\n", got);
    } else {
        goish::fmt::Printf!(
            "[!!] line %d\n  got  %q\n  want %q\n",
            *ln as int + 1,
            got,
            GO[*ln]
        );
        unsafe { FAILED += 1 };
    }
    *ln += 1;
}

fn err_line(ln: &mut usize, dir: &string, label: string, e: goish::errors::error) {
    let body = if e.IsNil() {
        string::from_static("<nil>")
    } else {
        norm(dir, e.Error())
    };
    line(ln, pad(label) + string::from_static(" err=") + body);
}

fn bytes_to_string(b: &goish::goslice::slice<u8>) -> string {
    let mut out = string::from_static("");
    let n = goish::len(b);
    let mut i: int = 0;
    while i < n {
        out = out + string::from_bytes(&[b[i]]);
        i += 1;
    }
    return out;
}

fn val_line(ln: &mut usize, dir: &string, label: string, v: string, e: goish::errors::error) {
    err_line(ln, dir, label.clone(), e);
    line(
        ln,
        pad(label + string::from_static(".v"))
            + goish::fmt::Sprintf!(" val=%q", norm(dir, v)),
    );
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;
    let dir = os::TempDir() + string::from_static("/goish_root_fs");
    let _ = os::RemoveAll(dir.clone());
    let inside = dir.clone() + string::from_static("/inside");
    let _ = os::MkdirAll(
        inside.clone() + string::from_static("/sub"),
        os::FileMode(0o755),
    );
    let _ = os::WriteFile(
        inside.clone() + string::from_static("/ok.txt"),
        b"hello".as_ref(),
        os::FileMode(0o644),
    );
    let _ = os::WriteFile(
        inside.clone() + string::from_static("/sub/deep.txt"),
        b"deep".as_ref(),
        os::FileMode(0o644),
    );
    let _ = os::WriteFile(
        dir.clone() + string::from_static("/secret.txt"),
        b"SECRET".as_ref(),
        os::FileMode(0o644),
    );
    let _ = os::Symlink(
        string::from_static("ok.txt"),
        inside.clone() + string::from_static("/link"),
    );
    let _ = os::Symlink(
        string::from_static("../secret.txt"),
        inside.clone() + string::from_static("/escape"),
    );
    let _ = os::Symlink(
        string::from_static("sub"),
        inside.clone() + string::from_static("/dirlink"),
    );
    let _ = os::Symlink(
        string::from_static("nope"),
        inside.clone() + string::from_static("/dangling"),
    );

    let (r, oerr) = os::OpenRoot(inside.clone());
    if !oerr.IsNil() {
        goish::fmt::Printf!("[!!] OpenRoot: %s\n", oerr.Error());
        os::Exit(1);
    }
    let r = r.MustTake();
    let f = r.FS();
    let fr: &(dyn fs::FS + Send + Sync + 'static) = f.as_ref();

    // ── interface satisfaction ──────────────────────────────────────
    line(
        &mut ln,
        pad(string::from_static("ifaces"))
            + goish::fmt::Sprintf!(
                " StatFS=%v ReadFileFS=%v ReadDirFS=%v ReadLinkFS=%v",
                goish::cast!(fr, fs::StatFS).1,
                goish::cast!(fr, fs::ReadFileFS).1,
                goish::cast!(fr, fs::ReadDirFS).1,
                goish::cast!(fr, fs::ReadLinkFS).1
            ),
    );

    // ── the path guard, one op at a time ────────────────────────────
    let bad: [&'static str; 7] = [
        "",
        "/ok.txt",
        "../secret.txt",
        "./ok.txt",
        "sub/",
        "sub//deep.txt",
        ".",
    ];
    for n in bad.iter() {
        let (fh, e) = fr.Open(string::from_static(n));
        if e.IsNil() {
            let _ = fh.Close();
        }
        err_line(
            &mut ln,
            &dir,
            string::from_static("Open:") + string::from_static(n),
            e,
        );
    }
    line(
        &mut ln,
        pad(string::from_static("ValidPath(.)"))
            + goish::fmt::Sprintf!(" %v", fs::ValidPath(string::from_static("."))),
    );

    // ── valid names ─────────────────────────────────────────────────
    for n in ["ok.txt", "nope.txt", "escape"].iter() {
        let (fh, e) = fr.Open(string::from_static(n));
        if e.IsNil() {
            let _ = fh.Close();
        }
        err_line(
            &mut ln,
            &dir,
            string::from_static("Open:") + string::from_static(n),
            e,
        );
    }

    // ── ReadFile ────────────────────────────────────────────────────
    for n in ["ok.txt", "/ok.txt", "escape", "link"].iter() {
        let (b, e) = fs::ReadFile(fr, string::from_static(n));
        val_line(
            &mut ln,
            &dir,
            string::from_static("ReadFile:") + string::from_static(n),
            bytes_to_string(&b),
            e,
        );
    }

    // ── Stat / Lstat ────────────────────────────────────────────────
    let (fi, e) = fs::Stat(fr, string::from_static("ok.txt"));
    err_line(&mut ln, &dir, string::from_static("Stat:ok.txt"), e.clone());
    if e.IsNil() {
        line(
            &mut ln,
            pad(string::from_static("Stat:ok.txt.m"))
                + goish::fmt::Sprintf!(" dir=%v mode=%v", fi.IsDir(), fi.Mode().String()),
        );
    }
    let (_, e) = fs::Stat(fr, string::from_static(".."));
    err_line(&mut ln, &dir, string::from_static("Stat:.."), e);

    let (fi, e) = fs::Stat(fr, string::from_static("link"));
    err_line(&mut ln, &dir, string::from_static("Stat:link"), e.clone());
    if e.IsNil() {
        line(
            &mut ln,
            pad(string::from_static("Stat:link.m"))
                + goish::fmt::Sprintf!(
                    " symlink=%v",
                    (fi.Mode() & fs::ModeSymlink).0 != 0
                ),
        );
    }
    let (fi, e) = fs::Lstat(fr, string::from_static("link"));
    err_line(&mut ln, &dir, string::from_static("Lstat:link"), e.clone());
    if e.IsNil() {
        line(
            &mut ln,
            pad(string::from_static("Lstat:link.m"))
                + goish::fmt::Sprintf!(
                    " symlink=%v",
                    (fi.Mode() & fs::ModeSymlink).0 != 0
                ),
        );
    }
    let (_, e) = fs::Lstat(fr, string::from_static(".."));
    err_line(&mut ln, &dir, string::from_static("Lstat:.."), e);
    let (_, e) = fs::Stat(fr, string::from_static("escape"));
    err_line(&mut ln, &dir, string::from_static("Stat:escape"), e);
    let (fi, e) = fs::Lstat(fr, string::from_static("escape"));
    err_line(&mut ln, &dir, string::from_static("Lstat:escape"), e.clone());
    if e.IsNil() {
        line(
            &mut ln,
            pad(string::from_static("Lstat:escape.m"))
                + goish::fmt::Sprintf!(
                    " symlink=%v",
                    (fi.Mode() & fs::ModeSymlink).0 != 0
                ),
        );
    }

    // ── ReadLink ────────────────────────────────────────────────────
    for n in ["link", "escape", "ok.txt", ".."].iter() {
        let (s, e) = fs::ReadLink(fr, string::from_static(n));
        val_line(
            &mut ln,
            &dir,
            string::from_static("ReadLink:") + string::from_static(n),
            s,
            e,
        );
    }

    // ── ReadDir, sorted ─────────────────────────────────────────────
    let (des, e) = fs::ReadDir(fr, string::from_static("."));
    err_line(&mut ln, &dir, string::from_static("ReadDir:."), e);
    line(
        &mut ln,
        pad(string::from_static("ReadDir:..n")) + string::from_static(" ") + join_names(&des),
    );
    let (_, e) = fs::ReadDir(fr, string::from_static("ok.txt"));
    err_line(&mut ln, &dir, string::from_static("ReadDir:ok.txt"), e);
    let (_, e) = fs::ReadDir(fr, string::from_static("/"));
    err_line(&mut ln, &dir, string::from_static("ReadDir:/"), e);
    let (des, e) = fs::ReadDir(fr, string::from_static("sub"));
    err_line(&mut ln, &dir, string::from_static("ReadDir:sub"), e);
    line(
        &mut ln,
        pad(string::from_static("ReadDir:sub.n")) + string::from_static(" ") + join_names(&des),
    );

    // ── the NUL, now that Root refuses it ───────────────────────────
    let mut nulname: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    nulname.extend_from_slice(b"ok");
    nulname.push(0);
    nulname.extend_from_slice(b"junk");
    let (b, e) = fs::ReadFile(fr, string::from_bytes(&nulname));
    val_line(
        &mut ln,
        &dir,
        string::from_static("ReadFile:NUL"),
        bytes_to_string(&b),
        e,
    );

    // ── dirFS: Lstat and ReadLink, new in Go 1.25 ───────────────────
    let d = os::DirFS(inside.clone());
    let dr: &(dyn fs::FS + Send + Sync + 'static) = d.as_ref();
    line(
        &mut ln,
        pad(string::from_static("dirFS.ifaces"))
            + goish::fmt::Sprintf!(
                " StatFS=%v ReadLinkFS=%v",
                goish::cast!(dr, fs::StatFS).1,
                goish::cast!(dr, fs::ReadLinkFS).1
            ),
    );
    let (fi, e) = fs::Lstat(dr, string::from_static("link"));
    err_line(&mut ln, &dir, string::from_static("dirFS.Lstat:link"), e.clone());
    if e.IsNil() {
        line(
            &mut ln,
            pad(string::from_static("dirFS.Lstat:link.m"))
                + goish::fmt::Sprintf!(
                    " symlink=%v name=%q",
                    (fi.Mode() & fs::ModeSymlink).0 != 0,
                    fi.Name()
                ),
        );
    }
    for n in ["nope", "/abs"].iter() {
        let (_, e) = fs::Lstat(dr, string::from_static(n));
        err_line(
            &mut ln,
            &dir,
            string::from_static("dirFS.Lstat:") + string::from_static(n),
            e,
        );
    }
    for n in ["link", "escape", "ok.txt", "/abs"].iter() {
        let (s, e) = fs::ReadLink(dr, string::from_static(n));
        val_line(
            &mut ln,
            &dir,
            string::from_static("dirFS.ReadLink:") + string::from_static(n),
            s,
            e,
        );
    }

    // ── the Path rewrite, in five methods and not the sixth ─────────
    let (fh, e) = dr.Open(string::from_static("nope"));
    if e.IsNil() {
        let _ = fh.Close();
    }
    err_line(&mut ln, &dir, string::from_static("dirFS.Open:nope"), e);
    let (b, e) = fs::ReadFile(dr, string::from_static("nope"));
    val_line(
        &mut ln,
        &dir,
        string::from_static("dirFS.ReadFile:nope"),
        bytes_to_string(&b),
        e,
    );
    let (_, e) = fs::ReadDir(dr, string::from_static("nope"));
    err_line(&mut ln, &dir, string::from_static("dirFS.ReadDir:nope"), e);
    let (_, e) = fs::ReadDir(dr, string::from_static("ok.txt"));
    err_line(&mut ln, &dir, string::from_static("dirFS.ReadDir:ok.txt"), e);
    let (_, e) = fs::Stat(dr, string::from_static("nope"));
    err_line(&mut ln, &dir, string::from_static("dirFS.Stat:nope"), e);
    let (fh, e) = dr.Open(string::from_static("/abs"));
    if e.IsNil() {
        let _ = fh.Close();
    }
    err_line(&mut ln, &dir, string::from_static("dirFS.Open:/abs"), e);
    let (b, e) = fs::ReadFile(dr, string::from_static("/abs"));
    val_line(
        &mut ln,
        &dir,
        string::from_static("dirFS.ReadFile:/abs"),
        bytes_to_string(&b),
        e,
    );
    let (_, e) = fs::ReadDir(dr, string::from_static("/abs"));
    err_line(&mut ln, &dir, string::from_static("dirFS.ReadDir:/abs"), e);
    let (_, e) = fs::Stat(dr, string::from_static("/abs"));
    err_line(&mut ln, &dir, string::from_static("dirFS.Stat:/abs"), e);

    // ── DirFS("") — the empty-root guard ────────────────────────────
    let z = os::DirFS(string::from_static(""));
    let zr: &(dyn fs::FS + Send + Sync + 'static) = z.as_ref();
    let (fh, e) = zr.Open(string::from_static("etc/passwd"));
    if e.IsNil() {
        let _ = fh.Close();
    }
    err_line(&mut ln, &dir, string::from_static("emptyDirFS.Open"), e);
    let (_, e) = fs::Lstat(zr, string::from_static("etc/passwd"));
    err_line(&mut ln, &dir, string::from_static("emptyDirFS.Lstat"), e);
    let (s, e) = fs::ReadLink(zr, string::from_static("etc/passwd"));
    val_line(&mut ln, &dir, string::from_static("emptyDirFS.ReadLink"), s, e);

    // ── and the whole point: DirFS is not a boundary ────────────────
    let (b, e) = fs::ReadFile(dr, string::from_static("escape"));
    val_line(
        &mut ln,
        &dir,
        string::from_static("dirFS.ReadFile:escape"),
        bytes_to_string(&b),
        e,
    );

    let _ = r.Close();
    let _ = os::RemoveAll(dir.clone());

    let run = unsafe { RUN };
    let f = unsafe { FAILED };
    if run != GO.len() as int {
        goish::fmt::Printf!("\nFAIL ran %d of %d rows\n", run, GO.len() as int);
        os::Exit(1);
    }
    if f == 0 {
        goish::fmt::Printf!("\nok %d/%d\n", run, run);
        os::Exit(0);
    }
    goish::fmt::Printf!("\nFAIL %d\n", f);
    os::Exit(1);
}

fn join_names(
    des: &goish::goslice::slice<alloc::sync::Arc<dyn fs::DirEntry + Send + Sync>>,
) -> string {
    let mut out = string::from_static("");
    let n = goish::len(des);
    let mut i: int = 0;
    while i < n {
        if i > 0 {
            out = out + string::from_static(",");
        }
        out = out + des[i].Name();
        i += 1;
    }
    return out;
}
