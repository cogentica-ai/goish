// iofs_ref_smoke — io/fs against a running Go.
// (io/fs: fs.go, readdir.go, glob.go, walk.go, sub.go, readfile.go, format.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_iofs_ref.go` run in
// `package fs_test` by `scripts/goref.sh`.
//
// io/fs is what every file-serving thing in the tree sits on:
// http.FileServer, embed, os.DirFS, archive/zip. Its rules decide which
// paths a caller can reach, and the one that matters most is ValidPath
// — the single function standing between a caller-supplied name and an
// FS implementation that will open whatever it is handed.
//
// ValidPath is strict in ways easy to relax by accident: no leading or
// trailing slash, no "." or ".." element ANYWHERE, no empty element,
// no backslash separators, and "." alone is the one valid special
// case. Thirty-one shapes are pinned. An FS that skipped the check
// would accept "../../etc/passwd", and a port that accepted one extra
// shape opens exactly that door.
//
// The io/fs logic itself matched Go on every line. Three defects were
// found in what it is PRINTABLE with, which is a different kind of
// wrong — not a wrong answer but no answer at all:
//
//   * `FileMode` had a `String()` that fmt could not reach. Go finds it
//     by structural assertion, so `%s` and `%v` on a mode just work;
//     goish's printer dispatches on `Format`, which a type reaches
//     through `Stringer`, and nothing implemented it. A file mode
//     could not be printed.
//   * `fs.FileInfo` and `fs.DirEntry` had the same problem one level
//     up. Go's fmt reaches the dynamic value's String, and every
//     FileInfo in the standard library returns `fs.FormatFileInfo(i)`
//     from it. goish had both `FormatFileInfo` and `FormatDirEntry`
//     ported faithfully — with nothing able to call them the way Go
//     does, because a trait OBJECT satisfied neither trait.
//
//     These are compile-time failures rather than wrong output, which
//     is why no existing smoke caught them: code that cannot be
//     written is code nobody notices is missing. `%v` on a FileInfo is
//     ordinary logging.
//
// What else is pinned:
//
//   * ReadDir sorts by filename, always, on every FS.
//   * The FileInfo and DirEntry renderings differ from each other —
//     "-rw-r--r-- 5 2021-03-04 05:06:07 a.txt" versus "- a.txt" — and
//     a directory gets a trailing slash in both.
//   * Glob's pattern rules, including that "**" is no different from
//     "*", that a malformed pattern is an ERROR rather than a quiet
//     non-match, and that a pattern with a trailing slash matches
//     nothing.
//   * WalkDir's traversal order, and both of its controls. SkipDir
//     returned from a FILE skips the rest of the containing directory
//     — a rule that reads like a bug until you need it — while SkipAll
//     stops the walk where it stands. Both are pinned, because a port
//     that treated them alike would silently visit fewer files.
//   * Sub rewrites paths and refuses to escape: "../a.txt" through a
//     sub-FS is "invalid argument", not the parent's file.
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::errors::error;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io::fs;
use goish::sort;
use goish::strings;
use goish::syscall;
use goish::testing::fstest;
use goish::time;
use goish::types::{byte, int};
const GO: [&str; 91] = [
    "valid \".\"          -> true",
    "valid \"\"           -> false",
    "valid \"/\"          -> false",
    "valid \"//\"         -> false",
    "valid \"a\"          -> true",
    "valid \"a/b\"        -> true",
    "valid \"a/b/c\"      -> true",
    "valid \"./a\"        -> false",
    "valid \"a/.\"        -> false",
    "valid \"a/./b\"      -> false",
    "valid \"..\"         -> false",
    "valid \"../a\"       -> false",
    "valid \"a/..\"       -> false",
    "valid \"a/../b\"     -> false",
    "valid \"a//b\"       -> false",
    "valid \"/a\"         -> false",
    "valid \"a/\"         -> false",
    "valid \"a/b/\"       -> false",
    "valid \"...\"        -> true",
    "valid \"a...\"       -> true",
    "valid \".a\"         -> true",
    "valid \"a.\"         -> true",
    "valid \" \"          -> true",
    "valid \"a b\"        -> true",
    "valid \"a\\\\b\"       -> true",
    "valid \"C:/a\"       -> true",
    "valid \"\\x00\"       -> true",
    "valid \"a\\x00b\"     -> true",
    "valid \"日本/語\"       -> true",
    "valid \"a/./\"       -> false",
    "valid \"././.\"      -> false",
    "readdir \".\"        -> n=4 [a.txt(dir=false,type=----------) b.txt(dir=false,type=----------) dir(dir=true,type=d---------) z.md(dir=false,type=----------)]",
    "readdir \"dir\"      -> n=3 [c.txt(dir=false,type=----------) d.go(dir=false,type=----------) sub(dir=true,type=d---------)]",
    "readdir \"dir/sub\"  -> n=1 [e.txt(dir=false,type=----------)]",
    "readdir \"missing\"  -> err=\"open missing: file does not exist\"",
    "readdir \"a.txt\"    -> err=\"readdir a.txt: not implemented\"",
    "stat \"a.txt\"        -> name=\"a.txt\" size=5 dir=false mode=-rw-r--r-- modtime=2021-03-04T05:06:07Z",
    "entry \"a.txt\"        -> name=\"a.txt\" dir=false type=---------- info-eq=true",
    "strings \"a.txt\"      -> fileinfo=\"-rw-r--r-- 5 2021-03-04 05:06:07 a.txt\" direntry=\"- a.txt\"",
    "stat \"dir\"          -> name=\"dir\" size=0 dir=true mode=dr-xr-xr-x modtime=0001-01-01T00:00:00Z",
    "entry \"dir\"          -> name=\"dir\" dir=true type=d--------- info-eq=true",
    "strings \"dir\"        -> fileinfo=\"dr-xr-xr-x 0 0001-01-01 00:00:00 dir/\" direntry=\"d dir/\"",
    "stat \"dir/sub/e.txt\" -> name=\"e.txt\" size=4 dir=false mode=-rw-r--r-- modtime=2021-03-04T05:06:07Z",
    "entry \"dir/sub/e.txt\" -> name=\"e.txt\" dir=false type=---------- info-eq=true",
    "strings \"dir/sub/e.txt\" -> fileinfo=\"-rw-r--r-- 4 2021-03-04 05:06:07 e.txt\" direntry=\"- e.txt\"",
    "stat \"missing\"      -> err=\"open missing: file does not exist\"",
    "stat \".\"            -> name=\".\" size=0 dir=true mode=dr-xr-xr-x modtime=0001-01-01T00:00:00Z",
    "entry \".\"            -> name=\".\" dir=true type=d--------- info-eq=true",
    "strings \".\"          -> fileinfo=\"dr-xr-xr-x 0 0001-01-01 00:00:00 ./\" direntry=\"d ./\"",
    "glob \"*\"            -> n=4 [a.txt b.txt dir z.md]",
    "glob \"*.txt\"        -> n=2 [a.txt b.txt]",
    "glob \"dir/*\"        -> n=3 [dir/c.txt dir/d.go dir/sub]",
    "glob \"dir/*.txt\"    -> n=1 [dir/c.txt]",
    "glob \"dir/**\"       -> n=3 [dir/c.txt dir/d.go dir/sub]",
    "glob \"*/*\"          -> n=3 [dir/c.txt dir/d.go dir/sub]",
    "glob \"*/*/*\"        -> n=1 [dir/sub/e.txt]",
    "glob \"a.txt\"        -> n=1 [a.txt]",
    "glob \"missing\"      -> n=0 []",
    "glob \"[\"            -> err=\"syntax error in pattern\"",
    "glob \"a[\"           -> err=\"syntax error in pattern\"",
    "glob \"dir/[a-z].txt\" -> n=1 [dir/c.txt]",
    "glob \"**\"           -> n=4 [a.txt b.txt dir z.md]",
    "glob \"\"             -> n=0 []",
    "glob \".\"            -> n=1 [.]",
    "glob \"./*\"          -> n=4 [a.txt b.txt dir z.md]",
    "glob \"dir\"          -> n=1 [dir]",
    "glob \"dir/\"         -> n=0 []",
    "glob \"*/\"           -> n=0 []",
    "glob \"?.txt\"        -> n=2 [a.txt b.txt]",
    "glob \"[!a]*.txt\"    -> n=1 [a.txt]",
    "walk all -> .(dir=true) a.txt(dir=false) b.txt(dir=false) dir(dir=true) dir/c.txt(dir=false) dir/d.go(dir=false) dir/sub(dir=true) dir/sub/e.txt(dir=false) z.md(dir=false)",
    "walk skipdir -> . a.txt b.txt dir z.md",
    "walk skipall -> . a.txt b.txt dir dir/c.txt",
    "walk skipdir-from-file -> . a.txt",
    "walk missing -> missing(err=true) err=true",
    "walk subtree -> dir dir/c.txt dir/d.go dir/sub dir/sub/e.txt",
    "sub readdir -> [c.txt d.go sub]",
    "sub read \"c.txt\"      -> \"charlie\"",
    "sub read \"sub/e.txt\"  -> \"echo\"",
    "sub read \"../a.txt\"   -> err=\"read ../a.txt: invalid argument\"",
    "sub read \"/c.txt\"     -> err=\"read /c.txt: invalid argument\"",
    "sub read \".\"          -> err=\"read .: invalid argument\"",
    "sub invalid-root err=\"sub ../escape: invalid argument\"",
    "sub dot-root err=<nil>",
    "readfile \"a.txt\"      -> \"alpha\"",
    "readfile \"dir/c.txt\"  -> \"charlie\"",
    "readfile \"missing\"    -> err=\"open missing: file does not exist\"",
    "readfile \"dir\"        -> err=\"read dir: invalid argument\"",
    "readfile \"../a.txt\"   -> err=\"open ../a.txt: file does not exist\"",
    "readfile \"/a.txt\"     -> err=\"open /a.txt: file does not exist\"",
    "readfile \"\"           -> err=\"open : file does not exist\"",
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
fn mapfs() -> Arc<fstest::MapFS> {
    let mt = time::Date(2021, time::March, 4, 5, 6, 7, 0, time::UTC);
    let mut m = fstest::MapFS::new();
    let add = |m: &mut fstest::MapFS, name: &str, data: &str, mode: u32| {
        let f = fstest::MapFile {
            Data: slice::<byte>::__from_vec(data.as_bytes().to_vec()),
            Mode: fs::FileMode(mode),
            ModTime: mt.clone(),
            Sys: None,
        };
        m.0.Set(s(name), Arc::new(f));
    };
    add(&mut m, "a.txt", "alpha", 0o644);
    add(&mut m, "b.txt", "bravo!!", 0o600);
    add(&mut m, "dir/c.txt", "charlie", 0o644);
    add(&mut m, "dir/d.go", "delta", 0o644);
    add(&mut m, "dir/sub/e.txt", "echo", 0o644);
    add(&mut m, "z.md", "zulu", 0o644);
    return Arc::new(m);
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    for p in [
        ".",
        "",
        "/",
        "//",
        "a",
        "a/b",
        "a/b/c",
        "./a",
        "a/.",
        "a/./b",
        "..",
        "../a",
        "a/..",
        "a/../b",
        "a//b",
        "/a",
        "a/",
        "a/b/",
        "...",
        "a...",
        ".a",
        "a.",
        " ",
        "a b",
        "a\\b",
        "C:/a",
        "\u{0}",
        "a\u{0}b",
        "日本/語",
        "a/./",
        "././.",
    ] {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("valid %-12q -> %v", s(p), fs::ValidPath(s(p))),
        );
    }
    let fsys = mapfs();
    let f: &(dyn fs::FS + Send + Sync + 'static) = &*fsys;
    for dir in [".", "dir", "dir/sub", "missing", "a.txt"] {
        let (ents, err) = fs::ReadDir(f, s(dir));
        if err != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("readdir %-10q -> err=%q", s(dir), err.Error()),
            );
            continue;
        }
        let mut parts: Vec<string> = Vec::new();
        for i in 0..ents.Len() {
            let e = ents[i].clone();
            parts.push(fmt::Sprintf!(
                "%s(dir=%v,type=%s)",
                e.Name(),
                e.IsDir(),
                e.Type()
            ));
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "readdir %-10q -> n=%d [%s]",
                s(dir),
                ents.Len(),
                strings::Join(slice::<string>::__from_vec(parts), s(" "))
            ),
        );
    }
    for name in ["a.txt", "dir", "dir/sub/e.txt", "missing", "."] {
        let (fi, err) = fs::Stat(f, s(name));
        if err != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("stat %-14q -> err=%q", s(name), err.Error()),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "stat %-14q -> name=%q size=%d dir=%v mode=%s modtime=%s",
                s(name),
                fi.Name(),
                fi.Size(),
                fi.IsDir(),
                fi.Mode(),
                fi.ModTime().UTC().Format(s(time::RFC3339))
            ),
        );
        let de = fs::FileInfoToDirEntry(fi.clone());
        let (di, dierr) = de.Info();
        let infoName = if dierr == goish::nil {
            di.Name()
        } else {
            string::new()
        };
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "entry %-14q -> name=%q dir=%v type=%s info-eq=%v",
                s(name),
                de.Name(),
                de.IsDir(),
                de.Type(),
                infoName == fi.Name()
            ),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "strings %-12q -> fileinfo=%q direntry=%q",
                s(name),
                fmt::Sprintf!("%v", &*fi),
                fmt::Sprintf!("%v", &*de)
            ),
        );
    }
    for pat in [
        "*",
        "*.txt",
        "dir/*",
        "dir/*.txt",
        "dir/**",
        "*/*",
        "*/*/*",
        "a.txt",
        "missing",
        "[",
        "a[",
        "dir/[a-z].txt",
        "**",
        "",
        ".",
        "./*",
        "dir",
        "dir/",
        "*/",
        "?.txt",
        "[!a]*.txt",
    ] {
        let (names, err) = fs::Glob(f, s(pat));
        if err != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("glob %-14q -> err=%q", s(pat), err.Error()),
            );
            continue;
        }
        let mut ns = names.clone();
        sort::Strings(&mut ns);
        let mut parts: Vec<string> = Vec::new();
        for i in 0..ns.Len() {
            parts.push(ns[i].clone());
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "glob %-14q -> n=%d [%s]",
                s(pat),
                ns.Len(),
                strings::Join(slice::<string>::__from_vec(parts), s(" "))
            ),
        );
    }
    {
        let seen = Arc::new(goish::sync::Mutex::new(Vec::<string>::new()));
        let sc = seen.clone();
        let _ = fs::WalkDir(
            f,
            s("."),
            move |p: string, d: &(dyn fs::DirEntry + Send + Sync + 'static), _e: error| -> error {
                sc.Lock().push(fmt::Sprintf!("%s(dir=%v)", p, d.IsDir()));
                return goish::nil.into();
            },
        );
        let v = seen.Lock().clone();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "walk all -> %s",
                strings::Join(slice::<string>::__from_vec(v), s(" "))
            ),
        );
    }
    {
        let seen = Arc::new(goish::sync::Mutex::new(Vec::<string>::new()));
        let sc = seen.clone();
        let _ = fs::WalkDir(
            f,
            s("."),
            move |p: string, d: &(dyn fs::DirEntry + Send + Sync + 'static), _e: error| -> error {
                sc.Lock().push(p.clone());
                if d.IsDir() && p == "dir" {
                    return fs::SkipDir.into();
                }
                return goish::nil.into();
            },
        );
        let v = seen.Lock().clone();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "walk skipdir -> %s",
                strings::Join(slice::<string>::__from_vec(v), s(" "))
            ),
        );
    }
    {
        let seen = Arc::new(goish::sync::Mutex::new(Vec::<string>::new()));
        let sc = seen.clone();
        let _ = fs::WalkDir(
            f,
            s("."),
            move |p: string, _d: &(dyn fs::DirEntry + Send + Sync + 'static), _e: error| -> error {
                sc.Lock().push(p.clone());
                if p == "dir/c.txt" {
                    return fs::SkipAll.into();
                }
                return goish::nil.into();
            },
        );
        let v = seen.Lock().clone();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "walk skipall -> %s",
                strings::Join(slice::<string>::__from_vec(v), s(" "))
            ),
        );
    }
    {
        let seen = Arc::new(goish::sync::Mutex::new(Vec::<string>::new()));
        let sc = seen.clone();
        let _ = fs::WalkDir(
            f,
            s("."),
            move |p: string, _d: &(dyn fs::DirEntry + Send + Sync + 'static), _e: error| -> error {
                sc.Lock().push(p.clone());
                if p == "a.txt" {
                    return fs::SkipDir.into();
                }
                return goish::nil.into();
            },
        );
        let v = seen.Lock().clone();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "walk skipdir-from-file -> %s",
                strings::Join(slice::<string>::__from_vec(v), s(" "))
            ),
        );
    }
    {
        let seen = Arc::new(goish::sync::Mutex::new(Vec::<string>::new()));
        let sc = seen.clone();
        let werr = fs::WalkDir(
            f,
            s("missing"),
            move |p: string, _d: &(dyn fs::DirEntry + Send + Sync + 'static), e: error| -> error {
                sc.Lock()
                    .push(fmt::Sprintf!("%s(err=%v)", p, e != goish::nil));
                return e;
            },
        );
        let v = seen.Lock().clone();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "walk missing -> %s err=%v",
                strings::Join(slice::<string>::__from_vec(v), s(" ")),
                werr != goish::nil
            ),
        );
    }
    {
        let seen = Arc::new(goish::sync::Mutex::new(Vec::<string>::new()));
        let sc = seen.clone();
        let _ = fs::WalkDir(
            f,
            s("dir"),
            move |p: string, _d: &(dyn fs::DirEntry + Send + Sync + 'static), _e: error| -> error {
                sc.Lock().push(p.clone());
                return goish::nil.into();
            },
        );
        let v = seen.Lock().clone();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "walk subtree -> %s",
                strings::Join(slice::<string>::__from_vec(v), s(" "))
            ),
        );
    }
    {
        let dynfs: Arc<dyn fs::FS + Send + Sync> = fsys.clone();
        let (sub, err) = fs::Sub(dynfs.clone(), s("dir"));
        if err != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("sub err=%q", err.Error()),
            );
        } else {
            let (ents, _) = fs::ReadDir(&*sub, s("."));
            let mut names: Vec<string> = Vec::new();
            for i in 0..ents.Len() {
                names.push(ents[i].Name());
            }
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "sub readdir -> [%s]",
                    strings::Join(slice::<string>::__from_vec(names), s(" "))
                ),
            );
            for p in ["c.txt", "sub/e.txt", "../a.txt", "/c.txt", "."] {
                let (b, e) = fs::ReadFile(&*sub, s(p));
                if e != goish::nil {
                    chk(
                        &mut failed,
                        &mut ln,
                        fmt::Sprintf!("sub read %-12q -> err=%q", s(p), e.Error()),
                    );
                    continue;
                }
                chk(
                    &mut failed,
                    &mut ln,
                    fmt::Sprintf!(
                        "sub read %-12q -> %q",
                        s(p),
                        string::from_bytes(&b.to_vec())
                    ),
                );
            }
        }
        let (_, e2) = fs::Sub(dynfs.clone(), s("../escape"));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("sub invalid-root err=%q", errText(e2)),
        );
        let (_, e3) = fs::Sub(dynfs.clone(), s("."));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("sub dot-root err=%s", errText(e3)),
        );
    }
    for p in [
        "a.txt",
        "dir/c.txt",
        "missing",
        "dir",
        "../a.txt",
        "/a.txt",
        "",
    ] {
        let (b, e) = fs::ReadFile(f, s(p));
        if e != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("readfile %-12q -> err=%q", s(p), e.Error()),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "readfile %-12q -> %q",
                s(p),
                string::from_bytes(&b.to_vec())
            ),
        );
    }
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
