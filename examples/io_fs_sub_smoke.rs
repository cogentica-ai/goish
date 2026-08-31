// io_fs_sub_smoke — io/fs's Sub, ReadLink, Lstat and the formatters
// against a running Go. (io/fs/sub.go, readlink.go, fs.go, format.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_fs_sub_ref.go` run in `package fs_test`
// by `scripts/goref.sh`.
//
// The whole point of a sub-filesystem is that it is INVISIBLE: a caller
// holding one must never see the parent's paths — not in results, and
// not in errors. The second half is `subFS.fixErr`, and it is what a
// port drops without noticing, because every happy path still passes.
// Before this file existed, `fs::Sub` reported `open sub/nope.txt:` to
// a caller that had only ever named `nope.txt`, rejected a bad `dir`
// with a fresh `errors.New("invalid name")` that `errors.Is(err,
// ErrInvalid)` answered false for, and had no `ReadLink`, `Lstat`,
// `Glob` or nested `Sub` at all.
//
// The error TEXT is the assertion here, deliberately: it is the only
// thing that distinguishes a shortened path from an unshortened one.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;

use goish::errors;
use goish::errors::ErrorTrait;
use goish::gostring::string;
use goish::io::fs;
use goish::testing::fstest::{MapFS, MapFile};
use goish::types::{byte, int};
use goish::{error, fmt, slice, syscall};

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

fn newfs() -> Arc<MapFS> {
    let mut m: goish::map<string, Arc<MapFile>> = goish::map::new();
    for (name, data) in [
        ("a.txt", "1"),
        ("sub/b.txt", "2"),
        ("sub/c.log", "3"),
        ("sub/deep/d.txt", "4"),
        ("sub/deep/e.log", "5"),
        ("other/f.txt", "6"),
        ("sub/link", "7"),
        ("sub/deep/g/h.txt", "8"),
    ]
    .iter()
    {
        let mut f = MapFile::default();
        f.Data = slice::__from_vec(data.as_bytes().to_vec());
        m.Set(s(name), Arc::new(f));
    }
    return Arc::new(MapFS(m));
}

// go: none — goish idiom: the Go reference's `plainFS` — a wrapper
//     that hides MapFS's ReadLinkFS, GlobFS and the rest behind a bare
//     `fs.FS`, so `ReadLink` and `Lstat` take their fallback arms. Go
//     writes it as a struct embedding only `fs.FS`; the same statement
//     here is a struct that implements only that one trait.
struct PlainFS(Arc<MapFS>);

impl fs::FS for PlainFS {
    fn Open(&self, name: string) -> (Arc<dyn fs::File + Send + Sync>, error) {
        return self.0.Open(name);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides. Deliberately
    //     the only interface `PlainFS` answers to.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

fn errText(e: &error) -> string {
    if e.IsNil() {
        return s("<nil>");
    }
    return e.Error();
}

fn names(list: &slice<Arc<dyn fs::DirEntry + Send + Sync>>) -> Vec<string> {
    let mut out: Vec<string> = Vec::new();
    let mut i: int = 0;
    while i < list.Len() {
        out.push(list[i as usize].Name());
        i += 1;
    }
    return out;
}

fn strs(list: &slice<string>) -> Vec<string> {
    let mut out: Vec<string> = Vec::new();
    let mut i: int = 0;
    while i < list.Len() {
        out.push(list[i as usize].clone());
        i += 1;
    }
    return out;
}

fn eqStrs(got: &Vec<string>, want: &[&str]) -> bool {
    if got.len() != want.len() {
        return false;
    }
    let mut i = 0usize;
    while i < got.len() {
        if got[i] != s(want[i]) {
            return false;
        }
        i += 1;
    }
    return true;
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let m = newfs();

    // 1. Sub's argument checking. An invalid dir is a PathError whose
    //    Err is ErrInvalid — not a fresh error, which `errors::Is`
    //    would answer false for.
    {
        let mut ok = true;
        // (dir, want_ok, want_err_text)
        let cases: [(&str, bool, &str); 9] = [
            (".", true, "<nil>"),
            ("sub", true, "<nil>"),
            ("sub/deep", true, "<nil>"),
            ("", false, "sub : invalid argument"),
            ("/sub", false, "sub /sub: invalid argument"),
            ("sub/", false, "sub sub/: invalid argument"),
            ("./sub", false, "sub ./sub: invalid argument"),
            ("../x", false, "sub ../x: invalid argument"),
            // A dir that does not exist is still a valid path: Sub does
            // not stat it, so this succeeds and fails later.
            ("nope", true, "<nil>"),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (dir, want_ok, want_err) = cases[i];
            let me: Arc<dyn fs::FS + Send + Sync> = m.clone();
            let (_, err) = fs::Sub(me, s(dir));
            if err.IsNil() != want_ok || errText(&err) != s(want_err) {
                ok = false;
            }
            if !want_ok && !errors::Is(err, fs::ErrInvalid) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 1", "Sub validates dir (ErrInvalid)");
    }

    let me: Arc<dyn fs::FS + Send + Sync> = m.clone();
    let (sub, err) = fs::Sub(me, s("sub"));
    if !err.IsNil() {
        fmt::Println!("setup FAIL", err.Error());
        syscall::Exit(1);
    }

    // 2. Open through the sub. The error names what the CALLER asked
    //    for — `open nope.txt`, never `open sub/nope.txt`. That is
    //    `fixErr`, and it is the whole reason a sub-filesystem is worth
    //    having.
    {
        let mut ok = true;
        // (name, want_data_or_"", want_err_text)
        let cases: [(&str, &str, &str); 8] = [
            ("b.txt", "2", "<nil>"),
            ("deep/d.txt", "4", "<nil>"),
            ("nope.txt", "", "open nope.txt: file does not exist"),
            ("deep", "", "<nil>"),
            (".", "", "<nil>"),
            ("", "", "open : invalid argument"),
            ("/b.txt", "", "open /b.txt: invalid argument"),
            ("../a.txt", "", "open ../a.txt: invalid argument"),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (name, want, want_err) = cases[i];
            let (f, err) = sub.Open(s(name));
            if errText(&err) != s(want_err) {
                ok = false;
            }
            if err.IsNil() {
                let mut buf = goish::make!([]byte, 8);
                let (n, _) = f.Read(&mut buf);
                let _ = f.Close();
                if string::from_bytes(&buf.slice(0, n)) != s(want) {
                    ok = false;
                }
            }
            i += 1;
        }
        report(&mut failed, ok, " 2", "Sub::Open shortens error paths");
    }

    // 3. ReadFile and ReadDir through the sub, errors included.
    {
        let mut ok = true;
        let rf: [(&str, &str, &str); 4] = [
            ("b.txt", "2", "<nil>"),
            ("deep/d.txt", "4", "<nil>"),
            ("nope.txt", "", "open nope.txt: file does not exist"),
            ("deep", "", "read deep: invalid argument"),
        ];
        let mut i = 0;
        while i < rf.len() {
            let (name, want, want_err) = rf[i];
            let (data, err) = fs::ReadFile(&*sub, s(name));
            if string::from_bytes(&data) != s(want) || errText(&err) != s(want_err) {
                ok = false;
            }
            i += 1;
        }
        // Go: readdir "." [b.txt c.log deep link]; "b.txt" is not a dir.
        let (l1, e1) = fs::ReadDir(&*sub, s("."));
        if !eqStrs(&names(&l1), &["b.txt", "c.log", "deep", "link"]) || !e1.IsNil() {
            ok = false;
        }
        let (l2, e2) = fs::ReadDir(&*sub, s("deep"));
        if !eqStrs(&names(&l2), &["d.txt", "e.log", "g"]) || !e2.IsNil() {
            ok = false;
        }
        let (l3, e3) = fs::ReadDir(&*sub, s("nope"));
        if l3.Len() != 0 || errText(&e3) != s("open nope: file does not exist") {
            ok = false;
        }
        report(&mut failed, ok, " 3", "Sub::ReadFile/ReadDir");
    }

    // 4. Stat through the sub. `Stat(".")` names the SUBTREE ROOT as Go
    //    does — "sub", the real directory — not ".".
    {
        let mut ok = true;
        // (name, want_name, want_isdir, want_err)
        let cases: [(&str, &str, bool, &str); 4] = [
            ("b.txt", "b.txt", false, "<nil>"),
            ("deep", "deep", true, "<nil>"),
            ("nope", "", false, "open nope: file does not exist"),
            (".", "sub", true, "<nil>"),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (name, want_name, want_dir, want_err) = cases[i];
            let (info, err) = fs::Stat(&*sub, s(name));
            if errText(&err) != s(want_err) {
                ok = false;
            }
            if err.IsNil() && (info.Name() != s(want_name) || info.IsDir() != want_dir) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 4", "Sub::Stat");
    }

    // 5. Glob through the sub. Results come back SHORTENED — a match at
    //    `sub/b.txt` is reported as `b.txt` — and a pattern matching
    //    nothing is not an error, while a malformed one is.
    {
        let mut ok = true;
        let cases: [(&str, &[&str], &str); 8] = [
            ("*", &["b.txt", "c.log", "deep", "link"], "<nil>"),
            ("*.txt", &["b.txt"], "<nil>"),
            ("*.log", &["c.log"], "<nil>"),
            ("deep/*", &["deep/d.txt", "deep/e.log", "deep/g"], "<nil>"),
            ("*/*.txt", &["deep/d.txt"], "<nil>"),
            (".", &["."], "<nil>"),
            ("nope*", &[], "<nil>"),
            ("[", &[], "syntax error in pattern"),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (pat, want, want_err) = cases[i];
            let (list, err) = fs::Glob(&*sub, s(pat));
            if !eqStrs(&strs(&list), want) || errText(&err) != s(want_err) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 5", "Sub::Glob shortens results");
    }

    // 6. A nested Sub COLLAPSES: Sub(Sub(fsys,"sub"),"deep") is one
    //    subFS rooted at sub/deep, not two wrappers — and its errors are
    //    shortened all the way back to the caller's name.
    {
        let mut ok = true;
        let (deep, err) = fs::Sub(sub.clone(), s("deep"));
        if !err.IsNil() {
            ok = false;
        }
        let (l, _) = fs::ReadDir(&*deep, s("."));
        if !eqStrs(&names(&l), &["d.txt", "e.log", "g"]) {
            ok = false;
        }
        let (_, oe) = deep.Open(s("nope.txt"));
        if errText(&oe) != s("open nope.txt: file does not exist") {
            ok = false;
        }
        let (data, de) = fs::ReadFile(&*deep, s("d.txt"));
        if string::from_bytes(&data) != s("4") || !de.IsNil() {
            ok = false;
        }
        let (g, ge) = fs::Glob(&*deep, s("*"));
        if !eqStrs(&strs(&g), &["d.txt", "e.log", "g"]) || !ge.IsNil() {
            ok = false;
        }
        // Sub(sub, ".") is the same subtree again.
        let (same, se) = fs::Sub(sub.clone(), s("."));
        if !se.IsNil() {
            ok = false;
        }
        let (l2, _) = fs::ReadDir(&*same, s("."));
        if !eqStrs(&names(&l2), &["b.txt", "c.log", "deep", "link"]) {
            ok = false;
        }
        report(&mut failed, ok, " 6", "nested Sub collapses");
    }

    // 7. ReadLink and Lstat.
    //
    //    MapFS implements ReadLinkFS, so both reach it. A plain file is
    //    not a symlink — that is ErrInvalid, not "not found" — and a
    //    name that is not there is ErrNotExist under the op that asked.
    {
        let mut ok = true;
        let me: Arc<dyn fs::FS + Send + Sync> = m.clone();
        // (name, want_readlink_err, want_lstat_name_or_"", want_lstat_err)
        let cases: [(&str, &str, &str, &str); 4] = [
            (
                "a.txt",
                "readlink a.txt: invalid argument",
                "a.txt",
                "<nil>",
            ),
            ("sub", "readlink sub: invalid argument", "sub", "<nil>"),
            (
                "nope",
                "readlink nope: file does not exist",
                "",
                "lstat nope: file does not exist",
            ),
            (
                "other/f.txt",
                "readlink other/f.txt: invalid argument",
                "f.txt",
                "<nil>",
            ),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (name, want_rl, want_name, want_ls) = cases[i];
            let (target, err) = fs::ReadLink(&*me, s(name));
            if target.Len() != 0 || errText(&err) != s(want_rl) {
                ok = false;
            }
            let (info, err2) = fs::Lstat(&*me, s(name));
            if errText(&err2) != s(want_ls) {
                ok = false;
            }
            if err2.IsNil() && info.Name() != s(want_name) {
                ok = false;
            }
            i += 1;
        }
        // ErrInvalid, not a fresh error — the whole point of a sentinel.
        let (_, e) = fs::ReadLink(&*me, s("a.txt"));
        if !errors::Is(e, fs::ErrInvalid) {
            ok = false;
        }
        report(&mut failed, ok, " 7", "ReadLink/Lstat via ReadLinkFS");
    }

    // 8. A filesystem that does NOT implement ReadLinkFS. ReadLink
    //    cannot answer at all — an ErrInvalid PathError — but Lstat
    //    falls back to Stat, because a filesystem with no links has
    //    nothing to not-follow. Getting that asymmetry backwards is the
    //    easy mistake, so both halves are pinned.
    {
        let mut ok = true;
        let plain: Arc<dyn fs::FS + Send + Sync> = Arc::new(PlainFS(m.clone()));
        let (target, err) = fs::ReadLink(&*plain, s("a.txt"));
        if target.Len() != 0 || errText(&err) != s("readlink a.txt: invalid argument") {
            ok = false;
        }
        if !errors::Is(err, fs::ErrInvalid) {
            ok = false;
        }
        let (info, err2) = fs::Lstat(&*plain, s("a.txt"));
        if !err2.IsNil() || info.Name() != s("a.txt") || info.IsDir() {
            ok = false;
        }
        // The fallback is Stat, so the error is Stat's — `open`, not
        // `lstat`.
        let (_, err3) = fs::Lstat(&*plain, s("nope"));
        if errText(&err3) != s("open nope: file does not exist") {
            ok = false;
        }
        // And through the sub, the ErrInvalid still names the caller's
        // path, not the parent's.
        let (_, err4) = fs::ReadLink(&*sub, s("b.txt"));
        if errText(&err4) != s("readlink b.txt: invalid argument") {
            ok = false;
        }
        report(&mut failed, ok, " 8", "Lstat falls back to Stat");
    }

    // 9. PathError: the text Go prints, Unwrap, and Timeout — which
    //    asserts `interface{ Timeout() bool }` on the wrapped error.
    {
        let mut ok = true;
        let pe = fs::PathError {
            Op: s("open"),
            Path: s("x/y"),
            Err: fs::ErrNotExist.into(),
        };
        if pe.Error() != s("open x/y: file does not exist") {
            ok = false;
        }
        if !errors::Is(pe.Unwrap(), fs::ErrNotExist) {
            ok = false;
        }
        if pe.Timeout() {
            ok = false;
        }
        report(&mut failed, ok, " 9", "PathError (text, Unwrap, Timeout)");
    }

    // 10. ValidPath. Every path above rests on it, and the rejections
    //    are the interesting half.
    {
        let mut ok = true;
        let cases: [(&str, bool); 15] = [
            (".", true),
            ("", false),
            ("/", false),
            ("x", true),
            ("x/y", true),
            ("x/", false),
            ("/x", false),
            ("x//y", false),
            ("./x", false),
            ("../x", false),
            ("x/.", false),
            ("x/..", false),
            ("..", false),
            ("a/b/c", true),
            ("\u{fffd}", true),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (p, want) = cases[i];
            if fs::ValidPath(s(p)) != want {
                ok = false;
            }
            i += 1;
        }
        // Go: validpath "\xff" false — invalid UTF-8 is not a valid path.
        if fs::ValidPath(string::from_bytes(b"\xff")) {
            ok = false;
        }
        report(&mut failed, ok, "10", "ValidPath");
    }

    // 11. FormatFileInfo / FormatDirEntry, including the trailing slash
    //     a directory gets and the mode letters.
    //
    //     ONE STATED DEVIATION, and it is not io/fs's: Go prints a zero
    //     `time.Time` as `0001-01-01 00:00:00`, because Go's Time counts
    //     from the absolute zero year. goish's `Time` holds Unix seconds,
    //     so its zero value is the epoch and it prints
    //     `1970-01-01 00:00:00`. Everything else — the mode letters, the
    //     size, the column order, the trailing slash on a directory — is
    //     byte-for-byte Go's. Fixing the epoch means changing `Time`'s
    //     representation, which is a `time` change, not this one.
    {
        let mut ok = true;
        let me: Arc<dyn fs::FS + Send + Sync> = m.clone();
        let (fi, _) = fs::Stat(&*me, s("a.txt"));
        if fs::FormatFileInfo(&*fi) != s("---------- 1 1970-01-01 00:00:00 a.txt") {
            ok = false;
        }
        let di = fs::FileInfoToDirEntry(fi);
        if fs::FormatDirEntry(&*di) != s("- a.txt") {
            ok = false;
        }
        let (dfi, _) = fs::Stat(&*me, s("sub"));
        if fs::FormatFileInfo(&*dfi) != s("dr-xr-xr-x 0 1970-01-01 00:00:00 sub/") {
            ok = false;
        }
        let ddi = fs::FileInfoToDirEntry(dfi);
        if fs::FormatDirEntry(&*ddi) != s("d sub/") {
            ok = false;
        }
        report(&mut failed, ok, "11", "FormatFileInfo/FormatDirEntry");
    }

    if failed == 0 {
        fmt::Println!("ok 11/11");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 11");
        syscall::Exit(1);
    }
}
