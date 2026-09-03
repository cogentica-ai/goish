// fstest_ref_smoke — testing/fstest against a running Go.
// (testing/fstest/testfs.go, testing/fstest/mapfs.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_fstest_ref.go` run in
// `package fstest_test` by `scripts/goref.sh`. goish matched Go on all
// 19 lines — no defects found.
//
// fstest.TestFS is a conformance checker: it walks an FS and asserts
// the contract every implementation is supposed to keep. That makes it
// load-bearing in a way tests usually are not — a checker that MISSES a
// violation is worse than no checker, because the implementation ships
// with a passing test and the bug surfaces in whatever reads it.
//
// So this measures TestFS against filesystems that are deliberately
// wrong, one broken rule each, and pins which ones it catches. A port
// whose TestFS were more permissive than Go's would let a broken FS
// through; one that were stricter would reject an FS Go accepts, which
// is its own problem for anyone porting a working implementation.
//
// WHAT IT CATCHES: an FS that opens a path fs.ValidPath rejects; one
// whose ReadDir hides an entry Open can still reach; one that opens
// every name whether or not it exists. Plus a caller naming a file
// that is not there.
//
// WHAT IT DOES NOT: content that differs between reads, and a DirEntry
// whose Stat disagrees with the file. Both come back caught=false, and
// pinning that is the point — the limits of a checker are part of its
// contract, and someone relying on TestFS should know it will not catch
// an unstable Read.
//
// One case is worth reading twice: `ok none`. TestFS with NO expected
// names FAILS on a non-empty FS, because a caller who names nothing is
// almost certainly not testing what they think. An empty FS with no
// names passes.
//
// A TRAP THIS MEASUREMENT WALKED INTO, recorded because anyone
// implementing an FS in goish will meet it. `readdir-hides` was not
// caught here at first, and it looked exactly like a missing check in
// goish's TestFS. It was not. Go resolves `t.fsys.(fs.ReadDirFS)`
// STRUCTURALLY; goish resolves it through a runtime registry plus a
// per-type `__goish_as_dyn_any` hook, and a concrete type must do BOTH
// — register the impl and override the hook — or the assertion silently
// misses and `fs.ReadDir` falls back to Open+ReadDir. The fallback
// re-reads the directory the same way the checker already did, so the
// comparison is a list against itself and no implementation can fail
// it. The wrapper below does both; without them a broken FS passes
// conformance for a reason that has nothing to do with the FS.

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
use goish::io;
use goish::io::fs;
use goish::strings;
use goish::syscall;
use goish::testing::fstest;
use goish::time;
use goish::types::{byte, int};
const GO: [&str; 19] = [
    "ok all-names -> <nil>",
    "ok subset -> <nil>",
    "ok none -> TestFS found errors: …",
    "missing-expected -> caught=true",
    "empty-fs -> <nil>",
    "broken opens-invalid-path     -> caught=true ",
    "broken content-differs        -> caught=false",
    "broken stat-disagrees         -> caught=false",
    "broken readdir-hides          -> caught=true ",
    "broken open-succeeds-missing  -> caught=true ",
    "mapfs read=\"alpha\" name=\"a.txt\" size=5 mode=-rw-r--r--",
    "mapfs open \"missing\"      -> err=open missing: file does not exist",
    "mapfs open \"dir\"          -> err=<nil>",
    "mapfs open \"\"             -> err=open : file does not exist",
    "mapfs open \"/a.txt\"       -> err=open /a.txt: file does not exist",
    "mapfs open \"./a.txt\"      -> err=open ./a.txt: file does not exist",
    "mapfs open \"dir/../a.txt\" -> err=open dir/../a.txt: file does not exist",
    "mapfs readdir-root -> [a.txt(dir=false) dir(dir=true)]",
    "mapfs implied-dir isdir=true err=<nil>",
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
    let e = err.Error();
    let i = strings::IndexByte(e.clone(), b'\n');
    if i >= 0 {
        return string::from_bytes(&e.as_bytes()[..i as usize]) + " …";
    }
    return e;
}
fn goodFS() -> Arc<fstest::MapFS> {
    let mt = time::Date(2021, time::March, 4, 5, 6, 7, 0, time::UTC);
    let mut m = fstest::MapFS::new();
    let add = |m: &mut fstest::MapFS, name: &str, data: &str| {
        m.0.Set(
            s(name),
            Arc::new(fstest::MapFile {
                Data: slice::<byte>::__from_vec(data.as_bytes().to_vec()),
                Mode: fs::FileMode(0o644),
                ModTime: mt.clone(),
                Sys: None,
            }),
        );
    };
    add(&mut m, "a.txt", "alpha");
    add(&mut m, "dir/b.txt", "bravo");
    add(&mut m, "dir/sub/c", "charlie");
    return Arc::new(m);
}
// Each wrapper breaks exactly one FS rule, chosen by `how`.
struct BrokenFS {
    inner: Arc<fstest::MapFS>,
    how: &'static str,
}
struct FlakyFile(Arc<dyn fs::File + Send + Sync>);
impl fs::File for FlakyFile {
    fn Stat(&self) -> (Arc<dyn fs::FileInfo + Send + Sync>, error) {
        return self.0.Stat();
    }
    fn Read(&self, p: &mut slice<byte>) -> (int, error) {
        let (n, e) = self.0.Read(p);
        for i in 0..n {
            p[i] ^= 0x20;
        }
        return (n, e);
    }
    fn Close(&self) -> error {
        return self.0.Close();
    }
}
impl fs::FS for BrokenFS {
    fn Open(&self, name: string) -> (Arc<dyn fs::File + Send + Sync>, error) {
        if self.how == "invalid-path" && (name == "./a.txt" || name == "/a.txt") {
            return self.inner.Open(s("a.txt"));
        }
        if self.how == "open-anything" {
            if !fs::ValidPath(name.clone()) {
                return self.inner.Open(name);
            }
            let (f, e) = self.inner.Open(name.clone());
            if e != goish::nil {
                return self.inner.Open(s("a.txt"));
            }
            return (f, e);
        }
        if self.how == "unstable-content" {
            let (f, e) = self.inner.Open(name.clone());
            if e != goish::nil || name != "a.txt" {
                return (f, e);
            }
            return (Arc::new(FlakyFile(f)), goish::nil.into());
        }
        return self.inner.Open(name);
    }
    // goish resolves an interface assertion through a runtime registry
    // and this hook; a concrete type has to override it or `cast!`
    // cannot see past the trait object. Go's assertion is structural
    // and needs neither.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}
struct LyingInfo(Arc<dyn fs::FileInfo + Send + Sync>);
impl fs::FileInfo for LyingInfo {
    fn Name(&self) -> string {
        return self.0.Name();
    }
    fn Size(&self) -> i64 {
        return self.0.Size() + 100;
    }
    fn Mode(&self) -> fs::FileMode {
        return self.0.Mode();
    }
    fn ModTime(&self) -> time::Time {
        return self.0.ModTime();
    }
    fn IsDir(&self) -> bool {
        return self.0.IsDir();
    }
    fn Sys(&self) -> Arc<dyn core::any::Any + Send + Sync> {
        return self.0.Sys();
    }
}
struct LyingEntry(Arc<dyn fs::DirEntry + Send + Sync>);
impl fs::DirEntry for LyingEntry {
    fn Name(&self) -> string {
        return self.0.Name();
    }
    fn IsDir(&self) -> bool {
        return self.0.IsDir();
    }
    fn Type(&self) -> fs::FileMode {
        return self.0.Type();
    }
    fn Info(&self) -> (Arc<dyn fs::FileInfo + Send + Sync>, error) {
        let (fi, e) = self.0.Info();
        if e != goish::nil {
            return (fi, e);
        }
        return (Arc::new(LyingInfo(fi)), goish::nil.into());
    }
}
impl fs::ReadDirFS for BrokenFS {
    fn Open(&self, name: string) -> (Arc<dyn fs::File + Send + Sync>, error) {
        return fs::FS::Open(self, name);
    }
    fn ReadDir(&self, name: string) -> (slice<Arc<dyn fs::DirEntry + Send + Sync>>, error) {
        let (ents, e) = fs::ReadDir(&*self.inner, name);
        if e != goish::nil {
            return (ents, e);
        }
        if self.how == "hide-entry" {
            let mut out: Vec<Arc<dyn fs::DirEntry + Send + Sync>> = Vec::new();
            for i in 0..ents.Len() {
                if ents[i].Name() != "a.txt" {
                    out.push(ents[i].clone());
                }
            }
            return (slice::__from_vec(out), goish::nil.into());
        }
        if self.how == "wrong-size" {
            let mut out: Vec<Arc<dyn fs::DirEntry + Send + Sync>> = Vec::new();
            for i in 0..ents.Len() {
                out.push(Arc::new(LyingEntry(ents[i].clone())));
            }
            return (slice::__from_vec(out), goish::nil.into());
        }
        return (ents, e);
    }
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    // goish resolves an interface assertion through a runtime registry
    // rather than structurally, so a type implementing ReadDirFS has
    // to register that impl for `fs::ReadDir` to find it. Go needs no
    // such step; this is the goish idiom, and without it the broken
    // ReadDir below is simply never consulted.
    fs::__goish_register_ReadDirFS_impl::<BrokenFS>();
    let good = goodFS();
    let g: Arc<dyn fs::FS + Send + Sync> = good.clone();
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "ok all-names -> %s",
            errText(fstest::TestFS(
                g.clone(),
                &slice::__from_vec(alloc::vec![s("a.txt"), s("dir/b.txt"), s("dir/sub/c")])
            ))
        ),
    );
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "ok subset -> %s",
            errText(fstest::TestFS(
                g.clone(),
                &slice::__from_vec(alloc::vec![s("a.txt")])
            ))
        ),
    );
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "ok none -> %s",
            errText(fstest::TestFS(g.clone(), &slice::__from_vec(Vec::new())))
        ),
    );
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "missing-expected -> caught=%v",
            fstest::TestFS(
                g.clone(),
                &slice::__from_vec(alloc::vec![s("a.txt"), s("nope.txt")])
            ) != goish::nil
        ),
    );
    let empty: Arc<dyn fs::FS + Send + Sync> = Arc::new(fstest::MapFS::new());
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "empty-fs -> %s",
            errText(fstest::TestFS(empty, &slice::__from_vec(Vec::new())))
        ),
    );
    for (name, how) in [
        ("opens-invalid-path", "invalid-path"),
        ("content-differs", "unstable-content"),
        ("stat-disagrees", "wrong-size"),
        ("readdir-hides", "hide-entry"),
        ("open-succeeds-missing", "open-anything"),
    ] {
        let b: Arc<dyn fs::FS + Send + Sync> = Arc::new(BrokenFS {
            inner: good.clone(),
            how,
        });
        let e = fstest::TestFS(b, &slice::__from_vec(alloc::vec![s("a.txt")]));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("broken %-22s -> caught=%-5v", s(name), e != goish::nil),
        );
    }
    {
        let (f, e) = good.Open(s("a.txt"));
        if e != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("mapfs open-err=%q", e.Error()),
            );
        } else {
            let mut buf = slice::<byte>::__from_vec(alloc::vec![0u8; 64]);
            let (n, _) = f.Read(&mut buf);
            let (st, _) = f.Stat();
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "mapfs read=%q name=%q size=%d mode=%s",
                    string::from_bytes(&buf.to_vec()[..n as usize]),
                    st.Name(),
                    st.Size(),
                    st.Mode()
                ),
            );
            let _ = f.Close();
        }
        for p in ["missing", "dir", "", "/a.txt", "./a.txt", "dir/../a.txt"] {
            let (_, e) = good.Open(s(p));
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("mapfs open %-14q -> err=%s", s(p), errText(e)),
            );
        }
        let (ents, _) = fs::ReadDir(&*good, s("."));
        let mut names: Vec<string> = Vec::new();
        for i in 0..ents.Len() {
            names.push(fmt::Sprintf!("%s(dir=%v)", ents[i].Name(), ents[i].IsDir()));
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "mapfs readdir-root -> [%s]",
                strings::Join(slice::<string>::__from_vec(names), s(" "))
            ),
        );
        let (st, e) = fs::Stat(&*good, s("dir/sub"));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "mapfs implied-dir isdir=%v err=%s",
                e == goish::nil && st.IsDir(),
                errText(e)
            ),
        );
    }
    let _ = io::EOF;
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
