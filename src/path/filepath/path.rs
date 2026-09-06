// go: file path/filepath/path.go decls: ToSlash, FromSlash, VolumeName, Abs, WalkDir, walkDir, Walk, walk, Rel, IsLocal, Localize, EvalSymlinks
//
// path.go — ToSlash, FromSlash, VolumeName, Abs, Rel, Walk,
// WalkDir, SkipDir and SkipAll.
//
// goishlint:ignore GOISH018 Clean, Split, Join, Ext, Base, Dir, IsAbs, SplitList, Localize, unixAbs, readDirNames — Clean/Split/Join/Ext/Base/Dir/IsAbs are re-exported from the slash-only `path` sibling by the module root: on Linux they are byte-identical, and Go only declares them twice because Windows needs volume names and a backslash separator. SplitList's body is in path_unix.rs, Localize's wrapper is here and its check is `io/fs.ValidPath`, `unixAbs` is inlined into `Abs` (its only caller), and `readDirNames` is inlined into `walk_helper` (likewise).
// goishlint:ignore GOISH021 Separator, ListSeparator, WalkFunc, lstat — Separator and ListSeparator are declared in the module root beside the re-exports they belong with; `WalkFunc` is Go's named function type, which goish expresses as the `F: FnMut(...)` bound on `Walk`; and `lstat` is Go's `var lstat = os.Lstat`, a seam that exists only so Go's own tests can swap it.

extern crate alloc;
use alloc::vec::Vec;

use crate::errors::{self, error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::runtime::spin::SpinLock;

use super::*;

// ─── ToSlash / FromSlash — no-op on Unix ──────────────────────────────

// go: sdk 1.25.5 path/filepath/path.go:92-94 ToSlash
/// `filepath.ToSlash(p)` — replaces Separator with '/'. On Unix this is
/// identity. Mirrors filepathlite/path.go:176.
pub fn ToSlash<S: Into<string>>(p: S) -> string {
    return p.into();
}

// go: sdk 1.25.5 path/filepath/path.go:102-104 FromSlash
/// `filepath.FromSlash(p)` — replaces '/' with Separator. On Unix this
/// is identity. Mirrors filepathlite/path.go:184.
pub fn FromSlash<S: Into<string>>(p: S) -> string {
    return p.into();
}

// ─── VolumeName / VolumeNameLen — empty on Unix ───────────────────────

// go: sdk 1.25.5 path/filepath/path.go:473-475 VolumeName
/// `filepath.VolumeName(p)` — leading volume name. Empty on Unix.
/// Mirrors filepathlite/path.go:266.
pub fn VolumeName<S: Into<string>>(_p: S) -> string {
    return string::new();
}

// ─── Abs ──────────────────────────────────────────────────────────────

// go: sdk 1.25.5 path/filepath/path.go:161-163 Abs
/// Line-by-line port of `filepath.Abs` (path.go:161 + path_unix.go's
/// `unixAbs`). If `path` is absolute, returns `Clean(path)`. Otherwise
/// joins `os.Getwd()` with `path`. The Linux semantics mirror Go's
/// `unixAbs` directly — no Windows volume / drive handling needed.
pub fn Abs<S: Into<string>>(path: S) -> (string, error) {
    let path = path.into();
    // Go: if IsAbs(path) { return Clean(path), nil }
    if IsAbs(path.clone()) {
        return (Clean(path), nil);
    }
    // Go: wd, err := os.Getwd(); if err != nil { return "", err }
    let (wd, e) = crate::os::Getwd();
    if !e.IsNil() {
        return (string::new(), e);
    }
    // Go: return Join(wd, path), nil
    let mut elems: alloc::vec::Vec<string> = alloc::vec::Vec::with_capacity(2);
    elems.push(wd);
    elems.push(path);
    let elem_slice = slice::__from_vec(elems);
    return (Join(elem_slice), nil);
}

// ─── Walk / WalkDir ───────────────────────────────────────────────────

/// `filepath.SkipDir` (path.go:259) — sentinel returned from a
/// WalkFunc / WalkDirFunc to signal "skip the directory I'm in".
///
/// Go declares this as `var SkipDir = errors.New("…")`, so call sites
/// reference it as a *value* (`return filepath.SkipDir`,
/// `if err == filepath.SkipDir`). To match that shape in goish — and
/// in particular let `==` work directly — we expose `SkipDir` as a
/// ZST marker with `From<…> for error` and `PartialEq` both ways.
/// Internally the marker materialises to a single shared error value
/// via a SpinLock-cached Arc.
#[derive(Copy, Clone, Default)]
pub struct __SkipDirMarker;

#[allow(non_upper_case_globals)]
pub const SkipDir: __SkipDirMarker = __SkipDirMarker;

const __SKIPDIR_MSG: &str = "skip this directory";

// go: none — goish idiom: Go's `SkipDir` and `SkipAll` are `error`
//     VALUES, compared with `==` and `errors.Is`. goish spells a
//     sentinel as a Copy ZST marker plus the conversions that let it
//     be compared against an `error`; this is one of them.
fn __skipdir_error() -> error {
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(errors::New(__SKIPDIR_MSG));
    }
    return g.as_ref().unwrap().clone();
}

impl From<__SkipDirMarker> for error {
    // go: none — goish idiom: Go's `SkipDir` and `SkipAll` are `error`
    //     VALUES, compared with `==` and `errors.Is`. goish spells a
    //     sentinel as a Copy ZST marker plus the conversions that let it
    //     be compared against an `error`; this is one of them.
    fn from(_: __SkipDirMarker) -> Self {
        return __skipdir_error();
    }
}
impl PartialEq<__SkipDirMarker> for error {
    // go: none — goish idiom: Go's `SkipDir` and `SkipAll` are `error`
    //     VALUES, compared with `==` and `errors.Is`. goish spells a
    //     sentinel as a Copy ZST marker plus the conversions that let it
    //     be compared against an `error`; this is one of them.
    fn eq(&self, _: &__SkipDirMarker) -> bool {
        if self.IsNil() {
            return false;
        }
        return self.Error() == __SKIPDIR_MSG;
    }
}
impl PartialEq<error> for __SkipDirMarker {
    // go: none — goish idiom: Go's `SkipDir` and `SkipAll` are `error`
    //     VALUES, compared with `==` and `errors.Is`. goish spells a
    //     sentinel as a Copy ZST marker plus the conversions that let it
    //     be compared against an `error`; this is one of them.
    fn eq(&self, e: &error) -> bool {
        return e == self;
    }
}
impl errors::IsTarget for __SkipDirMarker {
    #[inline]
    // go: none — goish idiom: Go's `SkipDir` and `SkipAll` are `error`
    //     VALUES, compared with `==` and `errors.Is`. goish spells a
    //     sentinel as a Copy ZST marker plus the conversions that let it
    //     be compared against an `error`; this is one of them.
    fn __resolve(&self) -> error {
        return __skipdir_error();
    }
}

/// `filepath.SkipAll` (path.go:264) — sentinel returned from a
/// WalkFunc / WalkDirFunc to signal "stop the walk entirely". Same
/// ZST-marker shape as `SkipDir`.
#[derive(Copy, Clone, Default)]
pub struct __SkipAllMarker;

#[allow(non_upper_case_globals)]
pub const SkipAll: __SkipAllMarker = __SkipAllMarker;

const __SKIPALL_MSG: &str = "skip everything and stop the walk";

// go: none — goish idiom: Go's `SkipDir` and `SkipAll` are `error`
//     VALUES, compared with `==` and `errors.Is`. goish spells a
//     sentinel as a Copy ZST marker plus the conversions that let it
//     be compared against an `error`; this is one of them.
fn __skipall_error() -> error {
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(errors::New(__SKIPALL_MSG));
    }
    return g.as_ref().unwrap().clone();
}

impl From<__SkipAllMarker> for error {
    // go: none — goish idiom: Go's `SkipDir` and `SkipAll` are `error`
    //     VALUES, compared with `==` and `errors.Is`. goish spells a
    //     sentinel as a Copy ZST marker plus the conversions that let it
    //     be compared against an `error`; this is one of them.
    fn from(_: __SkipAllMarker) -> Self {
        return __skipall_error();
    }
}
impl PartialEq<__SkipAllMarker> for error {
    // go: none — goish idiom: Go's `SkipDir` and `SkipAll` are `error`
    //     VALUES, compared with `==` and `errors.Is`. goish spells a
    //     sentinel as a Copy ZST marker plus the conversions that let it
    //     be compared against an `error`; this is one of them.
    fn eq(&self, _: &__SkipAllMarker) -> bool {
        if self.IsNil() {
            return false;
        }
        return self.Error() == __SKIPALL_MSG;
    }
}
impl PartialEq<error> for __SkipAllMarker {
    // go: none — goish idiom: Go's `SkipDir` and `SkipAll` are `error`
    //     VALUES, compared with `==` and `errors.Is`. goish spells a
    //     sentinel as a Copy ZST marker plus the conversions that let it
    //     be compared against an `error`; this is one of them.
    fn eq(&self, e: &error) -> bool {
        return e == self;
    }
}
impl errors::IsTarget for __SkipAllMarker {
    #[inline]
    // go: none — goish idiom: Go's `SkipDir` and `SkipAll` are `error`
    //     VALUES, compared with `==` and `errors.Is`. goish spells a
    //     sentinel as a Copy ZST marker plus the conversions that let it
    //     be compared against an `error`; this is one of them.
    fn __resolve(&self) -> error {
        return __skipall_error();
    }
}

// `filepathDirEnt` — a concrete `fs.DirEntry` synthesised for the
// walk root (which does not come from a parent `os.ReadDir`). Go uses
// `fs.FileInfoToDirEntry(info)`; the slim equivalent carries just the
// base name and the mode bits an `os.Lstat` reported. Its `Info()`
// re-stats the path (matching `fs.dirInfo` / `unixDirent` behaviour).
#[allow(non_camel_case_types)]
struct filepathDirEnt {
    full: string,
    name: string,
    mode: crate::os::FileMode,
}

impl crate::os::DirEntry for filepathDirEnt {
    // go: none — goish idiom: Go's `WalkDir` hands the callback the
    //     `fs.DirEntry` the readdir already produced. goish's `os`
    //     readdir yields a different concrete type, so this adapts it
    //     to the `DirEntry` interface the callback expects.
    fn Name(&self) -> string {
        return self.name.clone();
    }
    // go: none — goish idiom: Go's `WalkDir` hands the callback the
    //     `fs.DirEntry` the readdir already produced. goish's `os`
    //     readdir yields a different concrete type, so this adapts it
    //     to the `DirEntry` interface the callback expects.
    fn IsDir(&self) -> bool {
        return self.mode.IsDir();
    }
    // go: none — goish idiom: Go's `WalkDir` hands the callback the
    //     `fs.DirEntry` the readdir already produced. goish's `os`
    //     readdir yields a different concrete type, so this adapts it
    //     to the `DirEntry` interface the callback expects.
    fn Type(&self) -> crate::os::FileMode {
        return self.mode.Type();
    }
    // go: none — goish idiom: Go's `WalkDir` hands the callback the
    //     `fs.DirEntry` the readdir already produced. goish's `os`
    //     readdir yields a different concrete type, so this adapts it
    //     to the `DirEntry` interface the callback expects.
    fn Info(
        &self,
    ) -> (
        alloc::sync::Arc<dyn crate::os::FileInfo + Send + Sync>,
        error,
    ) {
        let (info, err) = crate::os::Lstat(self.full.clone());
        if !err.IsNil() {
            return (crate::nil.into(), err);
        }
        return (alloc::sync::Arc::new(info), nil);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: sdk 1.25.5 path/filepath/path.go:395-406 WalkDir
/// Line-by-line port of `filepath.WalkDir(root, fn)` (path.go:395).
/// Walks the file tree rooted at `root`, calling `fn` for each file or
/// directory, including `root` itself. Entries are walked in lexical
/// order. Symbolic links are not followed.
///
/// Slim deviation: `fn` is `FnMut`. The closure signature mirrors Go's
/// `WalkDirFunc` — `(string, &dyn os::DirEntry, error) -> error` — with
/// the `DirEntry` argument spelled as an interface-borrow.
pub fn WalkDir<F>(root: string, mut fn_: F) -> error
where
    F: FnMut(string, &(dyn crate::os::DirEntry + Send + Sync + 'static), error) -> error,
{
    // Go: info, err := os.Lstat(root)
    let (info, err) = crate::os::Lstat(root.clone());
    let walk_err = if !err.IsNil() {
        // Go: err = fn(root, nil, err)
        let d = synth_direntry(root.clone(), crate::os::FileMode(0));
        fn_(root.clone(), &*d, err)
    } else {
        // Go: err = walkDir(root, fs.FileInfoToDirEntry(info), fn)
        let d = synth_direntry(root.clone(), info.Mode());
        walk_dir(root, &d, &mut fn_)
    };
    // Go: if err == SkipDir || err == SkipAll { return nil }
    if errors::Is(walk_err.clone(), SkipDir) || errors::Is(walk_err.clone(), SkipAll) {
        return nil;
    }
    return walk_err;
}

// go: none — goish idiom: `WalkDir` needs a `DirEntry` for the ROOT,
//     which no readdir produced. Go builds one with
//     `fs.FileInfoToDirEntry(info)`; goish's equivalent lives in io/fs
//     over `fs.FileInfo`, and this walk carries `os::FileInfoData`.
fn synth_direntry(
    name: string,
    mode: crate::os::FileMode,
) -> alloc::sync::Arc<dyn crate::os::DirEntry + Send + Sync> {
    return alloc::sync::Arc::new(filepathDirEnt {
        full: name.clone(),
        name: Base(name),
        mode,
    });
}

// go: sdk 1.25.5 path/filepath/path.go:309-341 walkDir
// goishlint:ignore GOISH014 - the anchor names the GO symbol; goish
//     spells package-internal helpers in snake_case.
fn walk_dir<F>(
    path_: string,
    d: &alloc::sync::Arc<dyn crate::os::DirEntry + Send + Sync>,
    fn_: &mut F,
) -> error
where
    F: FnMut(string, &(dyn crate::os::DirEntry + Send + Sync + 'static), error) -> error,
{
    // Go: if err := walkDirFn(path, d, nil); err != nil || !d.IsDir() {
    //         if err == SkipDir && d.IsDir() { err = nil }
    //         return err
    //     }
    {
        let err = fn_(path_.clone(), &**d, nil);
        if !err.IsNil() || !d.IsDir() {
            if errors::Is(err.clone(), SkipDir) && d.IsDir() {
                return nil;
            }
            return err;
        }
    }

    // Go: dirs, err := os.ReadDir(path)
    let (dirs, err) = crate::os::ReadDir(path_.clone());
    if !err.IsNil() {
        // Go: err = walkDirFn(path, d, err); ... if err == SkipDir && d.IsDir() { err = nil }
        let err = fn_(path_.clone(), &**d, err);
        if !err.IsNil() {
            if errors::Is(err.clone(), SkipDir) && d.IsDir() {
                return nil;
            }
            return err;
        }
    }
    // Go: for _, d1 := range dirs { ... }
    let dirs_v = dirs.__into_vec();
    for d1 in dirs_v.into_iter() {
        // Go: path1 := Join(path, d1.Name())
        let mut elems: Vec<string> = Vec::with_capacity(2);
        elems.push(path_.clone());
        elems.push(d1.Name());
        let path1 = Join(slice::__from_vec(elems));
        let err = walk_dir(path1, &d1, fn_);
        if !err.IsNil() {
            // Go: if err == SkipDir { break }; return err
            if errors::Is(err.clone(), SkipDir) {
                break;
            }
            return err;
        }
    }
    return nil;
}

// go: sdk 1.25.5 path/filepath/path.go:422-433 Walk
/// Line-by-line port of `filepath.Walk(root, fn)` (path.go:422).
/// Older callback shape carrying FileInfo at every node — calls
/// os.Lstat on each visited path, so it's strictly more expensive
/// than `WalkDir`.
///
/// Slim: closure signature is `(string, FileInfo, error) -> error`;
/// FnMut to allow accumulating state.
pub fn Walk<F>(root: string, mut fn_: F) -> error
where
    F: FnMut(string, crate::os::FileInfoData, error) -> error,
{
    // Go: info, err := os.Lstat(root)
    let (info, err) = crate::os::Lstat(root.clone());
    let walk_err = if !err.IsNil() {
        fn_(root.clone(), info, err)
    } else {
        walk_helper(root, info, &mut fn_)
    };
    if errors::Is(walk_err.clone(), SkipDir) || errors::Is(walk_err.clone(), SkipAll) {
        return nil;
    }
    return walk_err;
}

// go: sdk 1.25.5 path/filepath/path.go:343-393 walk
// goishlint:ignore GOISH014 - the anchor names the GO symbol. `walk` is
//     also the name of the exported `Walk`'s lowercase twin here, so the
//     helper carries a suffix.
fn walk_helper<F>(path_: string, info: crate::os::FileInfoData, fn_: &mut F) -> error
where
    F: FnMut(string, crate::os::FileInfoData, error) -> error,
{
    // Go: if !info.IsDir() { return walkFn(path, info, nil) }
    if !info.IsDir() {
        return fn_(path_, info, nil);
    }
    // Go: names, err := readDirNames(path); err1 := walkFn(path, info, err)
    let (entries, rd_err) = crate::os::ReadDir(path_.clone());
    let err1 = fn_(path_.clone(), info.clone(), rd_err.clone());
    // Go: if err != nil || err1 != nil { return err1 }
    if !rd_err.IsNil() || !err1.IsNil() {
        return err1;
    }
    // Go: for _, name := range names { filename := Join(path, name); fileInfo, err := lstat(filename); ... }
    let entries_v = entries.__into_vec();
    for d in entries_v.into_iter() {
        let mut elems: Vec<string> = Vec::with_capacity(2);
        elems.push(path_.clone());
        elems.push(d.Name());
        let filename = Join(slice::__from_vec(elems));
        let (file_info, err) = crate::os::Lstat(filename.clone());
        if !err.IsNil() {
            // Go: if err := walkFn(filename, fileInfo, err); err != nil && err != SkipDir { return err }
            let cb_err = fn_(filename, file_info, err);
            if !cb_err.IsNil() && !errors::Is(cb_err.clone(), SkipDir) {
                return cb_err;
            }
        } else {
            // Go: err = walk(filename, fileInfo, walkFn)
            //     if err != nil { if !fileInfo.IsDir() || err != SkipDir { return err } }
            let is_dir_now = file_info.IsDir();
            let err = walk_helper(filename, file_info, fn_);
            if !err.IsNil() && (!is_dir_now || !errors::Is(err.clone(), SkipDir)) {
                return err;
            }
        }
    }
    return nil;
}

// ─── Rel ──────────────────────────────────────────────────────────────

// go: sdk 1.25.5 path/filepath/path.go:184-254 Rel
/// `filepath.Rel(basepath, targpath)` — returns a relative path lexically
/// equivalent to targpath when joined to basepath. Mirrors path.go:184.
pub fn Rel<S1: Into<string>, S2: Into<string>>(basepath: S1, targpath: S2) -> (string, error) {
    let basepath = basepath.into();
    let targpath = targpath.into();
    let base_clean = Clean(basepath.clone());
    let targ_clean = Clean(targpath.clone());
    if base_clean == targ_clean {
        return (string::from_static("."), nil);
    }
    let base = base_clean.as_bytes();
    let targ = targ_clean.as_bytes();
    let cur_base = if base == b"." { &b""[..] } else { base };
    let base_slashed = !cur_base.is_empty() && cur_base[0] == Separator;
    let targ_slashed = !targ.is_empty() && targ[0] == Separator;
    if base_slashed != targ_slashed {
        return (string::new(), rel_err(&basepath, &targpath));
    }

    let bl = cur_base.len();
    let tl = targ.len();
    let (mut b0, mut bi, mut t0, mut ti) = (0usize, 0usize, 0usize, 0usize);
    loop {
        while bi < bl && cur_base[bi] != Separator {
            bi += 1;
        }
        while ti < tl && targ[ti] != Separator {
            ti += 1;
        }
        if &targ[t0..ti] != &cur_base[b0..bi] {
            break;
        }
        if bi < bl {
            bi += 1;
        }
        if ti < tl {
            ti += 1;
        }
        b0 = bi;
        t0 = ti;
    }
    if &cur_base[b0..bi] == b".." {
        return (string::new(), rel_err(&basepath, &targpath));
    }
    if b0 != bl {
        // count separators in cur_base[b0..bl]
        let seps = cur_base[b0..bl].iter().filter(|&&c| c == Separator).count();
        let mut size = 2 + seps * 3;
        if tl != t0 {
            size += 1 + tl - t0;
        }
        let mut buf: Vec<u8> = alloc::vec![0u8; size];
        buf[0] = b'.';
        buf[1] = b'.';
        let mut n = 2usize;
        for _ in 0..seps {
            buf[n] = Separator;
            buf[n + 1] = b'.';
            buf[n + 2] = b'.';
            n += 3;
        }
        if t0 != tl {
            buf[n] = Separator;
            buf[n + 1..n + 1 + tl - t0].copy_from_slice(&targ[t0..tl]);
        }
        return (string::__from_vec(buf), nil);
    }
    return (string::from_bytes(&targ[t0..]), nil);
}

// go: none — goish idiom: Go writes
//     `errors.New("Rel: can't make " + targpath + " relative to " + basepath)`
//     at the three places Rel gives up. Named once here.
fn rel_err(basepath: &string, targpath: &string) -> error {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(b"Rel: can't make ");
    v.extend_from_slice(targpath.as_bytes());
    v.extend_from_slice(b" relative to ");
    v.extend_from_slice(basepath.as_bytes());
    return errors::New(string::__from_vec(v));
}

// go: sdk 1.25.5 path/filepath/path.go:73-75 IsLocal
//
// Go's is a one-line forward to `internal/filepathlite.IsLocal`
// (path.go:141), which forwards again to the per-OS `isLocal`. goish
// inlines the chain; the anchor stays on the exported declaration so
// this file ports exactly one Go file.
pub fn IsLocal<S: Into<string>>(p: S) -> bool {
    let p = p.into();
    let bytes = p.as_bytes();
    if bytes.is_empty() || bytes[0] == Separator {
        return false;
    }
    // Detect any "." or ".." element. If found, Clean and re-check the head.
    let mut has_dots = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let mut j = i;
        while j < bytes.len() && bytes[j] != Separator {
            j += 1;
        }
        let part = &bytes[i..j];
        if part == b"." || part == b".." {
            has_dots = true;
            break;
        }
        i = if j < bytes.len() { j + 1 } else { j };
    }
    let cleaned = if has_dots { Clean(p) } else { p };
    let cb = cleaned.as_bytes();
    if cb == b".." {
        return false;
    }
    if cb.len() >= 3 && &cb[..3] == b"../" {
        return false;
    }
    return true;
}

// go: sdk 1.25.5 path/filepath/path.go:85-87 Localize
/// `filepath.Localize(p)` — convert slash-separated path to OS path.
/// Errors if `p` is not a valid `io/fs.ValidPath`. On Unix the conversion
/// itself is identity, so the only failure mode is embedded NUL.
/// Mirrors filepathlite/path.go:168 + path_unix.go:27.
//
// Same forwarding chain as `IsLocal` above.
pub fn Localize<S: Into<string>>(p: S) -> (string, error) {
    let p = p.into();
    // Go: if !fs.ValidPath(path) { return "", errInvalidPath }
    //
    // This used to call a local copy of ValidPath, and the copy said
    // yes to the empty string — so Localize("") returned ("", nil)
    // where Go returns an error. io/fs owns the predicate; there is no
    // reason for a second one to drift from it.
    if !crate::io::fs::ValidPath(p.clone()) {
        return (string::new(), errInvalidPath());
    }
    // Go's per-OS `localize`; the Unix one (filepathlite/path_unix.go:27)
    // rejects only a NUL. A backslash is a legal filename byte here — it
    // is Windows that cannot take one, because there it is a separator.
    if p.as_bytes().contains(&0u8) {
        return (string::new(), errInvalidPath());
    }
    return (p, nil);
}

// go: none — goish idiom: Go writes `errInvalidPath` as a package-level
//     `var` in filepathlite. goish mints it on demand; the message is
//     Go's.
fn errInvalidPath() -> error {
    return errors::New("invalid path");
}

// ─── SplitList ────────────────────────────────────────────────────────

/// `filepath.SplitList(p)` — splits PATH-style list at ListSeparator.
/// Empty input yields empty result (not `[""]`). Mirrors
/// path/filepath/path_unix.go and filepath.SplitList.

// go: sdk 1.25.5 path/filepath/path.go:147-150 EvalSymlinks
//
// Go's forwards to the per-OS `evalSymlinks`, which on Unix forwards
// again to `walkSymlinks` in symlink.rs. goish collapses the two
// forwards; the anchor stays on the exported declaration.
pub fn EvalSymlinks<S: Into<string>>(path: S) -> (string, error) {
    return super::walk_symlinks(path.into());
}
