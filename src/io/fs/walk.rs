// go: file io/fs/walk.go decls: walkDir, WalkDir
//
// walk.go — SkipDir, SkipAll, WalkDirFunc, walkDir, WalkDir.
extern crate alloc;
use alloc::sync::Arc;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::gostring::string;

use super::*;

// ─── WalkDir (walk.go) ───────────────────────────────────────────────

// Go: var SkipDir = errors.New("skip this directory")
// Go: var SkipAll = errors.New("skip everything and stop the walk")
//
// Used only as return values from a `WalkDirFunc`; never returned as an
// error by any function. Emitted via `goish::var!` so a bare-symbol
// comparison (`err == SkipDir`) works without `.into()`.
crate::var! {
    // SkipDir — returned from a WalkDirFunc to skip the named directory.
    pub SkipDir: error = "skip this directory";
    // SkipAll — returned from a WalkDirFunc to skip everything and stop.
    pub SkipAll: error = "skip everything and stop the walk";
}

/// `fs.WalkDirFunc` (walk.go:69) — the function called by [`WalkDir`]
/// to visit each file or directory.
///
/// Go: `type WalkDirFunc func(path string, d DirEntry, err error) error`.
/// goish spells the `DirEntry` argument as an interface-borrow
/// (`&(dyn DirEntry + Send + Sync + 'static)`); when [`WalkDir`] has no
/// entry (the failed-`Stat`-on-root case) it passes a nil-interface
/// sentinel, so `d == crate::nil` is the Go `d == nil` test.
pub trait WalkDirFunc: Fn(string, &(dyn DirEntry + Send + Sync + 'static), error) -> error {}
impl<F> WalkDirFunc for F where
    F: Fn(string, &(dyn DirEntry + Send + Sync + 'static), error) -> error
{
}

// go: sdk 1.25.5 io/fs/walk.go:72-103 walkDir
// Go: walkDir — recursively descends `name`, calling `walkDirFn`.
fn walkDir<F: WalkDirFunc>(
    fsys: &(dyn FS + Send + Sync + 'static),
    name: string,
    d: &Arc<dyn DirEntry + Send + Sync>,
    walkDirFn: &F,
) -> error {
    // Go: if err := walkDirFn(name, d, nil); err != nil || !d.IsDir() {
    let err = walkDirFn(name.clone(), &**d, errors::nil.into());
    if err != errors::nil || !d.IsDir() {
        // Go: if err == SkipDir && d.IsDir() { err = nil }
        if err == SkipDir && d.IsDir() {
            return errors::nil;
        }
        return err;
    }

    // Go: dirs, err := ReadDir(fsys, name)
    let (dirs, err) = ReadDir(fsys, name.clone());
    if err != errors::nil {
        // Go: second call, to report the ReadDir error.
        let err = walkDirFn(name.clone(), &**d, err);
        if err != errors::nil {
            // Go: if err == SkipDir && d.IsDir() { err = nil }
            if err == SkipDir && d.IsDir() {
                return errors::nil;
            }
            return err;
        }
    }

    // Go: for _, d1 := range dirs {
    for (_, d1) in crate::range!(&dirs) {
        // Go: name1 := path.Join(name, d1.Name())
        let name1 = crate::path::Join(slice::__from_vec(alloc::vec![name.clone(), d1.Name()]));
        // Go: if err := walkDir(fsys, name1, d1, walkDirFn); err != nil {
        let err = walkDir(fsys, name1, d1, walkDirFn);
        if err != errors::nil {
            // Go: if err == SkipDir { break }
            if err == SkipDir {
                break;
            }
            return err;
        }
    }
    return errors::nil;
}

// go: sdk 1.25.5 io/fs/walk.go:117-128 WalkDir
/// `fs.WalkDir(fsys, root, fn)` (walk.go:117) — walks the file tree
/// rooted at `root`, calling `fn` for each file or directory in the
/// tree, including `root`.
///
/// Files are walked in lexical order. See [`WalkDirFunc`] for how the
/// `fn` return value (including [`SkipDir`] / [`SkipAll`]) controls the
/// walk.
pub fn WalkDir<S: Into<string>, F: WalkDirFunc>(
    fsys: &(dyn FS + Send + Sync + 'static),
    root: S,
    fn_: F,
) -> error {
    let root: string = root.into();
    // Go: info, err := Stat(fsys, root)
    let (info, err) = Stat(fsys, root.clone());
    let err = if err != errors::nil {
        // Go: err = fn(root, nil, err)
        let nil_d: Arc<dyn DirEntry + Send + Sync> = crate::nil.into();
        fn_(root.clone(), &*nil_d, err)
    } else {
        // Go: err = walkDir(fsys, root, FileInfoToDirEntry(info), fn)
        let d = FileInfoToDirEntry(info);
        walkDir(fsys, root, &d, &fn_)
    };
    // Go: if err == SkipDir || err == SkipAll { return nil }
    if err == SkipDir || err == SkipAll {
        return errors::nil;
    }
    return err;
}
