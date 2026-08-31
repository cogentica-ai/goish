// go: file io/fs/glob.go decls: Glob, globWithLimit, cleanGlobPath, glob, hasMeta
//
// glob.go — GlobFS, Glob and its helpers.
extern crate alloc;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::gostring::string;
use alloc::sync::Arc;

use crate::types::int;

use super::*;

// go: sdk 1.25.5 io/fs/glob.go:12-19 GlobFS
/// `fs.GlobFS` (glob.go:12) — a file system with its own `Glob`.
/// Embeds [`FS`] in Go (re-declared; see the note in `fs.rs`).
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait GlobFS {
    /// `Open(name)` — open the named file (from embedded [`FS`]).
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error);
    /// `Glob(pattern)` — the names of all files matching `pattern`,
    /// answering the top-level [`Glob`] directly.
    fn Glob(&self, pattern: string) -> (slice<string>, error);
}

// go: sdk 1.25.5 io/fs/glob.go:33-35 Glob
/// Go: "Glob returns the names of all files matching pattern or nil if
/// there is no matching file. The syntax of patterns is the same as in
/// path.Match. The pattern may describe hierarchical names such as
/// usr/*/bin/ed.
///
/// Glob ignores file system errors such as I/O errors reading
/// directories. The only possible returned error is path.ErrBadPattern,
/// reporting that the pattern is malformed."
///
/// If `fsys` implements [`GlobFS`], this calls its `Glob` — the
/// filesystem's chance to answer without a directory walk. Otherwise it
/// falls back to the [`ReadDir`] traversal.
pub fn Glob<S: Into<string>>(
    fsys: &(dyn FS + Send + Sync + 'static),
    pattern: S,
) -> (slice<string>, error) {
    let pattern: string = pattern.into();
    return globWithLimit(fsys, pattern, 0);
}

// go: sdk 1.25.5 io/fs/glob.go:37-83 globWithLimit
/// Go: the recursive worker behind `Glob`.
///
/// The depth limit is not decoration: Go added it for CVE-2022-30630,
/// where a pattern with enough separators drove `globWithLimit` deep
/// enough to exhaust the stack. goish's goroutine stacks are smaller
/// than Go's grow-on-demand ones, so if anything it matters more here.
fn globWithLimit(
    fsys: &(dyn FS + Send + Sync + 'static),
    pattern: string,
    depth: int,
) -> (slice<string>, error) {
    // Go: "This limit is added to prevent stack exhaustion issues. See
    // CVE-2022-30630."
    const pathSeparatorsLimit: int = 10000;
    if depth > pathSeparatorsLimit {
        return (slice::new(), crate::path::ErrBadPattern.clone().into());
    }
    // Go: if fsys, ok := fsys.(GlobFS); ok { return fsys.Glob(pattern) }
    let (gfs, ok) = goish::cast!(fsys, GlobFS);
    if ok {
        return gfs.Glob(pattern);
    }

    // Go: check pattern is well-formed.
    let (_, err) = crate::path::Match(pattern.clone(), string::from_static(""));
    if err != errors::nil {
        return (slice::new(), err);
    }

    if !hasMeta(pattern.clone()) {
        // Go: if _, err = Stat(fsys, pattern); err != nil {
        //         return nil, nil }
        //     return []string{pattern}, nil
        //
        // Note the discarded error: a pattern with no metacharacters
        // that names nothing is "no matches", not a failure.
        let (_, serr) = Stat(fsys, pattern.clone());
        if serr != errors::nil {
            return (slice::new(), errors::nil);
        }
        return (slice::__from_vec(alloc::vec![pattern]), errors::nil);
    }

    let (dir, file) = crate::path::Split(pattern.clone());
    let dir = cleanGlobPath(dir);

    if !hasMeta(dir.clone()) {
        return glob(fsys, dir, file, slice::new());
    }

    // Go: "Prevent infinite recursion. See issue 15879."
    if dir == pattern {
        return (slice::new(), crate::path::ErrBadPattern.clone().into());
    }

    let (m, err) = globWithLimit(fsys, dir, depth + 1);
    if err != errors::nil {
        return (slice::new(), err);
    }
    let mut matches: slice<string> = slice::new();
    for i in 0..m.Len() {
        let (next, gerr) = glob(fsys, m[i].clone(), file.clone(), matches);
        if gerr != errors::nil {
            return (next, gerr);
        }
        matches = next;
    }
    return (matches, errors::nil);
}

// go: sdk 1.25.5 io/fs/glob.go:86-93 cleanGlobPath
/// Go: "cleanGlobPath prepares path for glob matching."
fn cleanGlobPath(p: string) -> string {
    // Go: case "": return "."
    //     default: return path[0 : len(path)-1]  // chop off trailing separator
    if p.Len() == 0 {
        return string::from_static(".");
    }
    let b = p.as_bytes();
    return string::from_bytes(&b[..b.len() - 1]);
}

// go: sdk 1.25.5 io/fs/glob.go:99-117 glob
/// Go: "glob searches for files matching pattern in the directory dir
/// and appends them to matches, returning the updated slice. If the
/// directory cannot be opened, glob returns the existing matches. New
/// matches are added in lexicographical order."
fn glob(
    fsys: &(dyn FS + Send + Sync + 'static),
    dir: string,
    pattern: string,
    matches: slice<string>,
) -> (slice<string>, error) {
    let mut m = matches;
    let (infos, err) = ReadDir(fsys, dir.clone());
    if err != errors::nil {
        // Go: return  // ignore I/O error
        return (m, errors::nil);
    }

    for i in 0..infos.Len() {
        let n = infos[i].Name();
        let (matched, merr) = crate::path::Match(pattern.clone(), n.clone());
        if merr != errors::nil {
            return (m, merr);
        }
        if matched {
            m = crate::append!(
                m,
                crate::path::Join(slice::__from_vec(alloc::vec![dir.clone(), n]))
            );
        }
    }
    return (m, errors::nil);
}

// go: sdk 1.25.5 io/fs/glob.go:121-129 hasMeta
/// Go: "hasMeta reports whether path contains any of the magic
/// characters recognized by path.Match."
fn hasMeta(p: string) -> bool {
    let b = p.as_bytes();
    for i in 0..b.len() {
        match b[i] {
            b'*' | b'?' | b'[' | b'\\' => {
                return true;
            }
            _ => {}
        }
    }
    return false;
}
