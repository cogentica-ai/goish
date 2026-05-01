// path/filepath — Go's OS-aware path manipulation, ported.
//
// Reference: /share/go/src/path/filepath/path.go,
//            /share/go/src/internal/filepathlite/path.go,
//            /share/go/src/internal/filepathlite/path_unix.go.
//
// goish v1 is Linux-only, so Separator == '/' and most operations are
// identical to the slash-only `path` package. We keep the split because
// Go does and because user code that imports `path/filepath` is signaling
// "filesystem-shaped" intent — even if today the lexical behavior matches.
//
// Public API mirrors Go:
//
//   filepath::Separator                  filepath.Separator
//   filepath::ListSeparator              filepath.ListSeparator
//   filepath::Clean(p)                   filepath.Clean(p)
//   filepath::IsAbs(p)                   filepath.IsAbs(p)
//   filepath::IsLocal(p)                 filepath.IsLocal(p)
//   filepath::Localize(p)                filepath.Localize(p) (string, error)
//   filepath::ToSlash(p)                 filepath.ToSlash(p)
//   filepath::FromSlash(p)               filepath.FromSlash(p)
//   filepath::VolumeName(p)              filepath.VolumeName(p)
//   filepath::SplitList(p)               filepath.SplitList(p)
//   filepath::Split(p) -> (dir, file)    dir, file := filepath.Split(p)
//   filepath::Join(elem)                 filepath.Join(elem...)
//   filepath::Ext(p)                     filepath.Ext(p)
//   filepath::Base(p)                    filepath.Base(p)
//   filepath::Dir(p)                     filepath.Dir(p)
//   filepath::Rel(base, targ)            filepath.Rel(base, targ) (string, error)
//   filepath::Match(pat, name)           filepath.Match(pat, name) (bool, error)
//
// Phase A (this file): pure-lexical operations only.
// Phase B (deferred): Walk, WalkDir, Glob, EvalSymlinks, Abs — these
// need os.Lstat / os.ReadDir to be wired up.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::errors::{self, error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::runtime::spin::SpinLock;
use crate::types::byte;

/// `filepath.Separator` — '/' on Unix.
pub const Separator: byte = b'/';

/// `filepath.ListSeparator` — ':' on Unix.
pub const ListSeparator: byte = b':';

// On Linux, Clean / Split / Join / Ext / Base / IsAbs / Dir / Match are
// byte-identical to the slash-only sibling. Re-export instead of
// duplicating: same function, same semantics, same type signatures.
//
// User-visible names land at `goish::path::filepath::Clean` etc., exactly
// like Go's `path/filepath.Clean`.

pub use super::{Base, Clean, Dir, ErrBadPattern, Ext, IsAbs, Join, Match, Split};

// ─── ToSlash / FromSlash — no-op on Unix ──────────────────────────────

/// `filepath.ToSlash(p)` — replaces Separator with '/'. On Unix this is
/// identity. Mirrors filepathlite/path.go:176.
pub fn ToSlash<S: Into<string>>(p: S) -> string {
    p.into()
}

/// `filepath.FromSlash(p)` — replaces '/' with Separator. On Unix this
/// is identity. Mirrors filepathlite/path.go:184.
pub fn FromSlash<S: Into<string>>(p: S) -> string {
    p.into()
}

// ─── VolumeName / VolumeNameLen — empty on Unix ───────────────────────

/// `filepath.VolumeName(p)` — leading volume name. Empty on Unix.
/// Mirrors filepathlite/path.go:266.
pub fn VolumeName<S: Into<string>>(_p: S) -> string {
    string::new()
}

// ─── IsLocal / Localize ───────────────────────────────────────────────

/// `filepath.IsLocal(p)` — purely lexical check that a path stays within
/// its tree. Mirrors filepathlite/path.go:141 + path_unix.go:23.
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
    true
}

/// `filepath.Localize(p)` — convert slash-separated path to OS path.
/// Errors if `p` is not a valid `io/fs.ValidPath`. On Unix the conversion
/// itself is identity, so the only failure mode is embedded NUL.
/// Mirrors filepathlite/path.go:168 + path_unix.go:27.
pub fn Localize<S: Into<string>>(p: S) -> (string, error) {
    let p = p.into();
    if !valid_fs_path(p.as_bytes()) {
        return (string::new(), errInvalidPath());
    }
    if p.as_bytes().contains(&0u8) {
        return (string::new(), errInvalidPath());
    }
    (p, nil)
}

// io/fs.ValidPath — duplicated here to avoid pulling in io/fs for one
// predicate. See /share/go/src/io/fs/fs.go:ValidPath.
fn valid_fs_path(name: &[u8]) -> bool {
    if name == b"." {
        return true;
    }
    let mut i = 0usize;
    while i < name.len() {
        let mut j = i;
        while j < name.len() && name[j] != b'/' {
            j += 1;
        }
        let elem = &name[i..j];
        if elem.is_empty() || elem == b"." || elem == b".." {
            return false;
        }
        if j == name.len() {
            return true;
        }
        i = j + 1;
    }
    true
}

fn errInvalidPath() -> error {
    errors::New("invalid path")
}

// ─── SplitList ────────────────────────────────────────────────────────

/// `filepath.SplitList(p)` — splits PATH-style list at ListSeparator.
/// Empty input yields empty result (not `[""]`). Mirrors
/// /share/go/src/path/filepath/path_unix.go and filepath.SplitList.
pub fn SplitList<S: Into<string>>(p: S) -> slice<string> {
    let p = p.into();
    let bytes = p.as_bytes();
    if bytes.is_empty() {
        return slice::new();
    }
    let mut out: Vec<string> = Vec::new();
    let mut i = 0usize;
    let mut start = 0usize;
    while i < bytes.len() {
        if bytes[i] == ListSeparator {
            out.push(string::from_bytes(&bytes[start..i]));
            start = i + 1;
        }
        i += 1;
    }
    out.push(string::from_bytes(&bytes[start..]));
    slice::__from_vec(out)
}

// ─── Abs ──────────────────────────────────────────────────────────────

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
    (Join(elem_slice), nil)
}

// ─── Glob ─────────────────────────────────────────────────────────────

/// Line-by-line port of `path/filepath.Glob` (match.go:243). Returns
/// the names of all files matching `pattern`, or an empty slice if
/// none match. Pattern syntax matches `Match`. Glob ignores filesystem
/// errors; the only returned error is `ErrBadPattern`.
pub fn Glob<S: Into<string>>(pattern: S) -> (slice<string>, error) {
    glob_with_limit(pattern.into(), 0)
}

fn glob_with_limit(pattern: string, depth: i32) -> (slice<string>, error) {
    // Go: const pathSeparatorsLimit = 10000 (CVE-2022-30632)
    const PATH_SEPARATORS_LIMIT: i32 = 10000;
    if depth == PATH_SEPARATORS_LIMIT {
        return (slice::new(), ErrBadPattern());
    }
    // Go: if _, err := Match(pattern, ""); err != nil { return nil, err }
    {
        let (_, err) = Match(pattern.clone(), string::from_static(""));
        if !err.IsNil() {
            return (slice::new(), err);
        }
    }
    // Go: if !hasMeta(pattern) { ... return []string{pattern}, nil }
    if !has_meta(&pattern) {
        let (_, e) = crate::os::Lstat(pattern.clone());
        if !e.IsNil() {
            return (slice::new(), nil);
        }
        let mut out: Vec<string> = Vec::with_capacity(1);
        out.push(pattern);
        return (slice::__from_vec(out), nil);
    }
    // Go: dir, file := Split(pattern)
    let (dir_raw, file) = Split(pattern.clone());
    // Linux slim: volumeLen = 0, no Windows branch.
    let dir = clean_glob_path(dir_raw.clone());

    // Go: if !hasMeta(dir[volumeLen:]) { return glob(dir, file, nil) }
    if !has_meta(&dir) {
        return glob_dir(dir, file, slice::new());
    }
    // Go: if dir == pattern { return nil, ErrBadPattern } (issue 15879)
    if dir == pattern {
        return (slice::new(), ErrBadPattern());
    }
    // Go: m, err = globWithLimit(dir, depth+1)
    let (m, err) = glob_with_limit(dir, depth + 1);
    if !err.IsNil() {
        return (slice::new(), err);
    }
    // Go: for _, d := range m { matches, err = glob(d, file, matches) }
    let mut matches: slice<string> = slice::new();
    let m_vec = m.__into_vec();
    for d in m_vec.into_iter() {
        let (next, e2) = glob_dir(d, file.clone(), matches);
        if !e2.IsNil() {
            return (slice::new(), e2);
        }
        matches = next;
    }
    (matches, nil)
}

/// `cleanGlobPath` (match.go:297) — Linux variant. Empty → ".";
/// "/" → "/"; otherwise chop trailing separator.
fn clean_glob_path(path: string) -> string {
    let pb = path.as_bytes();
    if pb.is_empty() {
        return string::from_static(".");
    }
    if pb.len() == 1 && pb[0] == Separator {
        return path;
    }
    string::from_bytes(&pb[..pb.len() - 1])
}

/// `glob(dir, pattern, matches)` (match.go:332) — list `dir`,
/// append entries that match `pattern`. Filesystem errors are ignored
/// (returns existing matches unchanged), per Go semantics.
fn glob_dir(dir: string, pattern: string, matches: slice<string>) -> (slice<string>, error) {
    let mut m = matches;
    // Go: fi, err := os.Stat(dir); if err != nil { return }
    let (fi, err) = crate::os::Stat(dir.clone());
    if !err.IsNil() {
        return (m, nil);
    }
    // Go: if !fi.IsDir() { return }
    if !fi.IsDir() {
        return (m, nil);
    }
    // Go: d, err := os.Open(dir); if err != nil { return }; defer d.Close()
    // Go: names, _ := d.Readdirnames(-1); slices.Sort(names)
    let (entries, e) = crate::os::ReadDir(dir.clone());
    if !e.IsNil() {
        return (m, nil);
    }
    let entries_v = entries.__into_vec();
    let mut names: Vec<string> = Vec::with_capacity(entries_v.len());
    for d in entries_v.iter() {
        names.push(d.Name());
    }
    // Sort names lexicographically (slices.Sort).
    sort_strings(&mut names);
    // Go: for _, n := range names { matched, err := Match(pattern, n) ...
    //     if matched { m = append(m, Join(dir, n)) } }
    let mut m_vec: Vec<string> = m.__into_vec();
    for n in names.into_iter() {
        let (matched, err) = Match(pattern.clone(), n.clone());
        if !err.IsNil() {
            return (slice::__from_vec(m_vec), err);
        }
        if matched {
            // Go: m = append(m, Join(dir, n))
            let mut elems: Vec<string> = Vec::with_capacity(2);
            elems.push(dir.clone());
            elems.push(n);
            m_vec.push(Join(slice::__from_vec(elems)));
        }
    }
    m = slice::__from_vec(m_vec);
    (m, nil)
}

/// In-place lexicographic sort of `string` slice. Used by `glob` to
/// match `slices.Sort(names)` semantics from match.go:348. Uses
/// insertion sort — directory listings are short, and we don't have a
/// goish-internal sort module yet.
fn sort_strings(v: &mut Vec<string>) {
    let n = v.len();
    let mut i: usize = 1;
    while i < n {
        let mut j = i;
        while j > 0 {
            // Compare bytewise.
            let a = v[j - 1].as_bytes();
            let b = v[j].as_bytes();
            if a <= b {
                break;
            }
            v.swap(j - 1, j);
            j -= 1;
        }
        i += 1;
    }
}

/// `hasMeta(path)` (match.go:364) — true if `path` contains glob
/// metacharacters. Linux includes `\` for backslash escape.
fn has_meta(path: &string) -> bool {
    let bytes = path.as_bytes();
    for &c in bytes {
        if c == b'*' || c == b'?' || c == b'[' || c == b'\\' {
            return true;
        }
    }
    false
}

// ─── Walk / WalkDir ───────────────────────────────────────────────────

/// `filepath.SkipDir` (path.go:259) — sentinel returned from a
/// WalkFunc / WalkDirFunc to signal "skip the directory I'm in".
/// Compared with `errors::Is`, which uses Arc::ptr_eq, so the
/// singleton is cached behind a SpinLock.
pub fn SkipDir() -> error {
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(errors::New("skip this directory"));
    }
    g.as_ref().unwrap().clone()
}

/// `filepath.SkipAll` (path.go:264) — sentinel returned from a
/// WalkFunc / WalkDirFunc to signal "stop the walk entirely".
pub fn SkipAll() -> error {
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(errors::New("skip everything and stop the walk"));
    }
    g.as_ref().unwrap().clone()
}

/// Line-by-line port of `filepath.WalkDir(root, fn)` (path.go:395).
/// Walks the file tree rooted at `root`, calling `fn` for each file or
/// directory, including `root` itself. Entries are walked in lexical
/// order. Symbolic links are not followed.
///
/// Slim deviations: `fn` is `FnMut`; goish has no fs.WalkDirFunc trait,
/// so the closure signature is `(string, DirEntry, error) -> error`.
/// The DirEntry passed for `root` itself synthesises a Type from
/// the FileInfo (since `root` doesn't come from a parent ReadDir).
pub fn WalkDir<F>(root: string, mut fn_: F) -> error
where
    F: FnMut(string, crate::os::DirEntry, error) -> error,
{
    // Go: info, err := os.Lstat(root)
    let (info, err) = crate::os::Lstat(root.clone());
    let walk_err = if !err.IsNil() {
        // Go: err = fn(root, nil, err)
        fn_(root.clone(), synth_direntry(root.clone(), 0), err)
    } else {
        // Go: err = walkDir(root, fs.FileInfoToDirEntry(info), fn)
        let d = synth_direntry(root.clone(), info.Mode());
        walk_dir(root, d, &mut fn_)
    };
    // Go: if err == SkipDir || err == SkipAll { return nil }
    if errors::Is(walk_err.clone(), SkipDir()) || errors::Is(walk_err.clone(), SkipAll()) {
        return nil;
    }
    walk_err
}

fn synth_direntry(name: string, mode: crate::os::FileMode) -> crate::os::DirEntry {
    crate::os::DirEntry {
        Name_: Base(name),
        Type_: mode,
    }
}

fn walk_dir<F>(path_: string, d: crate::os::DirEntry, fn_: &mut F) -> error
where
    F: FnMut(string, crate::os::DirEntry, error) -> error,
{
    // Go: if err := walkDirFn(path, d, nil); err != nil || !d.IsDir() {
    //         if err == SkipDir && d.IsDir() { err = nil }
    //         return err
    //     }
    {
        let err = fn_(path_.clone(), d.clone(), nil);
        if !err.IsNil() || !d.IsDir() {
            if errors::Is(err.clone(), SkipDir()) && d.IsDir() {
                return nil;
            }
            return err;
        }
    }

    // Go: dirs, err := os.ReadDir(path)
    let (dirs, err) = crate::os::ReadDir(path_.clone());
    if !err.IsNil() {
        // Go: err = walkDirFn(path, d, err); ... if err == SkipDir && d.IsDir() { err = nil }
        let err = fn_(path_.clone(), d.clone(), err);
        if !err.IsNil() {
            if errors::Is(err.clone(), SkipDir()) && d.IsDir() {
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
        let err = walk_dir(path1, d1, fn_);
        if !err.IsNil() {
            // Go: if err == SkipDir { break }; return err
            if errors::Is(err.clone(), SkipDir()) {
                break;
            }
            return err;
        }
    }
    nil
}

/// Line-by-line port of `filepath.Walk(root, fn)` (path.go:422).
/// Older callback shape carrying FileInfo at every node — calls
/// os.Lstat on each visited path, so it's strictly more expensive
/// than `WalkDir`.
///
/// Slim: closure signature is `(string, FileInfo, error) -> error`;
/// FnMut to allow accumulating state.
pub fn Walk<F>(root: string, mut fn_: F) -> error
where
    F: FnMut(string, crate::os::FileInfo, error) -> error,
{
    // Go: info, err := os.Lstat(root)
    let (info, err) = crate::os::Lstat(root.clone());
    let walk_err = if !err.IsNil() {
        fn_(root.clone(), info, err)
    } else {
        walk_helper(root, info, &mut fn_)
    };
    if errors::Is(walk_err.clone(), SkipDir()) || errors::Is(walk_err.clone(), SkipAll()) {
        return nil;
    }
    walk_err
}

fn walk_helper<F>(path_: string, info: crate::os::FileInfo, fn_: &mut F) -> error
where
    F: FnMut(string, crate::os::FileInfo, error) -> error,
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
            if !cb_err.IsNil() && !errors::Is(cb_err.clone(), SkipDir()) {
                return cb_err;
            }
        } else {
            // Go: err = walk(filename, fileInfo, walkFn)
            //     if err != nil { if !fileInfo.IsDir() || err != SkipDir { return err } }
            let is_dir_now = file_info.IsDir();
            let err = walk_helper(filename, file_info, fn_);
            if !err.IsNil() && (!is_dir_now || !errors::Is(err.clone(), SkipDir())) {
                return err;
            }
        }
    }
    nil
}

// ─── EvalSymlinks ─────────────────────────────────────────────────────

/// Line-by-line port of `path/filepath.EvalSymlinks` (path.go:147 →
/// symlink.go:16 walkSymlinks). Walks each component of `path`, calling
/// os.Lstat to detect symlinks and os.Readlink to resolve them. Caps
/// chain length at 255 to bail on cycles. Linux slim: no Windows volume
/// handling, no plan9 branch.
pub fn EvalSymlinks<S: Into<string>>(path: S) -> (string, error) {
    walk_symlinks(path.into())
}

fn walk_symlinks(path0: string) -> (string, error) {
    // Go: volLen := filepathlite.VolumeNameLen(path) — Linux: 0.
    let mut path = path0;
    let vol_len: usize = 0;
    let _ = vol_len; // Linux: always 0; kept for parity.
    // Go: if volLen < len(path) && os.IsPathSeparator(path[volLen]) { volLen++ }
    let pb = path.as_bytes();
    let mut vol_len_eff: usize = 0;
    if vol_len_eff < pb.len() && pb[vol_len_eff] == Separator {
        vol_len_eff += 1;
    }
    // Go: vol := path[:volLen]; dest := vol
    let vol_slice = &path.as_bytes()[..vol_len_eff];
    let mut dest: Vec<u8> = vol_slice.to_vec();
    let mut links_walked: i32 = 0;
    // Go: for start, end := volLen, volLen; start < len(path); start = end { ... }
    let mut start: usize = vol_len_eff;
    let mut end: usize;
    loop {
        let pb = path.as_bytes();
        if start >= pb.len() {
            break;
        }
        // Go: for start < len(path) && os.IsPathSeparator(path[start]) { start++ }
        while start < pb.len() && pb[start] == Separator {
            start += 1;
        }
        end = start;
        // Go: for end < len(path) && !os.IsPathSeparator(path[end]) { end++ }
        while end < pb.len() && pb[end] != Separator {
            end += 1;
        }
        // Go: if end == start { break }
        if end == start {
            break;
        }
        let comp = &pb[start..end];
        // Go: else if path[start:end] == "." { continue }
        if comp == b"." {
            start = end;
            continue;
        }
        // Go: else if path[start:end] == ".." { ... back up ... }
        if comp == b".." {
            // Go: for r = len(dest)-1; r >= volLen; r-- { ... }
            let mut r: isize = dest.len() as isize - 1;
            while r >= vol_len_eff as isize {
                if dest[r as usize] == Separator {
                    break;
                }
                r -= 1;
            }
            // Go: if r < volLen || dest[r+1:] == ".."
            let tail_is_dotdot = (r + 1) <= dest.len() as isize
                && &dest[(r + 1) as usize..] == b"..";
            if r < vol_len_eff as isize || tail_is_dotdot {
                // Go: if len(dest) > volLen { dest += pathSeparator }
                if dest.len() > vol_len_eff {
                    dest.push(Separator);
                }
                // Go: dest += ".."
                dest.extend_from_slice(b"..");
            } else {
                // Go: dest = dest[:r]
                dest.truncate(r as usize);
            }
            start = end;
            continue;
        }
        // Ordinary path component. Add it to result.
        // Go: if len(dest) > VolumeNameLen(dest) && !IsPathSeparator(dest[last]) { dest += pathSeparator }
        if dest.len() > vol_len_eff
            && (dest.is_empty() || dest[dest.len() - 1] != Separator)
        {
            dest.push(Separator);
        }
        // Go: dest += path[start:end]
        dest.extend_from_slice(comp);
        // Resolve symlink.
        // Go: fi, err := os.Lstat(dest)
        let dest_s = string::from_bytes(&dest);
        let (fi, err) = crate::os::Lstat(dest_s.clone());
        if !err.IsNil() {
            return (string::new(), err);
        }
        // Go: if fi.Mode()&fs.ModeSymlink == 0 { ... continue }
        if (fi.Mode() & crate::os::ModeSymlink) == 0 {
            // Go: if !fi.Mode().IsDir() && end < len(path) { return "", syscall.ENOTDIR }
            if !fi.IsDir() && end < path.as_bytes().len() {
                return (string::new(), errors::New(string::from_static("not a directory")));
            }
            start = end;
            continue;
        }
        // Found symlink.
        links_walked += 1;
        // Go: if linksWalked > 255 { return "", errors.New("EvalSymlinks: too many links") }
        if links_walked > 255 {
            return (string::new(), errors::New(string::from_static("EvalSymlinks: too many links")));
        }
        // Go: link, err := os.Readlink(dest)
        let (link, err) = crate::os::Readlink(dest_s);
        if !err.IsNil() {
            return (string::new(), err);
        }
        let lb = link.as_bytes();
        // Go: path = link + path[end:]
        let mut new_path: Vec<u8> = Vec::with_capacity(lb.len() + path.as_bytes().len() - end);
        new_path.extend_from_slice(lb);
        new_path.extend_from_slice(&path.as_bytes()[end..]);
        path = string::from_bytes(&new_path);
        // Go: v := VolumeNameLen(link); if v > 0 { ... } else if abs { ... } else { ... }
        // Linux slim: v always 0.
        if !lb.is_empty() && lb[0] == Separator {
            // Symlink to absolute path.
            // Go: dest = link[:1]; end = 1; vol = link[:1]; volLen = 1
            dest = alloc::vec::Vec::new();
            dest.push(Separator);
            end = 1;
            vol_len_eff = 1;
        } else {
            // Symlink to relative path; replace last path component in dest.
            // Go: for r = len(dest)-1; r >= volLen; r-- { if IsPathSeparator { break } }
            let mut r: isize = dest.len() as isize - 1;
            while r >= vol_len_eff as isize {
                if dest[r as usize] == Separator {
                    break;
                }
                r -= 1;
            }
            // Go: if r < volLen { dest = vol } else { dest = dest[:r] }
            if r < vol_len_eff as isize {
                dest.truncate(vol_len_eff);
            } else {
                dest.truncate(r as usize);
            }
            end = 0;
        }
        start = end;
    }
    // Go: return Clean(dest), nil
    (Clean(string::from_bytes(&dest)), nil)
}

// ─── Rel ──────────────────────────────────────────────────────────────

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
    (string::from_bytes(&targ[t0..]), nil)
}

fn rel_err(basepath: &string, targpath: &string) -> error {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(b"Rel: can't make ");
    v.extend_from_slice(targpath.as_bytes());
    v.extend_from_slice(b" relative to ");
    v.extend_from_slice(basepath.as_bytes());
    errors::New(string::__from_vec(v))
}

