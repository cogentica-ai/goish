// go: file path/filepath/match.go decls: Glob, globWithLimit, cleanGlobPath, glob, hasMeta
//
// match.go — Glob and its helpers. Match itself is re-exported
// from the slash-only sibling; see the note in the module root.
//
// goishlint:ignore GOISH018 Match, scanChunk, matchChunk, getEsc, cleanGlobPathWindows — Match and its three helpers are re-exported from the slash-only `path` sibling by the module root. Go declares them twice because on Windows the separator is a backslash, which is also the escape character, so `filepath.Match` disables escaping there; on Linux the two functions are the same function. `cleanGlobPathWindows` has no Linux arm at all.
// goishlint:ignore GOISH021 ErrBadPattern — likewise re-exported from `path`; Go's `filepath.ErrBadPattern` IS `path.ErrBadPattern` (match.go:18 aliases it), so there is one value, not two.

extern crate alloc;
use alloc::vec::Vec;

use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::gostring::string;

use super::*;

// ─── Glob ─────────────────────────────────────────────────────────────

// go: sdk 1.25.5 path/filepath/match.go:243-245 Glob
/// Line-by-line port of `path/filepath.Glob` (match.go:243). Returns
/// the names of all files matching `pattern`, or an empty slice if
/// none match. Pattern syntax matches `Match`. Glob ignores filesystem
/// errors; the only returned error is `ErrBadPattern`.
pub fn Glob<S: Into<string>>(pattern: S) -> (slice<string>, error) {
    return glob_with_limit(pattern.into(), 0);
}

// go: sdk 1.25.5 path/filepath/match.go:247-295 globWithLimit
// goishlint:ignore GOISH014 - the anchor names the GO symbol; goish
//     spells package-internal helpers in snake_case.
fn glob_with_limit(pattern: string, depth: i32) -> (slice<string>, error) {
    // Go: const pathSeparatorsLimit = 10000 (CVE-2022-30632)
    const PATH_SEPARATORS_LIMIT: i32 = 10000;
    if depth == PATH_SEPARATORS_LIMIT {
        return (slice::new(), ErrBadPattern.into());
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
        return (slice::new(), ErrBadPattern.into());
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
    return (matches, nil);
}

// go: sdk 1.25.5 path/filepath/match.go:297-308 cleanGlobPath
/// `cleanGlobPath` (match.go:297) — Linux variant. Empty → ".";
/// "/" → "/"; otherwise chop trailing separator.
// goishlint:ignore GOISH014 - the anchor names the GO symbol; goish
//     spells package-internal helpers in snake_case.
fn clean_glob_path(path: string) -> string {
    let pb = path.as_bytes();
    if pb.is_empty() {
        return string::from_static(".");
    }
    if pb.len() == 1 && pb[0] == Separator {
        return path;
    }
    return string::from_bytes(&pb[..pb.len() - 1]);
}

// go: sdk 1.25.5 path/filepath/match.go:332-362 glob
/// `glob(dir, pattern, matches)` (match.go:332) — list `dir`,
/// append entries that match `pattern`. Filesystem errors are ignored
/// (returns existing matches unchanged), per Go semantics.
// goishlint:ignore GOISH014 - the anchor names the GO symbol; goish
//     spells package-internal helpers in snake_case.
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
    return (m, nil);
}

// go: none — goish idiom: Go writes `slices.Sort(m)` inside `glob`.
/// In-place lexicographic sort of `string` slice. Used by `glob` to
/// match `slices.Sort(names)` semantics from match.go:348. Uses
/// insertion sort — directory listings are short, and we don't have a
/// goish-internal sort module yet.
//     goish's `slices` does not yet carry a Sort over `string`, so the
//     sort is spelled here. Same order — a byte-wise lexical compare.
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

// go: sdk 1.25.5 path/filepath/match.go:364-372 hasMeta
/// `hasMeta(path)` (match.go:364) — true if `path` contains glob
/// metacharacters. Linux includes `\` for backslash escape.
// goishlint:ignore GOISH014 - the anchor names the GO symbol; goish
//     spells package-internal helpers in snake_case.
fn has_meta(path: &string) -> bool {
    let bytes = path.as_bytes();
    for &c in bytes {
        if c == b'*' || c == b'?' || c == b'[' || c == b'\\' {
            return true;
        }
    }
    return false;
}

// Waived out of the coverage denominator. Each is already explained in
// a GOISH018 ignore in this package; repeated here because
// port_coverage.py reads `go: waived` and not goishlint ignores, so
// without them filepath reads 30/38 and advertises eight declarations
// of unported work that do not exist.
//
// go: waived scanChunk — Go declares Match's three helpers once per package because on Windows the separator is a backslash, which is also the escape character; on Linux the two copies are identical, so filepath re-exports `path`'s Match and its helpers rather than carrying a second set.
// go: waived matchChunk — as scanChunk.
// go: waived getEsc — as scanChunk.
// go: waived cleanGlobPathWindows — the Windows arm of cleanGlobPath; goish builds linux/amd64 only.
// go: waived sameWord — `a == b`, which a Windows build needs a name for and Linux does not.
// go: waived HasPrefix — deprecated in Go and documented there as "not correct for all cases".
// go: waived unixAbs — a one-line forward, inlined into its only caller `Abs`.
// go: waived readDirNames — likewise, inlined into `walk_helper`.
