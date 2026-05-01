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

