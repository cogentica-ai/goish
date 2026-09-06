// go: file os/tempfile.go decls: nextRandom, CreateTemp, prefixAndSuffix, MkdirTemp, joinPath
// goishlint:ignore GOISH018 runtime_rand — Go pulls its randomness
// from the runtime through a linkname; goish has no such hook, so
// `nextRandom` seeds an LCG from the monotonic clock instead. The
// property both need is the same: two calls in one process do not
// collide.
//
// tempfile.go — CreateTemp and MkdirTemp, and the pattern rules that
// keep a caller-supplied pattern inside the directory it names.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::errors;
use crate::errors::nil;
use crate::gonilable::nilable;
use crate::gostring::string;

use super::{
    bytes_of, error, File, FileMode, IsExist, IsPathSeparator, Mkdir, OpenFile, PathError,
    PathSeparator, TempDir, O_CREATE, O_EXCL, O_RDWR,
};

// go: sdk 1.25.5 os/tempfile.go:22-24 nextRandom
/// Go draws from `runtime.rand()`; goish has no such hook, so this is a
/// seeded LCG. The property both need is the same: two calls in the
/// same process do not collide.
fn nextRandom() -> string {
    use core::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0);

    let mut s = STATE.load(Ordering::Relaxed);
    if s == 0 {
        let ns = crate::convert::uint64(crate::time::Now().UnixNano());
        s = ns ^ 0x9E37_79B9_7F4A_7C15;
        if s == 0 {
            s = 0xDEAD_BEEF_CAFE_BABE;
        }
    }
    // LCG step (Knuth / Numerical Recipes 64-bit constants).
    s = s
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    STATE.store(s, Ordering::Relaxed);
    // Take the top bits — higher quality than the low ones.
    let n = (s >> 32) % 1_000_000_000;
    return crate::strconv::FormatUint(n, 10);
}

// go: sdk 1.25.5 os/tempfile.go:64-76 prefixAndSuffix
/// Split `pattern` by the LAST wildcard `*`, returning the part before
/// it and the part after.
///
/// The path-separator check is the whole safety property of CreateTemp
/// and MkdirTemp: a caller-supplied pattern cannot escape the directory
/// the caller named. goish had no such check, so `CreateTemp(dir,
/// "sub/x*")` created a file in a SUBDIRECTORY and `"../up*"` created
/// one outside `dir` entirely — both silently, both with a nil error.
fn prefixAndSuffix(pattern: &string) -> (string, string, error) {
    let pb = bytes_of(pattern);
    let mut i = 0usize;
    while i < pb.len() {
        if IsPathSeparator(pb[i]) {
            return (string::new(), string::new(), errPatternHasSeparator.into());
        }
        i += 1;
    }
    return match pb.iter().rposition(|&b| b == b'*') {
        Some(pos) => (
            string::from_bytes(&pb[..pos]),
            string::from_bytes(&pb[pos + 1..]),
            nil,
        ),
        None => (pattern.clone(), string::new(), nil),
    };
}

// go: sdk 1.25.5 os/tempfile.go:60-60 errPatternHasSeparator
crate::var! {
    errPatternHasSeparator: error = "pattern contains path separator";
}

// go: sdk 1.25.5 os/tempfile.go:119-124 joinPath
fn joinPath(dir: &string, name: &string) -> string {
    let db = bytes_of(dir);
    if !db.is_empty() && IsPathSeparator(db[db.len() - 1]) {
        return dir.clone() + name.clone();
    }
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(db);
    v.push(PathSeparator);
    v.extend_from_slice(bytes_of(name));
    return string::__from_vec(v);
}

// go: sdk 1.25.5 os/tempfile.go:35-58 CreateTemp
/// Create a new temporary file in `dir`, open it for reading and
/// writing, and return it. The name is `pattern` with a random string
/// added; if `pattern` includes a `*`, the random string replaces the
/// LAST `*`. Mode 0600 before umask. An empty `dir` means `TempDir()`.
///
/// It is the caller's responsibility to remove the file.
// goishlint:ignore GOISH023 — the body ends in the retry loop, and
// every exit from it is an explicit `return`.
pub fn CreateTemp<S1: Into<string>, S2: Into<string>>(
    dir: S1,
    pattern: S2,
) -> (nilable<File>, error) {
    let mut dir: string = dir.into();
    let pattern: string = pattern.into();
    if dir.Len() == 0 {
        dir = TempDir();
    }
    let (prefix, suffix, err) = prefixAndSuffix(&pattern);
    if err != nil {
        return (
            nilable::nil(),
            errors::Wrap(PathError {
                Op: string::from("createtemp"),
                Path: pattern,
                Err: err,
            }),
        );
    }
    let prefix = joinPath(&dir, &prefix);

    let mut try_ = 0;
    loop {
        let name = prefix.clone() + nextRandom() + suffix.clone();
        let (f, err) = OpenFile(name, O_RDWR | O_CREATE | O_EXCL, FileMode(0o600));
        if IsExist(err.clone()) {
            try_ += 1;
            if try_ < 10000 {
                continue;
            }
            return (
                nilable::nil(),
                errors::Wrap(PathError {
                    Op: string::from("createtemp"),
                    Path: prefix + "*" + suffix,
                    Err: super::ErrExist.into(),
                }),
            );
        }
        return (f, err);
    }
}

// go: sdk 1.25.5 os/tempfile.go:77-117 MkdirTemp
/// Create a new temporary directory in `dir` and return its path. Same
/// pattern rules as [`CreateTemp`]; mode 0700 before umask.
// goishlint:ignore GOISH023 — the body ends in the retry loop, and
// every exit from it is an explicit `return`.
pub fn MkdirTemp<S1: Into<string>, S2: Into<string>>(dir: S1, pattern: S2) -> (string, error) {
    let mut dir: string = dir.into();
    let pattern: string = pattern.into();
    if dir.Len() == 0 {
        dir = TempDir();
    }
    let (prefix, suffix, err) = prefixAndSuffix(&pattern);
    if err != nil {
        return (
            string::new(),
            errors::Wrap(PathError {
                Op: string::from("mkdirtemp"),
                Path: pattern,
                Err: err,
            }),
        );
    }
    let prefix = joinPath(&dir, &prefix);

    let mut try_ = 0;
    loop {
        let name = prefix.clone() + nextRandom() + suffix.clone();
        let err = Mkdir(name.clone(), FileMode(0o700));
        if err == nil {
            return (name, nil);
        }
        if IsExist(err.clone()) {
            try_ += 1;
            if try_ < 10000 {
                continue;
            }
            let mut p: Vec<u8> = Vec::new();
            p.extend_from_slice(bytes_of(&dir));
            p.push(PathSeparator);
            p.extend_from_slice(bytes_of(&prefix));
            p.push(b'*');
            p.extend_from_slice(bytes_of(&suffix));
            return (
                string::new(),
                errors::Wrap(PathError {
                    Op: string::from("mkdirtemp"),
                    Path: string::__from_vec(p),
                    Err: super::ErrExist.into(),
                }),
            );
        }
        return (string::new(), err);
    }
}
