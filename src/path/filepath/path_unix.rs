// go: file path/filepath/path_unix.go decls: splitList
//
// path_unix.go — the Unix definitions of IsLocal, Localize and
// SplitList.
//
// goishlint:ignore GOISH018 HasPrefix, abs, join, sameWord — `HasPrefix` is deprecated in Go and documented as "not correct for all cases"; `abs` and `join` are one-line forwards to `unixAbs` and `Clean(strings.Join(...))`, both inlined into their callers here; `sameWord` is `a == b`, which is what a Windows build needs a name for and Linux does not.

extern crate alloc;
use alloc::vec::Vec;

use crate::goslice::slice;
use crate::gostring::string;

use super::*;

// ─── IsLocal / Localize ───────────────────────────────────────────────

// go: sdk 1.25.5 path/filepath/path_unix.go:21-26 splitList
/// `filepath.IsLocal(p)` — purely lexical check that a path stays within
/// its tree. Mirrors filepathlite/path.go:141 + path_unix.go:23.
// goishlint:ignore GOISH014 - the anchor names the GO symbol. Go's
//     exported `SplitList` (path.go:110) is a one-line forward to this
//     per-OS body; goish inlines the pair.
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
    return slice::__from_vec(out);
}
