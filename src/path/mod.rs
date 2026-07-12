// path — Go's slash-only `path` package, ported.
//
// Reference: /share/go/src/path/path.go.
//
// Use this for forward-slash paths like URLs. For OS file paths use
// the [filepath] sibling. Linux-only goish makes the two behaviorally
// identical, but we keep the split because Go does — and any user that
// reaches for `path` is signaling "URL-shaped", not "filesystem-shaped".
//
// Public API mirrors Go:
//
//   path::Clean(p)                   path.Clean(p)
//   path::Split(p) -> (dir, file)    dir, file := path.Split(p)
//   path::Join(elem)                 path.Join(elem...)
//   path::Ext(p)                     path.Ext(p)
//   path::Base(p)                    path.Base(p)
//   path::IsAbs(p)                   path.IsAbs(p)
//   path::Dir(p)                     path.Dir(p)
//   path::Match(pat, name)           ok, err := path.Match(...)
//
// What v1 omits: nothing — every function in path.go and match.go is here.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, rune};
use crate::unicode::utf8;

const SEP: byte = b'/';

// ─── lazybuf — lazily constructed path buffer (path.go:20) ─────────────

struct LazyBuf<'a> {
    s: &'a [u8],
    buf: Option<Vec<u8>>,
    w: usize,
}

impl<'a> LazyBuf<'a> {
    fn new(s: &'a [u8]) -> Self {
        Self { s, buf: None, w: 0 }
    }

    fn index(&self, i: usize) -> byte {
        match &self.buf {
            Some(b) => b[i],
            None => self.s[i],
        }
    }

    fn append(&mut self, c: byte) {
        if self.buf.is_none() {
            if self.w < self.s.len() && self.s[self.w] == c {
                self.w += 1;
                return;
            }
            let mut b = alloc::vec![0u8; self.s.len()];
            b[..self.w].copy_from_slice(&self.s[..self.w]);
            self.buf = Some(b);
        }
        let b = self.buf.as_mut().unwrap();
        b[self.w] = c;
        self.w += 1;
    }

    fn finish(self) -> string {
        match self.buf {
            None => string::from_bytes(&self.s[..self.w]),
            Some(b) => string::from_bytes(&b[..self.w]),
        }
    }
}

// ─── Clean / Split / Join / Ext / Base / IsAbs / Dir ──────────────────

/// `path.Clean(p)` — shortest path equivalent by purely lexical processing.
/// Mirrors path.go:72.
pub fn Clean<S: Into<string>>(p: S) -> string {
    let path_s = p.into();
    let path = path_s.as_bytes();
    if path.is_empty() {
        return string::from_static(".");
    }

    let rooted = path[0] == SEP;
    let n = path.len();

    let mut out = LazyBuf::new(path);
    let mut r: usize = 0;
    let mut dotdot: usize = 0;
    if rooted {
        out.append(SEP);
        r = 1;
        dotdot = 1;
    }

    while r < n {
        if path[r] == SEP {
            r += 1;
        } else if path[r] == b'.' && (r + 1 == n || path[r + 1] == SEP) {
            r += 1;
        } else if path[r] == b'.'
            && r + 1 < n
            && path[r + 1] == b'.'
            && (r + 2 == n || path[r + 2] == SEP)
        {
            r += 2;
            if out.w > dotdot {
                out.w -= 1;
                while out.w > dotdot && out.index(out.w) != SEP {
                    out.w -= 1;
                }
            } else if !rooted {
                if out.w > 0 {
                    out.append(SEP);
                }
                out.append(b'.');
                out.append(b'.');
                dotdot = out.w;
            }
        } else {
            if rooted && out.w != 1 || !rooted && out.w != 0 {
                out.append(SEP);
            }
            while r < n && path[r] != SEP {
                out.append(path[r]);
                r += 1;
            }
        }
    }

    if out.w == 0 {
        return string::from_static(".");
    }
    out.finish()
}

/// `path.Split(p)` — splits at the final slash. Returns `(dir, file)`.
/// Mirrors path.go:145.
pub fn Split<S: Into<string>>(p: S) -> (string, string) {
    let p = p.into();
    let bytes = p.as_bytes();
    let mut i: isize = bytes.len() as isize - 1;
    while i >= 0 && bytes[i as usize] != SEP {
        i -= 1;
    }
    let cut = (i + 1) as usize;
    (
        string::from_bytes(&bytes[..cut]),
        string::from_bytes(&bytes[cut..]),
    )
}

/// `path.Join(elem...)` — joins with `/`, then Cleans. Empty elements
/// are skipped. Mirrors path.go:155.
pub fn Join(elem: slice<string>) -> string {
    let v = elem.__into_vec();
    let size: usize = v.iter().map(|e| e.as_bytes().len()).sum();
    if size == 0 {
        return string::new();
    }
    let mut buf: Vec<u8> = Vec::with_capacity(size + v.len() - 1);
    for e in v {
        let eb = e.as_bytes();
        if !buf.is_empty() || !eb.is_empty() {
            if !buf.is_empty() {
                buf.push(SEP);
            }
            buf.extend_from_slice(eb);
        }
    }
    Clean(string::__from_vec(buf))
}

/// `path.Ext(p)` — extension at final dot of final element.
/// Mirrors path.go:179.
pub fn Ext<S: Into<string>>(p: S) -> string {
    let p = p.into();
    let bytes = p.as_bytes();
    let mut i: isize = bytes.len() as isize - 1;
    while i >= 0 && bytes[i as usize] != SEP {
        if bytes[i as usize] == b'.' {
            return string::from_bytes(&bytes[i as usize..]);
        }
        i -= 1;
    }
    string::new()
}

/// `path.Base(p)` — last element of path. Mirrors path.go:192.
pub fn Base<S: Into<string>>(p: S) -> string {
    let p = p.into();
    let bytes = p.as_bytes();
    if bytes.is_empty() {
        return string::from_static(".");
    }
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1] == SEP {
        end -= 1;
    }
    let trimmed = &bytes[..end];
    let mut i: isize = trimmed.len() as isize - 1;
    while i >= 0 && trimmed[i as usize] != SEP {
        i -= 1;
    }
    let last = if i >= 0 {
        &trimmed[(i + 1) as usize..]
    } else {
        trimmed
    };
    if last.is_empty() {
        return string::from_static("/");
    }
    string::from_bytes(last)
}

/// `path.IsAbs(p)` — leading slash. Mirrors path.go:212.
pub fn IsAbs<S: Into<string>>(p: S) -> bool {
    let p = p.into();
    let bytes = p.as_bytes();
    !bytes.is_empty() && bytes[0] == SEP
}

/// `path.Dir(p)` — all but last element, Cleaned. Mirrors path.go:223.
pub fn Dir<S: Into<string>>(p: S) -> string {
    let (dir, _) = Split(p);
    Clean(dir)
}

// ─── Match — shell-pattern matching (match.go) ────────────────────────

crate::var! {
    /// `path.ErrBadPattern` — returned from Match on syntax error.
    pub ErrBadPattern: error = "syntax error in pattern";
}

/// `path.Match(pattern, name)` — shell glob match against full name.
/// Returns `(matched, err)`. Mirrors match.go:39.
pub fn Match<S1: Into<string>, S2: Into<string>>(pattern: S1, name: S2) -> (bool, error) {
    let pat = pattern.into();
    let nm = name.into();
    let mut p = pat.as_bytes();
    let mut s = nm.as_bytes();
    'outer: loop {
        if p.is_empty() {
            return (s.is_empty(), nil);
        }
        let (star, chunk, rest) = scan_chunk(p);
        if star && chunk.is_empty() {
            // Trailing * matches rest of name unless it has a /.
            for &c in s {
                if c == SEP {
                    return (false, nil);
                }
            }
            return (true, nil);
        }
        match match_chunk(chunk, s) {
            (Some(t), _) => {
                if t.is_empty() || !rest.is_empty() {
                    s = t;
                    p = rest;
                    continue;
                }
            }
            (None, Some(err)) => return (false, err),
            _ => {}
        }
        if star {
            let mut i = 0usize;
            while i < s.len() && s[i] != SEP {
                match match_chunk(chunk, &s[i + 1..]) {
                    (Some(t), _) => {
                        if rest.is_empty() && !t.is_empty() {
                            i += 1;
                            continue;
                        }
                        s = t;
                        p = rest;
                        continue 'outer;
                    }
                    (None, Some(err)) => return (false, err),
                    _ => {}
                }
                i += 1;
            }
        }
        // Reset name to before match attempt to mirror Go's local return.
        return (false, nil);
    }
}

fn scan_chunk(mut pattern: &[u8]) -> (bool, &[u8], &[u8]) {
    let mut star = false;
    while !pattern.is_empty() && pattern[0] == b'*' {
        pattern = &pattern[1..];
        star = true;
    }
    let mut inrange = false;
    let mut i = 0usize;
    while i < pattern.len() {
        match pattern[i] {
            b'\\' => {
                if i + 1 < pattern.len() {
                    i += 1;
                }
            }
            b'[' => inrange = true,
            b']' => inrange = false,
            b'*' if !inrange => break,
            _ => {}
        }
        i += 1;
    }
    (star, &pattern[..i], &pattern[i..])
}

// On match success returns (Some(rest), None).
// On match failure with no syntax error returns (None, None).
// On syntax error returns (None, Some(err)).
fn match_chunk<'a>(mut chunk: &'a [u8], mut s: &'a [u8]) -> (Option<&'a [u8]>, Option<error>) {
    let mut failed = false;
    while !chunk.is_empty() {
        if !failed && s.is_empty() {
            failed = true;
        }
        match chunk[0] {
            b'[' => {
                let mut r: rune = 0;
                if !failed {
                    let (rr, n) = utf8::DecodeRune(s);
                    r = rr;
                    s = &s[n as usize..];
                }
                chunk = &chunk[1..];
                let mut negated = false;
                if !chunk.is_empty() && chunk[0] == b'^' {
                    negated = true;
                    chunk = &chunk[1..];
                }
                let mut matched = false;
                let mut nrange = 0;
                loop {
                    if !chunk.is_empty() && chunk[0] == b']' && nrange > 0 {
                        chunk = &chunk[1..];
                        break;
                    }
                    let (lo, c1, e) = get_esc(chunk);
                    if let Some(err) = e {
                        return (None, Some(err));
                    }
                    chunk = c1;
                    let (hi, c2) = if !chunk.is_empty() && chunk[0] == b'-' {
                        let (h, c2, e) = get_esc(&chunk[1..]);
                        if let Some(err) = e {
                            return (None, Some(err));
                        }
                        (h, c2)
                    } else {
                        (lo, chunk)
                    };
                    chunk = c2;
                    if lo <= r && r <= hi {
                        matched = true;
                    }
                    nrange += 1;
                }
                if matched == negated {
                    failed = true;
                }
            }
            b'?' => {
                if !failed {
                    if s[0] == SEP {
                        failed = true;
                    }
                    let (_, n) = utf8::DecodeRune(s);
                    s = &s[n as usize..];
                }
                chunk = &chunk[1..];
            }
            b'\\' => {
                chunk = &chunk[1..];
                if chunk.is_empty() {
                    return (None, Some(ErrBadPattern.into()));
                }
                if !failed {
                    if chunk[0] != s[0] {
                        failed = true;
                    }
                    s = &s[1..];
                }
                chunk = &chunk[1..];
            }
            c => {
                if !failed {
                    if c != s[0] {
                        failed = true;
                    }
                    s = &s[1..];
                }
                chunk = &chunk[1..];
            }
        }
    }
    if failed {
        (None, None)
    } else {
        (Some(s), None)
    }
}

fn get_esc(mut chunk: &[u8]) -> (rune, &[u8], Option<error>) {
    if chunk.is_empty() || chunk[0] == b'-' || chunk[0] == b']' {
        return (0, chunk, Some(ErrBadPattern.into()));
    }
    if chunk[0] == b'\\' {
        chunk = &chunk[1..];
        if chunk.is_empty() {
            return (0, chunk, Some(ErrBadPattern.into()));
        }
    }
    let (r, n) = utf8::DecodeRune(chunk);
    if r == utf8::RuneError && n == 1 {
        return (0, chunk, Some(ErrBadPattern.into()));
    }
    let nchunk = &chunk[n as usize..];
    if nchunk.is_empty() {
        return (r, nchunk, Some(ErrBadPattern.into()));
    }
    (r, nchunk, None)
}

// ─── filepath subpackage ──────────────────────────────────────────────

pub mod filepath;
