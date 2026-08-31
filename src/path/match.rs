// go: file path/match.go decls: Match, scanChunk, matchChunk, getEsc
//
// match.go — shell-pattern matching: Match and its three helpers.

extern crate alloc;

use crate::errors::{error, nil};
use crate::gostring::string;
use crate::types::rune;
use crate::unicode::utf8;

use super::*;

// ─── Match — shell-pattern matching (match.go) ────────────────────────

crate::var! {
    /// `path.ErrBadPattern` — returned from Match on syntax error.
    pub ErrBadPattern: error = "syntax error in pattern";
}

// go: sdk 1.25.5 path/match.go:37-88 Match
/// `path.Match(pattern, name)` — shell glob match against full name.
/// Returns `(matched, err)`. Mirrors match.go:39.
// goishlint:ignore GOISH023 — the body ends in an infinite `loop` whose
//     every exit is a `return` from inside it, so there is no tail
//     expression to make explicit. Go writes the same shape: a labelled
//     `Pattern:` loop with returns in the body.
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

// go: sdk 1.25.5 path/match.go:92-121 scanChunk
// goishlint:ignore GOISH014 - the anchor names the GO symbol. goish
//     spells package-internal helpers in snake_case; the exported
//     surface keeps Go's names.
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
    return (star, &pattern[..i], &pattern[i..]);
}

// go: sdk 1.25.5 path/match.go:123-207 matchChunk
// goishlint:ignore GOISH014 - the anchor names the GO symbol; see
//     `scan_chunk` above.
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
    return if failed {
        (None, None)
    } else {
        (Some(s), None)
    };
}

// go: sdk 1.25.5 path/match.go:209-230 getEsc
// goishlint:ignore GOISH014 - the anchor names the GO symbol; see
//     `scan_chunk` above.
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
    return (r, nchunk, None);
}
