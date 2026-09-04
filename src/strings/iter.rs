// go: file strings/iter.go decls: Lines, splitSeq, SplitSeq, SplitAfterSeq, FieldsSeq, FieldsFuncSeq
//
// strings/iter.go — the `iter.Seq[string]` returning splitters.
//
// Each one yields the same strings its slice-building twin would
// return, without building the slice. Go writes them as a closure over
// `yield func(string) bool`, and a `false` from `yield` stops the walk;
// goish's `iter::Seq` is the same closure shape.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use crate::gostring::string;
use crate::types::rune;
use crate::unicode::utf8;


// go: sdk 1.25.5 strings/iter.go:35-65 splitSeq
// goishlint:ignore GOISH014 — the anchor names Go's `splitSeq`; the
//     Rust fn is `split_seq` because `SplitSeq` already takes the
//     camel-case name and Rust is case-sensitive where Go's export
//     rule made the two distinct.
/// The shared body of `SplitSeq` and `SplitAfterSeq`: `sep_save` bytes
/// of each separator are kept in the yielded fragment, 0 or len(sep).
fn split_seq(s: string, sep: string, sep_save: usize) -> impl crate::iter::Seq<string> {
    return move |yield_: &mut dyn FnMut(string) -> bool| {
        let b = s.as_bytes();
        let sepb = sep.as_bytes();
        if sepb.is_empty() {
            // Go: split into UTF-8 sequences (like Split(s, "")).
            // DecodeRune, not a length table keyed on the leading byte:
            // it validates the CONTINUATION bytes too, and returns
            // size 1 for anything malformed. A table says 0xe4 begins a
            // 3-byte rune and hands back "\xe4\xb8" whole; Go yields
            // "\xe4" and "\xb8" separately, which is also what this
            // package's own `explode` (behind Split) already did.
            let mut pos = 0;
            while pos < b.len() {
                let (_, sz) = utf8::DecodeRune(&b[pos..]);
                let size = sz as usize;
                if !yield_(string::from_bytes(&b[pos..pos + size])) {
                    return;
                }
                pos += size;
            }
            return;
        }
        let mut pos = 0;
        loop {
            let found = b[pos..]
                .windows(sepb.len())
                .position(|w| w == sepb)
                .map(|i| pos + i);
            match found {
                Some(i) => {
                    if !yield_(string::from_bytes(&b[pos..i + sep_save])) {
                        return;
                    }
                    pos = i + sepb.len();
                }
                None => break,
            }
        }
        yield_(string::from_bytes(&b[pos..]));
    };
}

// go: sdk 1.25.5 strings/iter.go:67-69 SplitSeq
/// `strings.SplitSeq(s, sep)` (strings/iter.go:70) — iterator over
/// the substrings of `s` separated by `sep`; yields the same strings
/// `Split(s, sep)` returns, without building the slice.
pub fn SplitSeq<S1: Into<string>, S2: Into<string>>(
    s: S1,
    sep: S2,
) -> impl crate::iter::Seq<string> {
    return split_seq(s.into(), sep.into(), 0);
}

// go: sdk 1.25.5 strings/iter.go:75-77 SplitAfterSeq
/// `strings.SplitAfterSeq(s, sep)` (strings/iter.go:78) — like
/// `SplitSeq` but each fragment keeps its trailing separator.
pub fn SplitAfterSeq<S1: Into<string>, S2: Into<string>>(
    s: S1,
    sep: S2,
) -> impl crate::iter::Seq<string> {
    let sep = sep.into();
    let n = sep.as_bytes().len();
    return split_seq(s.into(), sep, n);
}

// go: sdk 1.25.5 strings/iter.go:18-32 Lines
/// `strings.Lines(s)` (strings/iter.go:12) — iterator over the
/// newline-terminated lines of `s`. Each yielded line keeps its
/// trailing `\n`; a final unterminated line is yielded as-is; the
/// empty string yields nothing.
pub fn Lines<S: Into<string>>(s: S) -> impl crate::iter::Seq<string> {
    let s = s.into();
    return move |yield_: &mut dyn FnMut(string) -> bool| {
        let b = s.as_bytes();
        let mut pos = 0;
        while pos < b.len() {
            let end = match b[pos..].iter().position(|&c| c == b'\n') {
                Some(i) => pos + i + 1,
                None => b.len(),
            };
            if !yield_(string::from_bytes(&b[pos..end])) {
                return;
            }
            pos = end;
        }
    };
}

// go: sdk 1.25.5 strings/iter.go:79-110 FieldsSeq
/// An iterator over substrings of `s` split around runs of whitespace,
/// as defined by `unicode.IsSpace`. Yields the same strings
/// [`super::Fields`] would return, without building the slice.
pub fn FieldsSeq<S: Into<string>>(s: S) -> impl crate::iter::Seq<string> {
    let s: string = s.into();
    return move |yield_: &mut dyn FnMut(string) -> bool| {
        let b = s.as_bytes();
        // Go uses -1 for "not in a field"; goish uses None, since a
        // byte offset is a usize here.
        let mut start: Option<usize> = None;
        let mut i = 0usize;
        while i < b.len() {
            let mut size = 1usize;
            let mut r = crate::convert::rune(b[i]);
            let mut isSpace = super::strings::is_ascii_space(b[i]);
            if r >= crate::convert::rune(utf8::RuneSelf) {
                let (r2, s2) = utf8::DecodeRune(&b[i..]);
                r = r2;
                size = s2 as usize;
                isSpace = crate::unicode::IsSpace(r);
            }
            if isSpace {
                if let Some(st) = start {
                    if !yield_(string::from_bytes(&b[st..i])) {
                        return;
                    }
                    start = None;
                }
            } else if start.is_none() {
                start = Some(i);
            }
            i += size;
        }
        if let Some(st) = start {
            yield_(string::from_bytes(&b[st..]));
        }
    };
}

// go: sdk 1.25.5 strings/iter.go:112-141 FieldsFuncSeq
/// An iterator over substrings of `s` split around runs of code points
/// satisfying `f`. Yields the same strings [`super::FieldsFunc`] would
/// return, without building the slice.
pub fn FieldsFuncSeq<S: Into<string>, F: Fn(rune) -> bool + 'static>(
    s: S,
    f: F,
) -> impl crate::iter::Seq<string> {
    let s: string = s.into();
    return move |yield_: &mut dyn FnMut(string) -> bool| {
        let b = s.as_bytes();
        let mut start: Option<usize> = None;
        let mut i = 0usize;
        while i < b.len() {
            let mut size = 1usize;
            let mut r = crate::convert::rune(b[i]);
            if r >= crate::convert::rune(utf8::RuneSelf) {
                let (r2, s2) = utf8::DecodeRune(&b[i..]);
                r = r2;
                size = s2 as usize;
            }
            if f(r) {
                if let Some(st) = start {
                    if !yield_(string::from_bytes(&b[st..i])) {
                        return;
                    }
                    start = None;
                }
            } else if start.is_none() {
                start = Some(i);
            }
            i += size;
        }
        if let Some(st) = start {
            yield_(string::from_bytes(&b[st..]));
        }
    };
}
