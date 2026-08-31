// go: file bytes/iter.go decls: Lines, splitSeq, SplitSeq, SplitAfterSeq, FieldsSeq, FieldsFuncSeq
//
// bytes/iter.go — the `iter.Seq[[]byte]` returning splitters.
//
// Each one yields the same subslices its slice-building twin would
// return, without building the outer slice. Go writes them as a closure
// over `yield func([]byte) bool`, and a `false` from `yield` stops the
// walk; goish's `iter::Seq` is the same closure shape.
//
// Go full-slices every yielded fragment — `s[:i:i]`, capping capacity
// at length — so a caller who appends to a yielded line cannot write
// into the bytes of the next one. A goish `slice<byte>` handed out of
// here already owns its bytes, so the aliasing that three-index slicing
// defends against cannot arise; the values yielded are identical.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use crate::goslice::slice;
use crate::types::{byte, rune};
use crate::unicode::utf8;

// go: sdk 1.25.5 bytes/iter.go:12-31 Lines
/// An iterator over the newline-terminated lines in `s`, each yielded
/// line including its terminating newline. An empty `s` yields no lines
/// at all, and a final line without a newline is yielded without one.
pub fn Lines<S: Into<slice<byte>>>(s: S) -> impl crate::iter::Seq<slice<byte>> {
    let s: slice<byte> = s.into();
    return move |yield_: &mut dyn FnMut(slice<byte>) -> bool| {
        let b: &[byte] = &s;
        let mut pos = 0usize;
        while pos < b.len() {
            let i = super::bytes_go::indexBytePortable(&b[pos..], b'\n');
            let end = if i >= 0 {
                pos + (i as usize) + 1
            } else {
                b.len()
            };
            if !yield_(slice::__from_vec(b[pos..end].to_vec())) {
                return;
            }
            pos = end;
        }
    };
}

// go: sdk 1.25.5 bytes/iter.go:36-61 splitSeq
// goishlint:ignore GOISH014 — the anchor names Go's `splitSeq`; the
//     Rust fn is `split_seq` because `SplitSeq` already takes the
//     camel-case name and Rust is case-sensitive where Go's export
//     rule made the two distinct.
/// `SplitSeq` or `SplitAfterSeq`, configured by how many bytes of `sep`
/// to include in the results — none, or all of them.
fn split_seq(
    s: slice<byte>,
    sep: slice<byte>,
    sepSave: usize,
) -> impl crate::iter::Seq<slice<byte>> {
    return move |yield_: &mut dyn FnMut(slice<byte>) -> bool| {
        let b: &[byte] = &s;
        let sepb: &[byte] = &sep;
        if sepb.is_empty() {
            // Go: split into UTF-8 sequences, as Split(s, nil) does.
            let mut pos = 0usize;
            while pos < b.len() {
                let (_, size) = utf8::DecodeRune(&b[pos..]);
                let size = size as usize;
                if !yield_(slice::__from_vec(b[pos..pos + size].to_vec())) {
                    return;
                }
                pos += size;
            }
            return;
        }
        let mut pos = 0usize;
        loop {
            let i = super::bytes_go::index_bytes(&b[pos..], sepb);
            if i < 0 {
                break;
            }
            let i = i as usize;
            if !yield_(slice::__from_vec(b[pos..pos + i + sepSave].to_vec())) {
                return;
            }
            pos += i + sepb.len();
        }
        yield_(slice::__from_vec(b[pos..].to_vec()));
    };
}

// go: sdk 1.25.5 bytes/iter.go:67-69 SplitSeq
/// An iterator over all subslices of `s` separated by `sep`. Yields the
/// same subslices [`super::Split`] would return, without building the
/// outer slice.
pub fn SplitSeq<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(
    s: S1,
    sep: S2,
) -> impl crate::iter::Seq<slice<byte>> {
    return split_seq(s.into(), sep.into(), 0);
}

// go: sdk 1.25.5 bytes/iter.go:75-77 SplitAfterSeq
/// An iterator over subslices of `s` split *after* each instance of
/// `sep`. Yields the same subslices [`super::SplitAfter`] would return.
pub fn SplitAfterSeq<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(
    s: S1,
    sep: S2,
) -> impl crate::iter::Seq<slice<byte>> {
    let sep: slice<byte> = sep.into();
    let save = sep.Len() as usize;
    return split_seq(s.into(), sep, save);
}

// go: sdk 1.25.5 bytes/iter.go:83-110 FieldsSeq
/// An iterator over subslices of `s` split around runs of whitespace,
/// as defined by `unicode.IsSpace`. Yields the same subslices
/// [`super::Fields`] would return.
pub fn FieldsSeq<S: Into<slice<byte>>>(s: S) -> impl crate::iter::Seq<slice<byte>> {
    let s: slice<byte> = s.into();
    return move |yield_: &mut dyn FnMut(slice<byte>) -> bool| {
        let b: &[byte] = &s;
        // Go uses -1 for "not in a field"; goish uses None, since a byte
        // offset is a usize here.
        let mut start: Option<usize> = None;
        let mut i = 0usize;
        while i < b.len() {
            let mut size = 1usize;
            let mut r = crate::convert::rune(b[i]);
            let mut isSpace = super::bytes_go::is_ascii_space(b[i]);
            if r >= crate::convert::rune(utf8::RuneSelf) {
                let (r2, s2) = utf8::DecodeRune(&b[i..]);
                r = r2;
                size = s2 as usize;
                isSpace = crate::unicode::IsSpace(r);
            }
            if isSpace {
                if let Some(st) = start {
                    if !yield_(slice::__from_vec(b[st..i].to_vec())) {
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
            yield_(slice::__from_vec(b[st..].to_vec()));
        }
    };
}

// go: sdk 1.25.5 bytes/iter.go:116-141 FieldsFuncSeq
/// An iterator over subslices of `s` split around runs of code points
/// satisfying `f`. Yields the same subslices [`super::FieldsFunc`]
/// would return.
pub fn FieldsFuncSeq<S: Into<slice<byte>>, F: Fn(rune) -> bool + 'static>(
    s: S,
    f: F,
) -> impl crate::iter::Seq<slice<byte>> {
    let s: slice<byte> = s.into();
    return move |yield_: &mut dyn FnMut(slice<byte>) -> bool| {
        let b: &[byte] = &s;
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
                    if !yield_(slice::__from_vec(b[st..i].to_vec())) {
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
            yield_(slice::__from_vec(b[st..].to_vec()));
        }
    };
}
