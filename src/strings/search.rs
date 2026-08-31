// go: file strings/search.go decls: makeStringFinder, longestCommonSuffix, stringFinder.next
//
// strings/search.go — the Boyer-Moore string finder.
//
// Two skip tables, both precomputed from the pattern alone:
//
//   * `badCharSkip[b]` is the distance from the last byte of the
//     pattern to the rightmost occurrence of `b` in it, or the whole
//     pattern length when `b` does not occur. A mismatch on `b` can
//     shift the frame at least that far before `b` could line up again.
//   * `goodSuffixSkip[i]` is how far to shift given that
//     `pattern[i+1:]` matched but `pattern[i]` did not — either to the
//     next occurrence of that suffix inside the pattern, or, when there
//     is none, to align the pattern's own prefix with the tail of the
//     matched suffix.
//
// Go's own worked examples: "mississi" has the suffix "issi" occurring
// again (right to left) at index 1, so `goodSuffixSkip[3]` is 3+4 = 7;
// "abcxxxabc" mismatching at 3 leaves the suffix "xxabc", which occurs
// nowhere else, but its rightmost "abc" is a prefix of the pattern, so
// `goodSuffixSkip[3]` is 6+5 = 11.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::convert::int as toint;
use crate::gostring::string;
use crate::types::int;

// go: sdk 1.25.5 strings/search.go:7-45 stringFinder
/// Finds strings in a source text using Boyer-Moore.
///
/// Go's `pattern` is a `string` view into the caller's argument; goish
/// keeps the bytes, since a `string` here would cost a lookup on every
/// comparison in the inner loop.
#[derive(Clone)]
pub(crate) struct stringFinder {
    // Go: pattern string — the string being searched for.
    pattern: Vec<u8>,
    // Go: badCharSkip [256]int
    badCharSkip: [int; 256],
    // Go: goodSuffixSkip []int
    goodSuffixSkip: Vec<int>,
}

// go: sdk 1.25.5 strings/search.go:48-89 makeStringFinder
pub(crate) fn makeStringFinder<S: Into<string>>(pattern: S) -> stringFinder {
    let pattern: string = pattern.into();
    let p: Vec<u8> = pattern.as_bytes().to_vec();
    let mut f = stringFinder {
        badCharSkip: [0; 256],
        goodSuffixSkip: alloc::vec![0; p.len()],
        pattern: p,
    };
    let pat = f.pattern.clone();
    // `last` is the index of the last character in the pattern.
    let last: int = toint(pat.len()) - 1;

    // Build the bad-character table. Bytes not in the pattern can skip
    // one pattern's length.
    let mut i = 0usize;
    while i < 256 {
        f.badCharSkip[i] = toint(pat.len());
        i += 1;
    }
    // The loop condition is `<` rather than `<=` so the last byte does
    // not have a zero distance to itself: finding that byte out of
    // place implies it is not in the last position.
    let mut i: int = 0;
    while i < last {
        f.badCharSkip[pat[i as usize] as usize] = last - i;
        i += 1;
    }

    // Build the good-suffix table. First pass: set each value to the
    // next index which starts a prefix of the pattern.
    let mut lastPrefix = last;
    let mut i = last;
    while i >= 0 {
        if hasPrefixBytes(&pat, &pat[(i + 1) as usize..]) {
            lastPrefix = i + 1;
        }
        // lastPrefix is the shift, and (last-i) is len(suffix).
        f.goodSuffixSkip[i as usize] = lastPrefix + last - i;
        i -= 1;
    }
    // Second pass: find repeats of the pattern's suffix starting from
    // the front.
    let mut i: int = 0;
    while i < last {
        let lenSuffix = longestCommonSuffix(&pat, &pat[1..(i + 1) as usize]);
        if pat[(i - lenSuffix) as usize] != pat[(last - lenSuffix) as usize] {
            // (last-i) is the shift, and lenSuffix is len(suffix).
            f.goodSuffixSkip[(last - lenSuffix) as usize] = lenSuffix + last - i;
        }
        i += 1;
    }

    return f;
}

// go: none — goish idiom: Go calls the package's own `HasPrefix`, which
//     takes two `string`s. Both arguments here are subslices of one
//     pattern, so goish compares the bytes directly rather than
//     rebuilding two `string` handles inside the table-building loop.
fn hasPrefixBytes(s: &[u8], prefix: &[u8]) -> bool {
    return s.len() >= prefix.len() && &s[..prefix.len()] == prefix;
}

// go: sdk 1.25.5 strings/search.go:91-98 longestCommonSuffix
// goishlint:ignore GOISH014 — the anchor names Go's
//     `longestCommonSuffix`; the Rust fn takes byte slices, because
//     both of its callers pass subslices of one pattern. The loop is
//     Go's, byte for byte.
fn longestCommonSuffix(a: &[u8], b: &[u8]) -> int {
    let mut i: usize = 0;
    while i < a.len() && i < b.len() {
        if a[a.len() - 1 - i] != b[b.len() - 1 - i] {
            break;
        }
        i += 1;
    }
    return toint(i);
}

impl stringFinder {
    // go: none — goish idiom: `singleStringReplacer` reads
    //     `r.finder.pattern` directly, being in the same Go package.
    //     goish's `pattern` is a private `Vec<u8>` in another module,
    //     so its length is exposed rather than the bytes.
    pub(crate) fn patternLen(&self) -> usize {
        return self.pattern.len();
    }

    // go: sdk 1.25.5 strings/search.go:102-117 stringFinder.next
    /// The index in `text` of the first occurrence of the pattern, or
    /// -1 when it does not occur.
    pub(crate) fn next(&self, text: &[u8]) -> int {
        let plen = toint(self.pattern.len());
        let mut i: int = plen - 1;
        while i < toint(text.len()) {
            // Compare backwards from the end until the first
            // unmatching character.
            let mut j: int = plen - 1;
            while j >= 0 && text[i as usize] == self.pattern[j as usize] {
                i -= 1;
                j -= 1;
            }
            if j < 0 {
                // Match.
                return i + 1;
            }
            let bad = self.badCharSkip[text[i as usize] as usize];
            let good = self.goodSuffixSkip[j as usize];
            i += if bad > good { bad } else { good };
        }
        return -1;
    }
}
