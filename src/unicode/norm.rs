// unicode/norm — Unicode normalization, ported from
// golang.org/x/text@v0.38.0 unicode/norm (the version typescript-go
// pins). Goish stays dependency-free, so this is a port, not a wrap.
//
// Scope: **NFD only** (canonical decomposition + canonical ordering,
// UAX #15). That is the only form typescript-go uses
// (ls/lsutil/organizeimports.go removeDiacritics: `norm.NFD.String(s)`
// then strip Mn). NFC/NFKC/NFKD need the composition/compatibility
// tables and are not declared until something needs them.
//
// Data: `norm_tables.rs` is generated from the real x/text v0.38.0 —
// for every code point, its full recursive canonical decomposition
// (norm.NFD.String on the single rune) and its canonical combining
// class (norm.NFD properties CCC). Hangul syllables (U+AC00..U+D7A3)
// decompose algorithmically per UAX #15 §3.12 and are not in the
// table. Regen: scratchpad xtext_ref/dumpnorm.go against the module
// cache, then the lang_tables/norm_tables generator script.
//
// Validation: exhaustive differential sweep vs real x/text — every
// code point singly, plus randomized combining sequences (reordering)
// and the typescript-go loc corpora; byte-exact (see the
// unicode_norm_smoke example for the embedded subset).

use crate::gostring::string;
use crate::goslice::slice;
use crate::types::byte;

use alloc::vec::Vec;

#[path = "norm_tables.rs"]
mod tables;

/// A Form denotes a canonical representation of Unicode code points.
/// Mirrors x/text unicode/norm.Form. Only NFD is ported.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Form(u8);

/// Canonical decomposition (UAX #15 Normalization Form D).
pub const NFD: Form = Form(1);

// Hangul decomposition constants (UAX #15 §3.12).
const HANGUL_BASE: u32 = 0xAC00;
const HANGUL_END: u32 = 0xD7A4; // exclusive
const JAMO_L_BASE: u32 = 0x1100;
const JAMO_V_BASE: u32 = 0x1161;
const JAMO_T_BASE: u32 = 0x11A7;
const JAMO_V_COUNT: u32 = 21;
const JAMO_T_COUNT: u32 = 28;

fn ccc(r: u32) -> u8 {
    match tables::CCC.binary_search_by_key(&r, |e| e.0) {
        Ok(i) => tables::CCC[i].1,
        Err(_) => 0,
    }
}

// Append the full canonical decomposition of `r` to `out` as
// (rune, ccc) pairs. Table entries are already fully recursive.
fn decompose_into(r: u32, out: &mut Vec<(u32, u8)>) {
    if (HANGUL_BASE..HANGUL_END).contains(&r) {
        let s = r - HANGUL_BASE;
        let l = JAMO_L_BASE + s / (JAMO_V_COUNT * JAMO_T_COUNT);
        let v = JAMO_V_BASE + (s % (JAMO_V_COUNT * JAMO_T_COUNT)) / JAMO_T_COUNT;
        let t = s % JAMO_T_COUNT;
        out.push((l, 0));
        out.push((v, 0));
        if t > 0 {
            out.push((JAMO_T_BASE + t, 0));
        }
        return;
    }
    match tables::DECOMP.binary_search_by_key(&r, |e| e.0) {
        Ok(i) => {
            for &d in tables::DECOMP[i].1 {
                out.push((d, ccc(d)));
            }
        }
        Err(_) => out.push((r, ccc(r))),
    }
}

// The Canonical Ordering Algorithm (UAX #15 §3.11 D109): within every
// maximal run of characters with nonzero CCC, stable-sort by CCC.
// Runs are tiny in practice; insertion sort keeps it allocation-free.
fn canonical_reorder(seq: &mut [(u32, u8)]) {
    let mut i = 1;
    while i < seq.len() {
        if seq[i].1 != 0 && seq[i - 1].1 > seq[i].1 {
            let mut j = i;
            while j > 0 && seq[j - 1].1 > seq[j].1 && seq[j].1 != 0 {
                seq.swap(j - 1, j);
                j -= 1;
            }
        }
        i += 1;
    }
}

fn nfd_bytes(src: &[u8]) -> Vec<u8> {
    let mut seq: Vec<(u32, u8)> = Vec::with_capacity(src.len());
    // Decode UTF-8 the Go way: invalid bytes become U+FFFD.
    let mut i = 0;
    while i < src.len() {
        let (r, size) = crate::unicode::utf8::DecodeRune(&src[i..]);
        decompose_into(r as u32, &mut seq);
        i += size as usize;
    }
    canonical_reorder(&mut seq);
    let mut out: Vec<u8> = Vec::with_capacity(seq.len() * 2);
    let mut buf = [0u8; 4];
    for &(r, _) in &seq {
        let c = char::from_u32(r).unwrap_or('\u{FFFD}');
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    }
    out
}

impl Form {
    /// String returns f(s) — the normalized form of s.
    pub fn String<S: Into<string>>(&self, s: S) -> string {
        let s = s.into();
        string::from_bytes(&nfd_bytes(s.as_bytes()))
    }

    /// Bytes returns f(b) — the normalized form of b.
    pub fn Bytes<B: AsRef<[byte]>>(&self, b: B) -> slice<byte> {
        slice::__from_vec(nfd_bytes(b.as_ref()))
    }
}
