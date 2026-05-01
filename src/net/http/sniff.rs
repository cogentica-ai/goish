// net/http/sniff — DetectContentType per https://mimesniff.spec.whatwg.org/.
//
// Line-by-line port of Go 1.25 src/net/http/sniff.go (304 LOC).
// Each match function annotated with the corresponding Go source line.

#![allow(non_snake_case)]
#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use crate::goslice::slice;
use crate::string;
use crate::types::byte;

/// Maximum number of bytes consulted by `DetectContentType`.
/// Mirrors Go's `sniffLen` (sniff.go:13).
const SNIFF_LEN: usize = 512;

/// `http.DetectContentType(data) -> string` (sniff.go:20).
///
/// WhatWG MIME sniffing algorithm, slim port. Returns
/// "application/octet-stream" if no signature matches.
pub fn DetectContentType(data: slice<byte>) -> string {
    // Go: if len(data) > sniffLen { data = data[:sniffLen] }
    let n = core::cmp::min(data.Len() as usize, SNIFF_LEN);
    let view: &[byte] = &(*data)[..n];

    // Go: index of the first non-whitespace byte.
    let mut first_non_ws: usize = 0;
    while first_non_ws < view.len() && is_ws(view[first_non_ws]) {
        first_non_ws += 1;
    }

    // Go: for _, sig := range sniffSignatures { … }
    if let Some(ct) = match_signatures(view, first_non_ws) {
        return string(ct);
    }
    string("application/octet-stream")
}

/// `isWS` (sniff.go:43) — whitespace per the WhatWG terminology.
fn is_ws(b: byte) -> bool {
    matches!(b, b'\t' | b'\n' | 0x0c | b'\r' | b' ')
}

/// `isTT` (sniff.go:52) — tag-terminating byte for HTML signatures.
fn is_tt(b: byte) -> bool {
    matches!(b, b' ' | b'>')
}

/// `exactSig.match` (sniff.go:202) — bytes::HasPrefix-style.
fn match_exact(data: &[byte], sig: &[byte]) -> bool {
    if data.len() < sig.len() {
        return false;
    }
    &data[..sig.len()] == sig
}

/// `maskedSig.match` (sniff.go:215) — masked prefix match. `data`
/// has already had `firstNonWS` accounted for if `skip_ws` is true.
fn match_masked(data: &[byte], pat: &[byte], mask: &[byte]) -> bool {
    if pat.len() != mask.len() || data.len() < pat.len() {
        return false;
    }
    for i in 0..pat.len() {
        if (data[i] & mask[i]) != pat[i] {
            return false;
        }
    }
    true
}

/// `htmlSig.match` (sniff.go:239) — case-insensitive prefix match
/// followed by a tag-terminating byte.
fn match_html(data: &[byte], sig: &[byte]) -> bool {
    if data.len() < sig.len() + 1 {
        return false;
    }
    for i in 0..sig.len() {
        let mut db = data[i];
        let b = sig[i];
        if (b'A'..=b'Z').contains(&b) {
            db &= 0xDF;
        }
        if b != db {
            return false;
        }
    }
    is_tt(data[sig.len()])
}

/// `mp4Sig.match` (sniff.go:265) — MP4 box-prefixed video.
fn match_mp4(data: &[byte]) -> bool {
    if data.len() < 12 {
        return false;
    }
    // Go: boxSize := binary.BigEndian.Uint32(data[:4])
    let box_size = (data[0] as usize) << 24
        | (data[1] as usize) << 16
        | (data[2] as usize) << 8
        | (data[3] as usize);
    if data.len() < box_size || box_size % 4 != 0 {
        return false;
    }
    if &data[4..8] != b"ftyp" {
        return false;
    }
    let mut st = 8;
    while st < box_size {
        if st == 12 {
            // Ignore "major brand" version bytes
            st += 4;
            continue;
        }
        if st + 3 <= data.len() && &data[st..st + 3] == b"mp4" {
            return true;
        }
        st += 4;
    }
    false
}

/// `textSig.match` (sniff.go:292) — plain-text fallback.
fn match_text(data: &[byte], first_non_ws: usize) -> bool {
    for &b in &data[first_non_ws..] {
        if b <= 0x08 || b == 0x0B || (0x0E..=0x1A).contains(&b) || (0x1C..=0x1F).contains(&b) {
            return false;
        }
    }
    true
}

/// Walk the table from sniff.go:66 and return the first match.
fn match_signatures(data: &[byte], first_non_ws: usize) -> Option<&'static str> {
    // Skip leading whitespace for HTML / "<?xml" matches (sniff.go:67-88).
    let trimmed = &data[first_non_ws..];

    // HTML signatures.
    let html_sigs: [&[byte]; 17] = [
        b"<!DOCTYPE HTML",
        b"<HTML",
        b"<HEAD",
        b"<SCRIPT",
        b"<IFRAME",
        b"<H1",
        b"<DIV",
        b"<FONT",
        b"<TABLE",
        b"<A",
        b"<STYLE",
        b"<TITLE",
        b"<B",
        b"<BODY",
        b"<BR",
        b"<P",
        b"<!--",
    ];
    for sig in html_sigs.iter() {
        if match_html(trimmed, sig) {
            return Some("text/html; charset=utf-8");
        }
    }

    // <?xml — masked, whitespace-skipping.
    if match_masked(trimmed, b"<?xml", b"\xFF\xFF\xFF\xFF\xFF") {
        return Some("text/xml; charset=utf-8");
    }

    // PDF / PostScript — exact prefix.
    if match_exact(data, b"%PDF-") {
        return Some("application/pdf");
    }
    if match_exact(data, b"%!PS-Adobe-") {
        return Some("application/postscript");
    }

    // UTF BOMs.
    if match_masked(data, b"\xFE\xFF\x00\x00", b"\xFF\xFF\x00\x00") {
        return Some("text/plain; charset=utf-16be");
    }
    if match_masked(data, b"\xFF\xFE\x00\x00", b"\xFF\xFF\x00\x00") {
        return Some("text/plain; charset=utf-16le");
    }
    if match_masked(data, b"\xEF\xBB\xBF\x00", b"\xFF\xFF\xFF\x00") {
        return Some("text/plain; charset=utf-8");
    }

    // Image types.
    if match_exact(data, b"\x00\x00\x01\x00") || match_exact(data, b"\x00\x00\x02\x00") {
        return Some("image/x-icon");
    }
    if match_exact(data, b"BM") {
        return Some("image/bmp");
    }
    if match_exact(data, b"GIF87a") || match_exact(data, b"GIF89a") {
        return Some("image/gif");
    }
    if match_masked(
        data,
        b"RIFF\x00\x00\x00\x00WEBPVP",
        b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF",
    ) {
        return Some("image/webp");
    }
    if match_exact(data, b"\x89PNG\x0D\x0A\x1A\x0A") {
        return Some("image/png");
    }
    if match_exact(data, b"\xFF\xD8\xFF") {
        return Some("image/jpeg");
    }

    // Audio / video.
    if match_masked(
        data,
        b"FORM\x00\x00\x00\x00AIFF",
        b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
    ) {
        return Some("audio/aiff");
    }
    if match_masked(data, b"ID3", b"\xFF\xFF\xFF") {
        return Some("audio/mpeg");
    }
    if match_masked(data, b"OggS\x00", b"\xFF\xFF\xFF\xFF\xFF") {
        return Some("application/ogg");
    }
    if match_masked(data, b"MThd\x00\x00\x00\x06", b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF") {
        return Some("audio/midi");
    }
    if match_masked(
        data,
        b"RIFF\x00\x00\x00\x00AVI ",
        b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
    ) {
        return Some("video/avi");
    }
    if match_masked(
        data,
        b"RIFF\x00\x00\x00\x00WAVE",
        b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
    ) {
        return Some("audio/wave");
    }
    if match_mp4(data) {
        return Some("video/mp4");
    }
    if match_exact(data, b"\x1A\x45\xDF\xA3") {
        return Some("video/webm");
    }

    // Fonts.
    if match_exact(data, b"\x00\x01\x00\x00") {
        return Some("font/ttf");
    }
    if match_exact(data, b"OTTO") {
        return Some("font/otf");
    }
    if match_exact(data, b"ttcf") {
        return Some("font/collection");
    }
    if match_exact(data, b"wOFF") {
        return Some("font/woff");
    }
    if match_exact(data, b"wOF2") {
        return Some("font/woff2");
    }

    // Archives.
    if match_exact(data, b"\x1F\x8B\x08") {
        return Some("application/x-gzip");
    }
    if match_exact(data, b"PK\x03\x04") {
        return Some("application/zip");
    }
    if match_exact(data, b"Rar!\x1A\x07\x00") || match_exact(data, b"Rar!\x1A\x07\x01\x00") {
        return Some("application/x-rar-compressed");
    }
    if match_exact(data, b"\x00\x61\x73\x6D") {
        return Some("application/wasm");
    }

    // textSig last.
    if match_text(data, first_non_ws) {
        return Some("text/plain; charset=utf-8");
    }

    None
}

// Suppress unused-import warnings for `Vec` in case future tweaks
// drop the local helper.
#[allow(dead_code)]
fn _unused() {
    let _: Vec<u8> = Vec::new();
}
