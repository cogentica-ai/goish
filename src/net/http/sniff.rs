// go: package net/http
//
// go: file net/http/sniff.go decls: DetectContentType, isWS, isTT, exactSig.match, maskedSig.match, htmlSig.match, mp4Sig.match, textSig.match
//
// Go: "DetectContentType implements the algorithm described at
// https://mimesniff.spec.whatwg.org/ to determine the Content-Type of
// the given data."
//
// The previous port flattened Go's `sniffSignatures` table of sniffSig
// values into a hand-written if-chain. That reads fine and it was very
// nearly right — but a table you cannot line up against Go's is a table
// whose entries can go missing without anyone noticing, and one had:
// the 34-NULL-bytes-then-"LP" signature for
// application/vnd.ms-fontobject was absent, so an embedded OpenType
// font sniffed as application/octet-stream. The table is a table again.
//
// `match` is a Rust keyword, hence `r#match`; it is Go's method name.

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, int};

// go: sdk 1.25.5 net/http/sniff.go:13-13 sniffLen
/// Go: "The algorithm uses at most sniffLen bytes to make its
/// decision."
const sniffLen: int = 512;

// go: sdk 1.25.5 net/http/sniff.go:21-38 DetectContentType
/// Go: "DetectContentType implements the algorithm described at
/// https://mimesniff.spec.whatwg.org/ to determine the Content-Type of
/// the given data. It considers at most the first 512 bytes of data.
/// DetectContentType always returns a valid MIME type: if it cannot
/// determine a more specific one, it returns
/// "application/octet-stream"."
pub fn DetectContentType(data: slice<byte>) -> string {
    let mut n = data.Len();
    if n > sniffLen {
        n = sniffLen;
    }
    let data: &[byte] = &(*data)[..crate::builtin::__make_size(n)];

    // Go: "Index of the first non-whitespace byte in data."
    let mut firstNonWS: int = 0;
    while firstNonWS < crate::int(data.len()) && isWS(data[crate::builtin::__make_size(firstNonWS)])
    {
        firstNonWS += 1;
    }

    for sig in sniffSignatures.iter() {
        let ct = sig.r#match(data, firstNonWS);
        if !ct.is_empty() {
            return string::from_static(ct);
        }
    }

    // fallback
    return string::from_static("application/octet-stream");
}

// go: sdk 1.25.5 net/http/sniff.go:42-48 isWS
/// Go: "isWS reports whether the provided byte is a whitespace byte
/// (0xWS) as defined in https://mimesniff.spec.whatwg.org/#terminology."
fn isWS(b: byte) -> bool {
    return matches!(b, b'\t' | b'\n' | 0x0c | b'\r' | b' ');
}

// go: sdk 1.25.5 net/http/sniff.go:52-58 isTT
/// Go: "isTT reports whether the provided byte is a tag-terminating
/// byte (0xTT) as defined in
/// https://mimesniff.spec.whatwg.org/#terminology."
fn isTT(b: byte) -> bool {
    return matches!(b, b' ' | b'>');
}

// go: sdk 1.25.5 net/http/sniff.go:60-63 sniffSig
trait sniffSig: Sync {
    /// Go: "match returns the MIME type of the data, or "" if unknown."
    fn r#match(&self, data: &[byte], firstNonWS: int) -> &'static str;
}

// ─── the signature types ────────────────────────────────────────────

// go: sdk 1.25.5 net/http/sniff.go:197-200 exactSig
struct exactSig {
    sig: &'static [byte],
    ct: &'static str,
}

impl sniffSig for exactSig {
    // go: sdk 1.25.5 net/http/sniff.go:202-207 exactSig.match
    fn r#match(&self, data: &[byte], _firstNonWS: int) -> &'static str {
        if data.len() >= self.sig.len() && &data[..self.sig.len()] == self.sig {
            return self.ct;
        }
        return "";
    }
}

// go: sdk 1.25.5 net/http/sniff.go:209-213 maskedSig
struct maskedSig {
    mask: &'static [byte],
    pat: &'static [byte],
    skipWS: bool,
    ct: &'static str,
}

impl sniffSig for maskedSig {
    // go: sdk 1.25.5 net/http/sniff.go:215-235 maskedSig.match
    /// Go: "pattern matching algorithm section 6
    /// https://mimesniff.spec.whatwg.org/#pattern-matching-algorithm"
    fn r#match(&self, data: &[byte], firstNonWS: int) -> &'static str {
        let data = if self.skipWS {
            &data[crate::builtin::__make_size(firstNonWS)..]
        } else {
            data
        };
        if self.pat.len() != self.mask.len() {
            return "";
        }
        if data.len() < self.pat.len() {
            return "";
        }
        for (i, pb) in self.pat.iter().enumerate() {
            let maskedData = data[i] & self.mask[i];
            if maskedData != *pb {
                return "";
            }
        }
        return self.ct;
    }
}

// go: sdk 1.25.5 net/http/sniff.go:237-237 htmlSig
struct htmlSig(&'static [byte]);

impl sniffSig for htmlSig {
    // go: sdk 1.25.5 net/http/sniff.go:239-258 htmlSig.match
    fn r#match(&self, data: &[byte], firstNonWS: int) -> &'static str {
        let data = &data[crate::builtin::__make_size(firstNonWS)..];
        let h = self.0;
        if data.len() < h.len() + 1 {
            return "";
        }
        for (i, b) in h.iter().enumerate() {
            let mut db = data[i];
            if b'A' <= *b && *b <= b'Z' {
                db &= 0xDF;
            }
            if *b != db {
                return "";
            }
        }
        // Go: "Next byte must be a tag-terminating byte(0xTT)."
        if !isTT(data[h.len()]) {
            return "";
        }
        return "text/html; charset=utf-8";
    }
}

// go: sdk 1.25.5 net/http/sniff.go:260-260 mp4ftype
static mp4ftype: &[byte] = b"ftyp";
// go: sdk 1.25.5 net/http/sniff.go:261-261 mp4
static mp4: &[byte] = b"mp4";

// go: sdk 1.25.5 net/http/sniff.go:263-263 mp4Sig
struct mp4Sig;

impl sniffSig for mp4Sig {
    // go: sdk 1.25.5 net/http/sniff.go:265-288 mp4Sig.match
    /// Go: "https://mimesniff.spec.whatwg.org/#signature-for-mp4, c.f.
    /// section 6.2.1"
    fn r#match(&self, data: &[byte], _firstNonWS: int) -> &'static str {
        if data.len() < 12 {
            return "";
        }
        // Go: boxSize := int(binary.BigEndian.Uint32(data[:4]))
        let boxSize = crate::int(crate::encoding::binary::BigEndian.Uint32(&data[..4]));
        if crate::int(data.len()) < boxSize || boxSize % 4 != 0 {
            return "";
        }
        if &data[4..8] != mp4ftype {
            return "";
        }
        let mut st: int = 8;
        while st < boxSize {
            if st == 12 {
                // Go: "Ignores the four bytes that correspond to the
                // version number of the "major brand"."
                st += 4;
                continue;
            }
            // boxSize is a multiple of 4 and st <= boxSize-4, so
            // st+3 < boxSize <= len(data); Go indexes unguarded here
            // for the same reason.
            let s = crate::builtin::__make_size(st);
            if &data[s..s + 3] == mp4 {
                return "video/mp4";
            }
            st += 4;
        }
        return "";
    }
}

// go: sdk 1.25.5 net/http/sniff.go:290-290 textSig
struct textSig;

impl sniffSig for textSig {
    // go: sdk 1.25.5 net/http/sniff.go:292-304 textSig.match
    /// Go: "c.f. section 5, step 4."
    fn r#match(&self, data: &[byte], firstNonWS: int) -> &'static str {
        for b in data[crate::builtin::__make_size(firstNonWS)..].iter() {
            let b = *b;
            if b <= 0x08 || b == 0x0B || (0x0E <= b && b <= 0x1A) || (0x1C <= b && b <= 0x1F) {
                return "";
            }
        }
        return "text/plain; charset=utf-8";
    }
}

// ─── the table ──────────────────────────────────────────────────────

/// Go: "34 NULL bytes followed by the string "LP"".
static eotPat: &[byte] =
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00LP";
/// Go: "34 NULL bytes followed by \xF\xF".
static eotMask: &[byte] =
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF";

// go: sdk 1.25.5 net/http/sniff.go:66-195 sniffSignatures
/// Go: "Data matching the table in section 6."
///
/// Order is load-bearing twice over: the audio/video block carries a
/// comment in Go saying so, and textSig must stay last because it
/// matches almost anything printable.
static sniffSignatures: &[&dyn sniffSig] = &[
    &htmlSig(b"<!DOCTYPE HTML"),
    &htmlSig(b"<HTML"),
    &htmlSig(b"<HEAD"),
    &htmlSig(b"<SCRIPT"),
    &htmlSig(b"<IFRAME"),
    &htmlSig(b"<H1"),
    &htmlSig(b"<DIV"),
    &htmlSig(b"<FONT"),
    &htmlSig(b"<TABLE"),
    &htmlSig(b"<A"),
    &htmlSig(b"<STYLE"),
    &htmlSig(b"<TITLE"),
    &htmlSig(b"<B"),
    &htmlSig(b"<BODY"),
    &htmlSig(b"<BR"),
    &htmlSig(b"<P"),
    &htmlSig(b"<!--"),
    &maskedSig {
        mask: b"\xFF\xFF\xFF\xFF\xFF",
        pat: b"<?xml",
        skipWS: true,
        ct: "text/xml; charset=utf-8",
    },
    &exactSig { sig: b"%PDF-", ct: "application/pdf" },
    &exactSig { sig: b"%!PS-Adobe-", ct: "application/postscript" },
    // UTF BOMs.
    &maskedSig {
        mask: b"\xFF\xFF\x00\x00",
        pat: b"\xFE\xFF\x00\x00",
        skipWS: false,
        ct: "text/plain; charset=utf-16be",
    },
    &maskedSig {
        mask: b"\xFF\xFF\x00\x00",
        pat: b"\xFF\xFE\x00\x00",
        skipWS: false,
        ct: "text/plain; charset=utf-16le",
    },
    &maskedSig {
        mask: b"\xFF\xFF\xFF\x00",
        pat: b"\xEF\xBB\xBF\x00",
        skipWS: false,
        ct: "text/plain; charset=utf-8",
    },
    // Image types.
    //
    // Go: "For posterity, we originally returned
    // "image/vnd.microsoft.icon" ... but that has since been replaced
    // with "image/x-icon" in Section 6.2 of
    // https://mimesniff.spec.whatwg.org/#matching-an-image-type-pattern"
    &exactSig { sig: b"\x00\x00\x01\x00", ct: "image/x-icon" },
    &exactSig { sig: b"\x00\x00\x02\x00", ct: "image/x-icon" },
    &exactSig { sig: b"BM", ct: "image/bmp" },
    &exactSig { sig: b"GIF87a", ct: "image/gif" },
    &exactSig { sig: b"GIF89a", ct: "image/gif" },
    &maskedSig {
        mask: b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF",
        pat: b"RIFF\x00\x00\x00\x00WEBPVP",
        skipWS: false,
        ct: "image/webp",
    },
    &exactSig { sig: b"\x89PNG\x0D\x0A\x1A\x0A", ct: "image/png" },
    &exactSig { sig: b"\xFF\xD8\xFF", ct: "image/jpeg" },
    // Audio and Video types.
    //
    // Go: "Enforce the pattern match ordering as prescribed in
    // https://mimesniff.spec.whatwg.org/#matching-an-audio-or-video-type-pattern"
    &maskedSig {
        mask: b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
        pat: b"FORM\x00\x00\x00\x00AIFF",
        skipWS: false,
        ct: "audio/aiff",
    },
    &maskedSig { mask: b"\xFF\xFF\xFF", pat: b"ID3", skipWS: false, ct: "audio/mpeg" },
    &maskedSig {
        mask: b"\xFF\xFF\xFF\xFF\xFF",
        pat: b"OggS\x00",
        skipWS: false,
        ct: "application/ogg",
    },
    &maskedSig {
        mask: b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
        pat: b"MThd\x00\x00\x00\x06",
        skipWS: false,
        ct: "audio/midi",
    },
    &maskedSig {
        mask: b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
        pat: b"RIFF\x00\x00\x00\x00AVI ",
        skipWS: false,
        ct: "video/avi",
    },
    &maskedSig {
        mask: b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
        pat: b"RIFF\x00\x00\x00\x00WAVE",
        skipWS: false,
        ct: "audio/wave",
    },
    // 6.2.0.2. video/mp4
    &mp4Sig,
    // 6.2.0.3. video/webm
    &exactSig { sig: b"\x1A\x45\xDF\xA3", ct: "video/webm" },
    // Font types.
    &maskedSig {
        pat: eotPat,
        mask: eotMask,
        skipWS: false,
        ct: "application/vnd.ms-fontobject",
    },
    &exactSig { sig: b"\x00\x01\x00\x00", ct: "font/ttf" },
    &exactSig { sig: b"OTTO", ct: "font/otf" },
    &exactSig { sig: b"ttcf", ct: "font/collection" },
    &exactSig { sig: b"wOFF", ct: "font/woff" },
    &exactSig { sig: b"wOF2", ct: "font/woff2" },
    // Archive types.
    &exactSig { sig: b"\x1F\x8B\x08", ct: "application/x-gzip" },
    &exactSig { sig: b"PK\x03\x04", ct: "application/zip" },
    // Go: "RAR's signatures are incorrectly defined by the MIME spec as
    // per https://github.com/whatwg/mimesniff/issues/63. However, RAR
    // Labs correctly defines it at
    // https://www.rarlab.com/technote.htm#rarsign, so we use the
    // definition from RAR Labs."
    &exactSig { sig: b"Rar!\x1A\x07\x00", ct: "application/x-rar-compressed" }, // RAR v1.5-v4.0
    &exactSig { sig: b"Rar!\x1A\x07\x01\x00", ct: "application/x-rar-compressed" }, // RAR v5+
    &exactSig { sig: b"\x00\x61\x73\x6D", ct: "application/wasm" },
    &textSig, // should be last
];
