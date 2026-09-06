// html — HTML escape / unescape.
//
// Reference: html/escape.go (214 LOC).
//
// The full HTML5 named-entity table now ships, in entity.rs, generated
// from Go's own entity.go rather than transcribed.
//
// Slim deviations from upstream (documented):
//
//   * Full HTML5 named-entity table (2261 LOC of static data in
//     html/entity.go) is NOT shipped. `UnescapeString`
//     recognises only the five standard entities — `&amp;`, `&lt;`,
//     `&gt;`, `&quot;`, `&apos;` (the inverse of `EscapeString`) —
//     plus all numeric character references (`&#NN;` and `&#xNN;`),
//     including the Windows-1252 replacement table. This covers the
//     output of `EscapeString` as well as the typical decimal /
//     hexadecimal numeric-ref forms emitted by other HTML escapers.
//     The full named-entity set (`&aacute;`, `&copy;`, …) can be
//     wired in later by porting `entity.go` verbatim.
//
//   * `EscapeString` mirrors Go exactly via `strings::NewReplacer`
//     with the same five entries. `'` becomes `&#39;` (shorter than
//     `&apos;`); `"` becomes `&#34;` (shorter than `&quot;`).
//     Round-trip with `UnescapeString` is preserved because the
//     numeric-ref decoder is unconditional.
//
//   * `unescapeEntity` is a free function operating on `&mut [byte]`
//     scratch — same shape as Go's, but with goish `int` cursors.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

mod entity;

extern crate alloc;

use alloc::vec::Vec;

use crate::goslice::slice;
use crate::gostring::string;
use crate::strings;
use crate::types::{byte, int, rune};
use crate::unicode::utf8;

// Go: escape.go:14 — `var replacementTable = [...]rune{...}`. 32-entry
// table for Windows-1252 → Unicode legacy mapping when a numeric
// character reference falls in 0x80..=0x9F.
const replacementTable: [rune; 32] = [
    '\u{20AC}' as rune, // 0x80
    '\u{0081}' as rune,
    '\u{201A}' as rune,
    '\u{0192}' as rune,
    '\u{201E}' as rune,
    '\u{2026}' as rune,
    '\u{2020}' as rune,
    '\u{2021}' as rune,
    '\u{02C6}' as rune,
    '\u{2030}' as rune,
    '\u{0160}' as rune,
    '\u{2039}' as rune,
    '\u{0152}' as rune,
    '\u{008D}' as rune,
    '\u{017D}' as rune,
    '\u{008F}' as rune,
    '\u{0090}' as rune,
    '\u{2018}' as rune,
    '\u{2019}' as rune,
    '\u{201C}' as rune,
    '\u{201D}' as rune,
    '\u{2022}' as rune,
    '\u{2013}' as rune,
    '\u{2014}' as rune,
    '\u{02DC}' as rune,
    '\u{2122}' as rune,
    '\u{0161}' as rune,
    '\u{203A}' as rune,
    '\u{0153}' as rune,
    '\u{009D}' as rune,
    '\u{017E}' as rune,
    '\u{0178}' as rune, // 0x9F
];

/// Slim 5-entry named-entity lookup. Returns 0 on miss.
///
/// Goish deviation: only the inverse of `EscapeString`. The full
/// HTML5 table from `entity.go` can replace this later.
// go: none — goish idiom: Go looks the name up in a `map[string]rune`;
//     goish's table is a sorted static array, so the lookup is a binary
//     search over it. Same table, same answers.
fn entity_lookup(name: &[byte]) -> rune {
    let key = match core::str::from_utf8(name) {
        Ok(k) => k,
        // A name is ASCII by construction — the scanner only accepts
        // letters, digits and a trailing ';' — so this cannot happen,
        // and "no match" is the right answer if it somehow does.
        Err(_) => return 0,
    };
    return match entity::entity.binary_search_by(|probe| probe.0.cmp(key)) {
        Ok(i) => entity::entity[i].1,
        Err(_) => 0,
    };
}

// go: none — goish idiom: as `entity_lookup`, for the names that expand
//     to TWO runes.
fn entity2_lookup(name: &[byte]) -> Option<(rune, rune)> {
    let key = match core::str::from_utf8(name) {
        Ok(k) => k,
        Err(_) => return None,
    };
    return match entity::entity2.binary_search_by(|probe| probe.0.cmp(key)) {
        Ok(i) => Some((entity::entity2[i].1, entity::entity2[i].2)),
        Err(_) => None,
    };
}

// Go: escape.go:56
//   func unescapeEntity(b []byte, dst, src int, entity map[string]rune,
//                       entity2 map[string][2]rune) (dst1, src1 int) {
//       const attribute = false
//       i, s := 1, b[src:]
//       if len(s) <= 1 { ... }
//       if s[i] == '#' { ... numeric ref ... }
//       ... named entity ...
//   }
//
// Goish slim: drops the `entity2` map (two-codepoint entities are
// only in the full HTML5 table) and uses `entity_lookup` for the
// five standard names.
fn unescapeEntity(b: &mut Vec<byte>, dst: int, src: int) -> (int, int) {
    // Go: escape.go:62 — i, s := 1, b[src:]
    //   We work directly on indices into b.
    let blen = b.len() as int;
    // Length of s == blen - src.
    let s_len = blen - src;

    // Go: escape.go:64 — if len(s) <= 1 { b[dst] = b[src]; return dst+1, src+1 }
    if s_len <= 1 {
        b[dst as usize] = b[src as usize];
        return (dst + 1, src + 1);
    }

    // Go: escape.go:69 — if s[i] == '#' { ... }
    if b[(src + 1) as usize] == b'#' {
        // Go: escape.go:70 — if len(s) <= 3 { ... }
        if s_len <= 3 {
            b[dst as usize] = b[src as usize];
            return (dst + 1, src + 1);
        }
        // Go: escape.go:74 — i++; c := s[i]; hex := false; if c=='x' || c=='X' { hex=true; i++ }
        let mut i: int = 2; // points at first char after '&#'
        let mut c = b[(src + i) as usize];
        let mut hex = false;
        if c == b'x' || c == b'X' {
            hex = true;
            i += 1;
        }

        // Go: escape.go:82
        //   x := '\x00'
        //   for i < len(s) { c = s[i]; i++; ... }
        let mut x: rune = 0;
        while i < s_len {
            c = b[(src + i) as usize];
            i += 1;
            if hex {
                if c >= b'0' && c <= b'9' {
                    x = 16 * x + (c as rune) - ('0' as rune);
                    continue;
                } else if c >= b'a' && c <= b'f' {
                    x = 16 * x + (c as rune) - ('a' as rune) + 10;
                    continue;
                } else if c >= b'A' && c <= b'F' {
                    x = 16 * x + (c as rune) - ('A' as rune) + 10;
                    continue;
                }
            } else if c >= b'0' && c <= b'9' {
                x = 10 * x + (c as rune) - ('0' as rune);
                continue;
            }
            // Go: escape.go:101 — if c != ';' { i-- }; break
            if c != b';' {
                i -= 1;
            }
            break;
        }

        // Go: escape.go:107 — if i <= 3 { no chars matched, treat literally }
        if i <= 3 {
            b[dst as usize] = b[src as usize];
            return (dst + 1, src + 1);
        }

        // Go: escape.go:112 — Windows-1252 replacement.
        if x >= 0x80 && x <= 0x9F {
            x = replacementTable[(x - 0x80) as usize];
        } else if x == 0 || (x >= 0xD800 && x <= 0xDFFF) || x > 0x10FFFF {
            // Go: escape.go:115 — Replace invalid characters with U+FFFD.
            x = '\u{FFFD}' as rune;
        }

        // Go: escape.go:120 — return dst+utf8.EncodeRune(b[dst:], x), src+i
        let mut tmp = [0u8; 4];
        let n = utf8::EncodeRune(&mut tmp, x) as usize;
        for k in 0..n {
            b[dst as usize + k] = tmp[k];
        }
        return (dst + n as int, src + i);
    }

    // ─── Named-entity branch ─────────────────────────────────────────
    //
    // Go: escape.go:126
    //   for i < len(s) { c := s[i]; i++;
    //       if 'a'<=c<='z' || 'A'<=c<='Z' || '0'<=c<='9' { continue }
    //       if c != ';' { i-- }
    //       break
    //   }
    let mut i: int = 1;
    while i < s_len {
        let c = b[(src + i) as usize];
        i += 1;
        if (c >= b'a' && c <= b'z') || (c >= b'A' && c <= b'Z') || (c >= b'0' && c <= b'9') {
            continue;
        }
        if c != b';' {
            i -= 1;
        }
        break;
    }

    // Go: escape.go:139 — entityName := s[1:i]
    let from = (src + 1) as usize;
    let to = (src + i) as usize;
    // Snapshot the candidate name so the borrow-checker lets us mutate b.
    let name_buf: Vec<byte> = b[from..to].to_vec();

    if name_buf.is_empty() {
        // Go: escape.go:140 — no-op, fall through to literal copy.
    } else {
        // Go: escape.go:143 — else if x := entity[string(entityName)]; x != 0
        let x = entity_lookup(&name_buf);
        if x != 0 {
            // Go: escape.go:144 — return dst+utf8.EncodeRune(b[dst:], x), src+i
            let mut tmp = [0u8; 4];
            let n = utf8::EncodeRune(&mut tmp, x) as usize;
            for k in 0..n {
                b[dst as usize + k] = tmp[k];
            }
            return (dst + n as int, src + i);
        }
        // Go: escape.go:145 — else if x := entity2[string(entityName)]; x[0] != 0
        if let Some((r1, r2)) = entity2_lookup(&name_buf) {
            let mut tmp = [0u8; 4];
            let n1 = utf8::EncodeRune(&mut tmp, r1) as usize;
            for k in 0..n1 {
                b[dst as usize + k] = tmp[k];
            }
            let d1 = dst + n1 as int;
            let n2 = utf8::EncodeRune(&mut tmp, r2) as usize;
            for k in 0..n2 {
                b[d1 as usize + k] = tmp[k];
            }
            return (d1 + n2 as int, src + i);
        }
        // Go: escape.go:148-155 — the LONGEST-PREFIX walk. A name with
        // no trailing semicolon can still match a shorter entity, which
        // is why "&notreal;" decodes to "\u{ac}real;": `&not` matches
        // and the rest is left alone. Only names in the
        // without-semicolon set can do this, hence the length cap.
        let mut max_len = name_buf.len() - 1;
        if max_len > entity::longestEntityWithoutSemicolon {
            max_len = entity::longestEntityWithoutSemicolon;
        }
        let mut j = max_len;
        while j > 1 {
            let x = entity_lookup(&name_buf[..j]);
            if x != 0 {
                let mut tmp = [0u8; 4];
                let n = utf8::EncodeRune(&mut tmp, x) as usize;
                for k in 0..n {
                    b[dst as usize + k] = tmp[k];
                }
                return (dst + n as int, src + j as int + 1);
            }
            j -= 1;
        }
    }

    // Go: escape.go:161 — copy literal "&...". dst1, src1 = dst+i, src+i
    let dst1 = dst + i;
    let src1 = src + i;
    // Go: escape.go:162 — copy(b[dst:dst1], b[src:src1])
    for k in 0..i {
        b[(dst + k) as usize] = b[(src + k) as usize];
    }
    (dst1, src1)
}

// Go: escape.go:166
//   var htmlEscaper = strings.NewReplacer(
//       `&`, "&amp;",
//       `'`, "&#39;",
//       `<`, "&lt;",
//       `>`, "&gt;",
//       `"`, "&#34;",
//   )
fn htmlEscaper() -> strings::Replacer {
    let v: alloc::vec::Vec<string> = alloc::vec![
        string::from_static("&"),
        string::from_static("&amp;"),
        string::from_static("'"),
        string::from_static("&#39;"),
        string::from_static("<"),
        string::from_static("&lt;"),
        string::from_static(">"),
        string::from_static("&gt;"),
        string::from_static("\""),
        string::from_static("&#34;"),
    ];
    strings::NewReplacer(slice::__from_vec(v))
}

// Go: escape.go:178
//   func EscapeString(s string) string {
//       return htmlEscaper.Replace(s)
//   }
/// `html.EscapeString` — escapes `<`, `>`, `&`, `'` and `"`. The
/// inverse is [`UnescapeString`] (which also recognises numeric
/// character references).
pub fn EscapeString<S: Into<string>>(s: S) -> string {
    let s: string = s.into();
    htmlEscaper().Replace(s)
}

// Go: escape.go:187
//   func UnescapeString(s string) string {
//       i := strings.IndexByte(s, '&')
//       if i < 0 { return s }
//       b := []byte(s)
//       entity, entity2 := entityMaps()
//       dst, src := unescapeEntity(b, i, i, entity, entity2)
//       for len(s[src:]) > 0 { ... }
//       return string(b[:dst])
//   }
/// `html.UnescapeString` — inverse of [`EscapeString`], plus every
/// numeric character reference (`&#NN;`, `&#xNN;`) and the full HTML5
/// named-entity table.
pub fn UnescapeString<S: Into<string>>(s: S) -> string {
    let s: string = s.into();
    // Go: escape.go:188 — i := strings.IndexByte(s, '&')
    let i = strings::IndexByte(s.clone(), b'&');

    // Go: escape.go:190 — if i < 0 { return s }
    if i < 0 {
        return s;
    }

    // Go: escape.go:194 — b := []byte(s)
    let mut b: Vec<byte> = bytes_of(&s);

    // Go: escape.go:196 — dst, src := unescapeEntity(b, i, i, entity, entity2)
    let (mut dst, mut src) = unescapeEntity(&mut b, i, i);

    let total = b.len() as int;

    // Go: escape.go:197 — for len(s[src:]) > 0 { ... }
    while src < total {
        // Go: escape.go:198 — if s[src] == '&' { i = 0 } else { i = strings.IndexByte(s[src:], '&') }
        let mut j: int;
        if b[src as usize] == b'&' {
            j = 0;
        } else {
            // Inline IndexByte over the remaining slice.
            j = -1;
            let mut k: int = src;
            while k < total {
                if b[k as usize] == b'&' {
                    j = k - src;
                    break;
                }
                k += 1;
            }
        }
        // Go: escape.go:203 — if i < 0 { dst += copy(b[dst:], s[src:]); break }
        if j < 0 {
            // Copy the rest verbatim.
            let n = total - src;
            for k in 0..n {
                b[(dst + k) as usize] = b[(src + k) as usize];
            }
            dst += n;
            break;
        }

        // Go: escape.go:208 — if i > 0 { copy(b[dst:], s[src:src+i]) }
        if j > 0 {
            for k in 0..j {
                b[(dst + k) as usize] = b[(src + k) as usize];
            }
        }
        // Go: escape.go:211 — dst, src = unescapeEntity(b, dst+i, src+i, ...)
        let (d, s_new) = unescapeEntity(&mut b, dst + j, src + j);
        dst = d;
        src = s_new;
    }

    // Go: escape.go:213 — return string(b[:dst])
    b.truncate(dst as usize);
    string_from_bytes(b)
}

// ─── helpers ─────────────────────────────────────────────────────────

fn bytes_of(s: &string) -> Vec<byte> {
    let mut v: Vec<byte> = Vec::with_capacity(s.Len() as usize);
    let n = s.Len();
    let mut k: int = 0;
    while k < n {
        v.push(s[k]);
        k += 1;
    }
    v
}

fn string_from_bytes(v: Vec<byte>) -> string {
    string::from_bytes(&v)
}
