// runtime::symbolize::demangle — Rust legacy (Itanium-style) demangler.
//
// Format:
//   _ZN<len><name><len><name>...17h<16-hex-hash>E
//
// Example:
//   _ZN21segv_diagnostic_smoke8overflow17heb8894ecc1139a35E
//     → segv_diagnostic_smoke::overflow
//
// Special escapes (Rust legacy mangling, see rustc_codegen_utils):
//   $u20$ → ' '   $u22$ → '"'   $u27$ → '\''  $u24$ → '$'
//   $u3c$ → '<'   $u3e$ → '>'   $u7b$ → '{'   $u7d$ → '}'
//   $u5b$ → '['   $u5d$ → ']'   $u3a$ → ':'   $u2c$ → ','
//   $C$   → ','   $SP$  → '@'   $BP$  → '*'   $RF$  → '&'
//   $LT$  → '<'   $GT$  → '>'   $LP$  → '('   $RP$  → ')'
//   ..    → '::'  .     → '-'
//
// Output is written into a caller-supplied buffer to avoid allocation
// in the SIGSEGV handler. Returns the number of bytes written, or 0 if
// the input doesn't look like a Rust mangled symbol (in which case the
// caller falls back to printing the raw symbol).

const HASH_LEN: usize = 17; // "17h" + 16 hex chars

/// Demangle `sym` into `out`. Returns the number of bytes written, or
/// 0 if `sym` is not a Rust legacy mangled symbol.
pub fn demangle(sym: &[u8], out: &mut [u8]) -> usize {
    // Must start with `_ZN` and end with `E`.
    if sym.len() < 5 || &sym[0..3] != b"_ZN" || sym[sym.len() - 1] != b'E' {
        return 0;
    }
    let mut i = 3usize;
    let end = sym.len() - 1;
    let mut o = 0usize;
    let mut first_segment = true;

    while i < end {
        // Read length prefix.
        let (len, after) = match read_decimal(sym, i) {
            Some(v) => v,
            None => return 0,
        };
        i = after;
        if i + len > end {
            return 0;
        }
        let segment = &sym[i..i + len];
        i += len;

        // Skip the trailing hash segment. The length prefix (always
        // 17) was already consumed; the segment itself is "h<16 hex>"
        // (17 bytes total) and is always the last one before `E`.
        if i == end && len == HASH_LEN && segment[0] == b'h' {
            break;
        }

        if !first_segment {
            if !push(out, &mut o, b"::") {
                return 0;
            }
        }
        first_segment = false;
        if !decode_segment(segment, out, &mut o) {
            return 0;
        }
    }
    o
}

fn read_decimal(s: &[u8], mut i: usize) -> Option<(usize, usize)> {
    let mut n = 0usize;
    let mut any = false;
    while i < s.len() && (s[i] as char).is_ascii_digit() {
        n = n.checked_mul(10)?.checked_add((s[i] - b'0') as usize)?;
        i += 1;
        any = true;
    }
    if !any {
        return None;
    }
    Some((n, i))
}

fn decode_segment(seg: &[u8], out: &mut [u8], o: &mut usize) -> bool {
    let mut i = 0usize;
    // Strip a leading `_` placeholder used by rustc when a segment
    // would otherwise start with a `$` escape (impl-block style:
    // `_$LT$...`, `_$u7b$$u7b$closure$u7d$$u7d$`). The underscore is
    // there only so the length-prefixed segment doesn't conflict
    // with the digit-prefix length scheme.
    if seg.len() >= 2 && seg[0] == b'_' && seg[1] == b'$' {
        i = 1;
    }
    while i < seg.len() {
        if seg[i] == b'$' {
            // Find the closing `$`.
            let start = i + 1;
            let mut end = start;
            while end < seg.len() && seg[end] != b'$' {
                end += 1;
            }
            if end >= seg.len() {
                return false;
            }
            let esc = &seg[start..end];
            i = end + 1;
            let replacement: &[u8] = match esc {
                b"SP" => b"@",
                b"BP" => b"*",
                b"RF" => b"&",
                b"LT" => b"<",
                b"GT" => b">",
                b"LP" => b"(",
                b"RP" => b")",
                b"C" => b",",
                _ => {
                    // $u<hex>$ form — Unicode codepoint. We only handle
                    // ASCII (single byte), which covers everything Rust
                    // mangling actually emits.
                    if esc.len() >= 2 && esc[0] == b'u' {
                        let hex = &esc[1..];
                        match parse_hex(hex) {
                            Some(cp) if cp <= 0x7f => {
                                let b = [cp as u8];
                                if !push(out, o, &b) {
                                    return false;
                                }
                                continue;
                            }
                            _ => return false,
                        }
                    } else {
                        return false;
                    }
                }
            };
            if !push(out, o, replacement) {
                return false;
            }
        } else if seg[i] == b'.' {
            // `..` → `::` (Rust namespace separator, escaped to avoid
            // colliding with C++ `::`). Single `.` is left as-is —
            // rustc legacy mangling does not transform it.
            if i + 1 < seg.len() && seg[i + 1] == b'.' {
                if !push(out, o, b"::") {
                    return false;
                }
                i += 2;
            } else {
                if *o >= out.len() {
                    return false;
                }
                out[*o] = b'.';
                *o += 1;
                i += 1;
            }
        } else {
            if *o >= out.len() {
                return false;
            }
            out[*o] = seg[i];
            *o += 1;
            i += 1;
        }
    }
    true
}

fn parse_hex(s: &[u8]) -> Option<u32> {
    let mut v: u32 = 0;
    if s.is_empty() {
        return None;
    }
    for &b in s {
        let d = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return None,
        };
        v = v.checked_mul(16)?.checked_add(d as u32)?;
    }
    Some(v)
}

fn push(out: &mut [u8], o: &mut usize, src: &[u8]) -> bool {
    if *o + src.len() > out.len() {
        return false;
    }
    out[*o..*o + src.len()].copy_from_slice(src);
    *o += src.len();
    true
}
