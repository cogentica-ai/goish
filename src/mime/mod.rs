// mime — Go's `mime` package, ported (slim).
//
// Currently provides TypeByExtension(ext) — the bedrock helper for
// http.FileServer / http.ServeFile. The full Go implementation walks
// system MIME databases (/etc/mime.types) and an OS-specific cache;
// goish v1 ships a fixed lookup table covering the formats that
// http.DetectContentType also covers, plus common text formats that
// the WhatWG sniff algorithm wouldn't catch (CSS, JS, JSON, etc.).
//
// Reference: /nix/store/.../mime/type.go and /etc/mime.types.

#![no_std]
#![allow(non_snake_case)]

extern crate alloc;

use crate::string;
use crate::strings;

/// `mime.FormatMediaType(t, param)` (mediatype.go:21) — serialize the
/// media type `t` and its parameters as a Content-Type / Content-
/// Disposition value. Returns `""` if any input violates the RFC 2045
/// token grammar.
///
/// Slim port: skips RFC 2231 percent-encoding for non-ASCII parameter
/// values (paired with the matching slim ParseMediaType). Values that
/// would need encoding are emitted as quoted strings instead.
pub fn FormatMediaType(t: string, param: crate::gomap::map<string, string>) -> string {
    let mut b = strings::Builder::new();

    // Go: if major, sub, ok := strings.Cut(t, "/"); !ok { ... } else { ... }
    let (major, sub, ok) = strings::Cut(t.clone(), string("/"));
    if !ok {
        // Go: if !isToken(t) { return "" }
        if !is_token(t.clone()) {
            return string::new();
        }
        let _ = b.WriteString(strings::ToLower(t));
    } else {
        if !is_token(major.clone()) || !is_token(sub.clone()) {
            return string::new();
        }
        let _ = b.WriteString(strings::ToLower(major));
        let _ = b.WriteByte(b'/');
        let _ = b.WriteString(strings::ToLower(sub));
    }

    // Go: for _, attribute := range slices.Sorted(maps.Keys(param))
    let keys = param.Keys();
    let mut i: crate::types::int = 0;
    while i < keys.Len() {
        let attribute = keys[i].clone();
        let (value, _) = param.Get(attribute.clone());
        let _ = b.WriteByte(b';');
        let _ = b.WriteByte(b' ');
        if !is_token(attribute.clone()) {
            return string::new();
        }
        let _ = b.WriteString(strings::ToLower(attribute));
        let _ = b.WriteByte(b'=');

        // Go: if isToken(value) { b.WriteString(value); continue }
        if is_token(value.clone()) {
            let _ = b.WriteString(value);
            i += 1;
            continue;
        }
        // Go: quoted-string with backslash-escape for '"' and '\'.
        let _ = b.WriteByte(b'"');
        let bs = value.as_bytes();
        let mut j: usize = 0;
        while j < bs.len() {
            let c = bs[j];
            if c == b'"' || c == b'\\' {
                let _ = b.WriteByte(b'\\');
            }
            let _ = b.WriteByte(c);
            j += 1;
        }
        let _ = b.WriteByte(b'"');
        i += 1;
    }
    b.String()
}

/// `mime/grammar.go:75` `isToken(s)` — whole-string variant.
fn is_token(s: string) -> bool {
    if s.Len() == 0 {
        return false;
    }
    let bs = s.as_bytes();
    let mut i: usize = 0;
    while i < bs.len() {
        if !is_token_char(bs[i]) {
            return false;
        }
        i += 1;
    }
    true
}

/// `mime.ErrInvalidMediaParameter` (mediatype.go:122) — sentinel
/// returned by ParseMediaType when the optional parameters are
/// malformed.
pub fn ErrInvalidMediaParameter() -> crate::errors::error {
    use crate::runtime::spin::SpinLock;
    static SLOT: SpinLock<Option<crate::errors::error>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(crate::errors::New(string("mime: invalid media parameter")));
    }
    g.as_ref().unwrap().clone()
}

/// `mime.ParseMediaType(v)` (mediatype.go:134) — parse a Content-Type
/// or Content-Disposition value into `(mediatype, params, err)`.
///
/// Slim port: drops RFC 2231 parameter continuations (`name*0`,
/// `name*`) since they're rarely seen on the wire and add ~80 LOC of
/// charset+percent-decode logic. Otherwise mirrors Go's behavior:
///   - mediatype is lowercased and trimmed.
///   - param keys are lowercased; values keep case.
///   - Quoted values are unescaped (handles `\"` etc.).
///   - Duplicate parameter keys with conflicting values → error.
pub fn ParseMediaType(
    v: string,
) -> (
    string,
    crate::gomap::map<string, string>,
    crate::errors::error,
) {
    // Go: base, _, _ := strings.Cut(v, ";")
    let (base, _, _) = strings::Cut(v.clone(), string(";"));
    // Go: mediatype = strings.TrimSpace(strings.ToLower(base))
    let mediatype = strings::TrimSpace(strings::ToLower(base.clone()));

    // Go: err = checkMediaTypeDisposition(mediatype)
    if let Err(e) = check_media_type_disposition(mediatype.clone()) {
        return (
            string::new(),
            crate::gomap::map::<string, string>::new(),
            e,
        );
    }

    let mut params: crate::gomap::map<string, string> = crate::gomap::map::new();
    // Go: v = v[len(base):]
    let mut v = string::from_bytes(&v.as_bytes()[base.Len() as usize..]);
    while v.Len() > 0 {
        // Go: v = strings.TrimLeftFunc(v, unicode.IsSpace)
        v = trim_left_ascii_space(v);
        if v.Len() == 0 {
            break;
        }
        let (key, value, rest) = consume_media_param(v.clone());
        if key.Len() == 0 {
            // Go: if strings.TrimSpace(rest) == ";" { break }  // trailing semicolons OK
            if strings::TrimSpace(rest) == ";" {
                break;
            }
            return (
                mediatype,
                crate::gomap::map::<string, string>::new(),
                ErrInvalidMediaParameter(),
            );
        }
        // Go: if v, exists := pmap[key]; exists && v != value { duplicate err }
        let (existing, ok) = params.Get(key.clone());
        if ok && existing != value {
            return (
                string::new(),
                crate::gomap::map::<string, string>::new(),
                crate::errors::New(string("mime: duplicate parameter name")),
            );
        }
        params.Set(key, value);
        v = rest;
    }
    (mediatype, params, crate::errors::nil)
}

/// Line-by-line port of `checkMediaTypeDisposition` (mediatype.go:98).
fn check_media_type_disposition(s: string) -> Result<(), crate::errors::error> {
    let (typ, rest) = consume_token(s);
    if typ.Len() == 0 {
        return Err(crate::errors::New(string("mime: no media type")));
    }
    if rest.Len() == 0 {
        return Ok(());
    }
    if !strings::HasPrefix(rest.clone(), string("/")) {
        return Err(crate::errors::New(string(
            "mime: expected slash after first token",
        )));
    }
    let after_slash = string::from_bytes(&rest.as_bytes()[1..]);
    let (subtype, rest2) = consume_token(after_slash);
    if subtype.Len() == 0 {
        return Err(crate::errors::New(string(
            "mime: expected token after slash",
        )));
    }
    if rest2.Len() != 0 {
        return Err(crate::errors::New(string(
            "mime: unexpected content after media subtype",
        )));
    }
    Ok(())
}

/// Line-by-line port of `consumeToken` (mediatype.go:257).
fn consume_token(v: string) -> (string, string) {
    let bs = v.as_bytes();
    let mut i: usize = 0;
    while i < bs.len() {
        if !is_token_char(bs[i]) {
            return (
                string::from_bytes(&bs[..i]),
                string::from_bytes(&bs[i..]),
            );
        }
        i += 1;
    }
    (v, string::new())
}

/// Line-by-line port of `consumeValue` (mediatype.go:271).
fn consume_value(v: string) -> (string, string) {
    if v.Len() == 0 {
        return (string::new(), v);
    }
    let bs = v.as_bytes();
    if bs[0] != b'"' {
        return consume_token(v);
    }
    let mut buf = strings::Builder::new();
    let mut i: usize = 1;
    while i < bs.len() {
        let r = bs[i];
        if r == b'"' {
            return (buf.String(), string::from_bytes(&bs[i + 1..]));
        }
        if r == b'\\' && i + 1 < bs.len() && is_tspecial(bs[i + 1]) {
            let _ = buf.WriteByte(bs[i + 1]);
            i += 2;
            continue;
        }
        if r == b'\r' || r == b'\n' {
            return (string::new(), v);
        }
        let _ = buf.WriteByte(r);
        i += 1;
    }
    (string::new(), v)
}

/// Line-by-line port of `consumeMediaParam` (mediatype.go:310).
fn consume_media_param(v: string) -> (string, string, string) {
    let rest = trim_left_ascii_space(v.clone());
    if !strings::HasPrefix(rest.clone(), string(";")) {
        return (string::new(), string::new(), v);
    }
    let rest = string::from_bytes(&rest.as_bytes()[1..]);
    let rest = trim_left_ascii_space(rest);
    let (param, rest) = consume_token(rest);
    let param = strings::ToLower(param);
    if param.Len() == 0 {
        return (string::new(), string::new(), v);
    }
    let rest = trim_left_ascii_space(rest);
    if !strings::HasPrefix(rest.clone(), string("=")) {
        return (string::new(), string::new(), v);
    }
    let rest = string::from_bytes(&rest.as_bytes()[1..]);
    let rest = trim_left_ascii_space(rest);
    let (value, rest) = consume_value(rest);
    (param, value, rest)
}

fn trim_left_ascii_space(s: string) -> string {
    let bs = s.as_bytes();
    let mut i: usize = 0;
    while i < bs.len() {
        let c = bs[i];
        if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' || c == 0x0b || c == 0x0c {
            i += 1;
        } else {
            break;
        }
    }
    if i == 0 {
        return s;
    }
    string::from_bytes(&bs[i..])
}

/// `isTokenChar` (grammar.go:40).
fn is_token_char(c: u8) -> bool {
    if c >= 0x80 {
        return false;
    }
    if c <= b' ' || c == 0x7f {
        return false;
    }
    !is_tspecial(c)
}

/// `isTSpecial` (grammar.go:9).
fn is_tspecial(c: u8) -> bool {
    matches!(
        c,
        b'(' | b')' | b'<' | b'>' | b'@' | b',' | b';' | b':' | b'\\' | b'"' | b'/' | b'[' | b']' | b'?' | b'='
    )
}

/// `mime.TypeByExtension(ext)` — look up the MIME type for a file
/// extension. `ext` should begin with a dot (e.g. `".html"`); ASCII
/// case is ignored. Returns the empty string if no entry is known.
pub fn TypeByExtension(ext: string) -> string {
    if ext.Len() == 0 {
        return string::new();
    }
    let lowered = strings::ToLower(ext);
    let table = builtin_table();
    for (k, v) in table {
        if lowered == *k {
            return string(*v);
        }
    }
    string::new()
}

fn builtin_table() -> &'static [(&'static str, &'static str)] {
    // Keys sorted; values match Go's standard built-in table where
    // shipping (mime/type.go:initMime + extensions table).
    &[
        (".bmp", "image/bmp"),
        (".css", "text/css; charset=utf-8"),
        (".csv", "text/csv; charset=utf-8"),
        (".gif", "image/gif"),
        (".gz", "application/gzip"),
        (".htm", "text/html; charset=utf-8"),
        (".html", "text/html; charset=utf-8"),
        (".ico", "image/x-icon"),
        (".jpeg", "image/jpeg"),
        (".jpg", "image/jpeg"),
        (".js", "text/javascript; charset=utf-8"),
        (".json", "application/json"),
        (".manifest", "text/cache-manifest"),
        (".md", "text/markdown; charset=utf-8"),
        (".mjs", "text/javascript; charset=utf-8"),
        (".mp3", "audio/mpeg"),
        (".mp4", "video/mp4"),
        (".otf", "font/otf"),
        (".pdf", "application/pdf"),
        (".png", "image/png"),
        (".svg", "image/svg+xml"),
        (".tar", "application/x-tar"),
        (".tif", "image/tiff"),
        (".tiff", "image/tiff"),
        (".ttf", "font/ttf"),
        (".txt", "text/plain; charset=utf-8"),
        (".wasm", "application/wasm"),
        (".wav", "audio/wave"),
        (".webm", "video/webm"),
        (".webp", "image/webp"),
        (".woff", "font/woff"),
        (".woff2", "font/woff2"),
        (".xhtml", "application/xhtml+xml"),
        (".xml", "text/xml; charset=utf-8"),
        (".zip", "application/zip"),
    ]
}
