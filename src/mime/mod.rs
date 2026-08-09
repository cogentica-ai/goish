// mime — Go's `mime` package, ported (slim).
//
// Currently provides TypeByExtension(ext) — the bedrock helper for
// http.FileServer / http.ServeFile. The full Go implementation walks
// system MIME databases (/etc/mime.types) and an OS-specific cache;
// goish v1 ships a fixed lookup table covering the formats that
// http.DetectContentType also covers, plus common text formats that
// the WhatWG sniff algorithm wouldn't catch (CSS, JS, JSON, etc.).
//
// Reference: go1.25.5/src/mime/type.go and /etc/mime.types.

#![allow(non_snake_case)]

extern crate alloc;

pub mod encodedword;
pub mod multipart;
pub mod quotedprintable;

pub use encodedword::{BEncoding, QEncoding, WordDecoder, WordEncoder};

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
pub fn FormatMediaType<T: Into<string>>(t: T, param: crate::gomap::map<string, string>) -> string {
    let t: string = t.into();
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
pub fn ErrInvalidMediaParameter() -> crate::error {
    use crate::runtime::spin::SpinLock;
    static SLOT: SpinLock<Option<crate::error>> = SpinLock::new(None);
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
pub fn ParseMediaType<V: Into<string>>(v: V) -> (
    string,
    crate::gomap::map<string, string>,
    crate::error,
) {
    let v: string = v.into();
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
fn check_media_type_disposition(s: string) -> Result<(), crate::error> {
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
pub fn TypeByExtension<E: Into<string>>(ext: E) -> string {
    let ext: string = ext.into();
    if ext.Len() == 0 {
        return string::new();
    }
    // Go: case-sensitive lookup first, then case-insensitive.
    // Goish slim: check runtime overrides first (case-sensitive then
    // case-insensitive), then fall back to the static builtin (which
    // is already lowercase).
    {
        let guard = mime_overrides().Lock();
        if let Some(map) = guard.as_ref() {
            let (v, ok) = map.Get(ext.clone());
            if ok {
                return v;
            }
            let (v_lower, ok2) = map.Get(strings::ToLower(ext.clone()));
            if ok2 {
                return v_lower;
            }
        }
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

/// `mime.ExtensionsByType(typ)` (type.go:141) — return the file
/// extensions known to be associated with the MIME type `typ`. The
/// returned slice is sorted ascending. Returns `(nil, nil)` if `typ`
/// has no associated extensions; returns `("", err)` if `typ` is not
/// a valid media type.
pub fn ExtensionsByType<T: Into<string>>(typ: T) -> (crate::goslice::slice<string>, crate::error) {
    let typ: string = typ.into();
    // Go: justType, _, err := ParseMediaType(typ)
    let (just_type, _, err) = ParseMediaType(typ);
    if !err.IsNil() {
        return (
            crate::goslice::slice::__from_vec(alloc::vec::Vec::new()),
            err,
        );
    }

    // Go: collect from static table (lowercase keys) plus runtime overrides.
    let mut out: alloc::vec::Vec<string> = alloc::vec::Vec::new();
    let seen = |out: &alloc::vec::Vec<string>, e: &string| -> bool {
        for v in out.iter() {
            if v == e {
                return true;
            }
        }
        false
    };

    for (k, v) in builtin_table() {
        let (vt, _, vt_err) = ParseMediaType(string(*v));
        if vt_err.IsNil() && strings::EqualFold(vt, just_type.clone()) {
            let e = string(*k);
            if !seen(&out, &e) {
                out.push(e);
            }
        }
    }
    {
        let guard = mime_overrides().Lock();
        if let Some(map) = guard.as_ref() {
            for (k, v) in map.__iter() {
                let (vt, _, vt_err) = ParseMediaType(v.clone());
                if vt_err.IsNil() && strings::EqualFold(vt, just_type.clone()) {
                    // Only count case-insensitive (lowercase) registrations
                    // to avoid duplicating an ext present under both cases.
                    let lowered = strings::ToLower(k.clone());
                    if !seen(&out, &lowered) {
                        out.push(lowered);
                    }
                }
            }
        }
    }

    // Go: slices.Sort(ret)
    out.sort();
    (
        crate::goslice::slice::__from_vec(out),
        crate::errors::nil,
    )
}

/// `mime.AddExtensionType(ext, typ)` (type.go:160) — register the
/// MIME type `typ` for file extension `ext`. `ext` must begin with
/// a leading dot. For text/* types without an explicit charset
/// parameter, `charset=utf-8` is added automatically.
pub fn AddExtensionType<E: Into<string>, T: Into<string>>(ext: E, typ: T) -> crate::error {
    let ext: string = ext.into();
    let typ: string = typ.into();
    // Go: if !strings.HasPrefix(ext, ".") { return fmt.Errorf(...) }
    if !strings::HasPrefix(ext.clone(), string(".")) {
        let mut msg: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(48 + ext.Len() as usize);
        msg.extend_from_slice(b"mime: extension \"");
        msg.extend_from_slice(ext.as_bytes());
        msg.extend_from_slice(b"\" missing leading dot");
        return crate::errors::New(string::from_bytes(&msg));
    }
    set_extension_type(ext, typ)
}

/// `setExtensionType(extension, mimeType)` (type.go:168).
fn set_extension_type(extension: string, mut mime_type: string) -> crate::error {
    // Go: justType, param, err := ParseMediaType(mimeType)
    let (just_type, mut param, err) = ParseMediaType(mime_type.clone());
    if !err.IsNil() {
        return err;
    }
    // Go: if strings.HasPrefix(mimeType, "text/") && param["charset"] == "" {
    //         param["charset"] = "utf-8"; mimeType = FormatMediaType(mimeType, param) }
    if strings::HasPrefix(mime_type.clone(), string("text/")) {
        let (charset, has_charset) = param.Get(string("charset"));
        if !has_charset || charset.Len() == 0 {
            param.Set(string("charset"), string("utf-8"));
            mime_type = FormatMediaType(just_type.clone(), param);
        }
    }
    let ext_lower = strings::ToLower(extension.clone());

    let mut guard = mime_overrides().Lock();
    if guard.is_none() {
        *guard = Some(crate::gomap::map::new());
    }
    if let Some(map) = guard.as_mut() {
        // Go: mimeTypes.Store(extension, mimeType); mimeTypesLower.Store(extLower, mimeType)
        map.Set(extension, mime_type.clone());
        map.Set(ext_lower, mime_type);
    }
    crate::errors::nil
}

fn mime_overrides() -> &'static crate::sync::Mutex<Option<crate::gomap::map<string, string>>> {
    static OVERRIDES: crate::sync::Mutex<Option<crate::gomap::map<string, string>>> =
        crate::sync::Mutex::new(None);
    &OVERRIDES
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
