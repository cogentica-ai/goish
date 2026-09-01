// go: file mime/type.go decls: TypeByExtension, ExtensionsByType, AddExtensionType, set_extension_type
// goishlint:ignore GOISH018 loadMimeFile, loadMimeGlobsFile, setMimeTypes, initMime, initMimeForTests, initMimeUnix, clearSyncMap — Go walks the system MIME databases (/etc/mime.types, the freedesktop glob files) and caches the result in a sync.Map. goish ships a fixed table instead, so there is no file to load and no cache to clear; `set_extension_type` below is the one piece of `setExtensionType` that a table needs.
// goishlint:ignore GOISH021 mimeTypes, mimeTypesLower, extensions, builtinTypesLower, once, errPhrase, testInitMime, typeFiles, initMimeUnixTest, osInitMime — the same: Go's mutable registry and its lazy-init state, replaced by a fixed table.
//
// type.go — TypeByExtension, ExtensionsByType, AddExtensionType, and
// the fixed table behind them.

extern crate alloc;

use crate::string;
use crate::strings;

pub mod grammar;
pub mod mediatype;

pub use mediatype::{ErrInvalidMediaParameter, FormatMediaType, ParseMediaType};

// go: sdk 1.25.5 mime/type.go:104-135 TypeByExtension
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
    return string::new();
}

// go: sdk 1.25.5 mime/type.go:141-155 ExtensionsByType
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
    return (crate::goslice::slice::__from_vec(out), crate::errors::nil);
}

// go: sdk 1.25.5 mime/type.go:160-166 AddExtensionType
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
    return set_extension_type(ext, typ);
}

// go: sdk 1.25.5 mime/type.go:168-195 setExtensionType
/// Go's `setExtensionType`, under Rust casing.
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
    return crate::errors::nil;
}

// go: none — goish idiom: the process-wide overrides `AddExtensionType`
//     writes into. Go keeps its registry in two `sync.Map`s built by
//     `initMime`; goish has a fixed table plus this.
fn mime_overrides() -> &'static crate::sync::Mutex<Option<crate::gomap::map<string, string>>> {
    static OVERRIDES: crate::sync::Mutex<Option<crate::gomap::map<string, string>>> =
        crate::sync::Mutex::new(None);
    return &OVERRIDES;
}

// go: none — goish idiom: the fixed table that stands in for Go's
//     `initMime` plus the system MIME databases it reads.
fn builtin_table() -> &'static [(&'static str, &'static str)] {
    // Keys sorted; values match Go's standard built-in table where
    // shipping (mime/type.go:initMime + extensions table).
    return &[
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
    ];
}
