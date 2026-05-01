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
