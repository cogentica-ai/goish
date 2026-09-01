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

#[path = "type.rs"]
mod type_go;
pub use type_go::*;
