// go: package net/url
//
// net/url — Go's `net/url` package, ported to goish.

#![allow(non_snake_case)]

#[path = "url.rs"]
mod url_go;
pub use url_go::*;
