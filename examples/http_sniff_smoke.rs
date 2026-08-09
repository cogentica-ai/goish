// http_sniff_smoke — exercise http.DetectContentType on common formats.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::goslice::slice;
use goish::net::http;
use goish::{syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // (input bytes, expected mime)
    let cases: [(&'static [u8], &'static str); 14] = [
        (b"<!DOCTYPE HTML>\n", "text/html; charset=utf-8"),
        (b"<html>", "text/html; charset=utf-8"),
        (b"   <head>", "text/html; charset=utf-8"),
        (b"<?xml version=\"1.0\"?>", "text/xml; charset=utf-8"),
        (b"%PDF-1.4", "application/pdf"),
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xff\xd8\xff\xe0", "image/jpeg"),
        (b"GIF89a", "image/gif"),
        (b"BM\x00\x00\x00\x00", "image/bmp"),
        (b"PK\x03\x04", "application/zip"),
        (b"\x1f\x8b\x08\x00", "application/x-gzip"),
        (b"\x00asm\x01\x00\x00\x00", "application/wasm"),
        (b"hello world\n", "text/plain; charset=utf-8"),
        (b"\x00\x01\x02\x03\x04\x05garbage", "application/octet-stream"),
    ];

    for (i, (data, want)) in cases.iter().enumerate() {
        let s = slice::<u8>::__from_vec(data.to_vec());
        let got = http::DetectContentType(s);
        if got == *want {
            fmt::Println!("[{:2}] {} → {}", i, *want, got);
        } else {
            fmt::Println!(
                "[{:2}] FAIL want={:?} got={}",
                i, *want, got
            );
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok sniff smoke");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {}", failed);
        syscall::Exit(1);
    }
}
