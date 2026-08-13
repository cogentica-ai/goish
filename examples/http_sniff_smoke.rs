// http_sniff_smoke — exercise http.DetectContentType (net/http/sniff.go).
//
// The cases below walk Go's sniffSignatures table. Two groups earn
// their place beyond "the common formats work":
//
//   * The ORDER-sensitive ones. textSig matches almost any printable
//     input and Go's table comment says it "should be last", so a
//     signature accidentally placed after it would be unreachable —
//     case 15 is text that also begins with a real signature.
//   * The signature that was MISSING. goish's table had been flattened
//     into an if-chain, and the 34-NULL-bytes-then-"LP" entry for
//     application/vnd.ms-fontobject was simply not in it, so an
//     embedded OpenType font sniffed as application/octet-stream —
//     case 16, and case 17 for the near-miss that must NOT match.
//
// Output uses goish's fmt, which reads Go verbs; the previous version
// of this file used Rust's `{}` and printed the braces literally, so
// every line came out as "[{:2}] {} → {}" and a failure would have been
// just as unreadable as a pass.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::goslice::slice;
use goish::net::http;
use goish::syscall;

/// 34 NUL bytes then "LP" — Go's application/vnd.ms-fontobject pattern.
const EOT: &[u8] = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00LP\x00\x00";

/// The same 36 bytes with the "LP" replaced. The mask is all-zero for
/// the first 34 bytes, so ONLY those two bytes decide the match; if
/// they were ignored this would sniff as a font too.
const EOT_NEAR_MISS: &[u8] = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00XY\x00\x00";

#[goish::main]
fn main() {
    let mut failed = 0;

    // (input bytes, expected mime)
    let cases: [(&'static [u8], &'static str); 18] = [
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
        // Masked signatures whose mask has DON'T-CARE bytes in the
        // middle: "RIFF????WAVE". A matcher that compared the pattern
        // straight through would reject these.
        (b"RIFFxxxxWAVEmore", "audio/wave"),
        (b"RIFFxxxxWEBPVPmore", "image/webp"),
        // The signature that had gone missing, and its near miss.
        (EOT, "application/vnd.ms-fontobject"),
        (EOT_NEAR_MISS, "application/octet-stream"),
    ];

    let mut i = 0;
    for (data, want) in cases.iter() {
        let s = slice::<u8>::__from_vec(data.to_vec());
        let got = http::DetectContentType(s);
        if got == *want {
            fmt::Println!("[", i, "] ok  ", got);
        } else {
            fmt::Println!("[", i, "] FAIL want=", *want, " got=", got);
            failed += 1;
        }
        i += 1;
    }

    if failed == 0 {
        fmt::Println!("ok 18/18");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 18");
        syscall::Exit(1);
    }
}
