// base64_encoding_smoke — exercise encoding/base64's Encoding type.
// (encoding/base64/base64.go)
//
// Every expectation here was printed by a running Go 1.25.5
// (tools/gen_base64_ref.go, run through scripts/goref.sh).
//
// The four package encodings differ only in alphabet and padding, so
// check 1 walks all four over nine inputs including non-ASCII bytes and
// the URL-safe alphabet's `-_` substitutions. Check 2 builds an
// Encoding with a custom alphabet *and* a custom padding character,
// which is what NewEncoding and WithPadding exist for. Checks 3 and 4
// are the decoder: every awkward case lives in decodeQuantum, and the
// error offsets are as much a part of the contract as the bytes.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::encoding::base64;
use goish::fmt;
use goish::goslice::slice;
use goish::types::byte;
use goish::{string, syscall};

fn eq(a: &slice<byte>, b: &[u8]) -> bool {
    let raw: &[byte] = a;
    raw == b
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. EncodeToString for all four package encodings.
    {
        let cases: [(&base64::Encoding, &[u8], &[u8]); 36] = [
            (&base64::StdEncoding, b"", b""),
            (&base64::StdEncoding, b"f", b"Zg=="),
            (&base64::StdEncoding, b"fo", b"Zm8="),
            (&base64::StdEncoding, b"foo", b"Zm9v"),
            (&base64::StdEncoding, b"foob", b"Zm9vYg=="),
            (&base64::StdEncoding, b"fooba", b"Zm9vYmE="),
            (&base64::StdEncoding, b"foobar", b"Zm9vYmFy"),
            (&base64::StdEncoding, b"\x00\xff\xfe\x01", b"AP/+AQ=="),
            (&base64::StdEncoding, b"sure.~?", b"c3VyZS5+Pw=="),
            (&base64::URLEncoding, b"", b""),
            (&base64::URLEncoding, b"f", b"Zg=="),
            (&base64::URLEncoding, b"fo", b"Zm8="),
            (&base64::URLEncoding, b"foo", b"Zm9v"),
            (&base64::URLEncoding, b"foob", b"Zm9vYg=="),
            (&base64::URLEncoding, b"fooba", b"Zm9vYmE="),
            (&base64::URLEncoding, b"foobar", b"Zm9vYmFy"),
            (&base64::URLEncoding, b"\x00\xff\xfe\x01", b"AP_-AQ=="),
            (&base64::URLEncoding, b"sure.~?", b"c3VyZS5-Pw=="),
            (&base64::RawStdEncoding, b"", b""),
            (&base64::RawStdEncoding, b"f", b"Zg"),
            (&base64::RawStdEncoding, b"fo", b"Zm8"),
            (&base64::RawStdEncoding, b"foo", b"Zm9v"),
            (&base64::RawStdEncoding, b"foob", b"Zm9vYg"),
            (&base64::RawStdEncoding, b"fooba", b"Zm9vYmE"),
            (&base64::RawStdEncoding, b"foobar", b"Zm9vYmFy"),
            (&base64::RawStdEncoding, b"\x00\xff\xfe\x01", b"AP/+AQ"),
            (&base64::RawStdEncoding, b"sure.~?", b"c3VyZS5+Pw"),
            (&base64::RawURLEncoding, b"", b""),
            (&base64::RawURLEncoding, b"f", b"Zg"),
            (&base64::RawURLEncoding, b"fo", b"Zm8"),
            (&base64::RawURLEncoding, b"foo", b"Zm9v"),
            (&base64::RawURLEncoding, b"foob", b"Zm9vYg"),
            (&base64::RawURLEncoding, b"fooba", b"Zm9vYmE"),
            (&base64::RawURLEncoding, b"foobar", b"Zm9vYmFy"),
            (&base64::RawURLEncoding, b"\x00\xff\xfe\x01", b"AP_-AQ"),
            (&base64::RawURLEncoding, b"sure.~?", b"c3VyZS5-Pw"),
        ];
        let mut bad = 0;
        let mut k: usize = 0;
        while k < cases.len() {
            let (enc, input, want) = cases[k];
            let got = enc.EncodeToString(input);
            if got.as_bytes() != want {
                bad += 1;
            }
            k += 1;
        }
        if bad == 0 {
            fmt::Println!("[ 1] EncodeToString x4 vs Go  PASS");
        } else {
            fmt::Println!("[ 1] EncodeToString x4 vs Go  FAIL");
            failed += 1;
        }
    }

    // 2. A custom alphabet with a custom padding character, and a
    //    round trip through it. Neither NewEncoding nor WithPadding
    //    existed before this port.
    {
        let c =
            base64::NewEncoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_")
                .WithPadding('@' as goish::types::rune);
        let enc = c.EncodeToString(b"foobar!");
        let (dec, err) = c.DecodeString(enc.clone());
        if enc.as_bytes() == b"PczlOc5o8G@@" && err == goish::nil && eq(&dec, b"foobar!") {
            fmt::Println!("[ 2] NewEncoding/WithPadding  PASS");
        } else {
            fmt::Println!("[ 2] NewEncoding/WithPadding  FAIL");
            failed += 1;
        }
    }

    // 3. The decoder, including its error offsets. Newlines are
    //    skipped mid-quantum; padding must be complete; anything after
    //    the padding is trailing garbage; and a padded encoding
    //    rejects input that simply stops early.
    {
        let cases: [(&base64::Encoding, &[u8], &[u8], &str); 14] = [
            (&base64::StdEncoding, b"Zm9vYmFy", b"foobar", "<nil>"),
            (
                &base64::StdEncoding,
                b"Zm9v\x0aYmFy\x0a",
                b"foobar",
                "<nil>",
            ),
            (
                &base64::StdEncoding,
                b"Zm9v\x0d\x0aYmFy",
                b"foobar",
                "<nil>",
            ),
            (&base64::StdEncoding, b"Zm9vYmE=", b"fooba", "<nil>"),
            (&base64::StdEncoding, b"Zm9vYg==", b"foob", "<nil>"),
            (
                &base64::StdEncoding,
                b"Zm9vYg=",
                b"foo",
                "illegal base64 data at input byte 7",
            ),
            (
                &base64::StdEncoding,
                b"Zm9vYg",
                b"foo",
                "illegal base64 data at input byte 4",
            ),
            (
                &base64::StdEncoding,
                b"Zm9vYg==X",
                b"foob",
                "illegal base64 data at input byte 8",
            ),
            (
                &base64::StdEncoding,
                b"Zm9v*mFy",
                b"foo",
                "illegal base64 data at input byte 4",
            ),
            (
                &base64::StdEncoding,
                b"Z",
                b"",
                "illegal base64 data at input byte 0",
            ),
            (&base64::RawStdEncoding, b"Zm9vYg", b"foob", "<nil>"),
            (
                &base64::RawStdEncoding,
                b"Zm9vYg==",
                b"foo",
                "illegal base64 data at input byte 6",
            ),
            (&base64::StdEncoding, b"aGk=", b"hi", "<nil>"),
            (&base64::StdEncoding, b"aGl=", b"hi", "<nil>"),
        ];
        let mut bad = 0;
        let mut k: usize = 0;
        while k < cases.len() {
            let (enc, input, want, werr) = cases[k];
            let (got, err) = enc.DecodeString(string::from_bytes(input));
            let goterr = if err == goish::nil {
                string("<nil>")
            } else {
                err.Error()
            };
            if !eq(&got, want) || goterr != werr {
                bad += 1;
            }
            k += 1;
        }
        if bad == 0 {
            fmt::Println!("[ 3] Decode + offsets vs Go   PASS");
        } else {
            fmt::Println!("[ 3] Decode + offsets vs Go   FAIL");
            failed += 1;
        }
    }

    // 4. Strict mode. "aGk=" and "aGl=" both decode to "hi" normally,
    //    because the discarded low bits of the last byte are ignored;
    //    strict decoding requires them to be zero, so the second is
    //    rejected. Nothing else distinguishes the two inputs.
    {
        let strict = base64::StdEncoding.Strict();
        let (a, ea) = strict.DecodeString(string("aGk="));
        let (b, eb) = strict.DecodeString(string("aGl="));
        let (c, ec) = base64::StdEncoding.DecodeString(string("aGl="));
        if ea == goish::nil
            && eq(&a, b"hi")
            && !eb.IsNil()
            && eb.Error() == "illegal base64 data at input byte 3"
            && b.Len() == 0
            && ec == goish::nil
            && eq(&c, b"hi")
        {
            fmt::Println!("[ 4] Strict mode vs Go        PASS");
        } else {
            fmt::Println!("[ 4] Strict mode vs Go        FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 4");
        syscall::Exit(1);
    }
}
