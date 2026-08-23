// mime_extensions_smoke — exercise mime.ExtensionsByType + AddExtensionType.
// (mime/type.go)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::mime;
use goish::types::int;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. ExtensionsByType for image/jpeg should return [.jpeg, .jpg] (sorted).
    {
        let (exts, err) = mime::ExtensionsByType(string("image/jpeg"));
        let n = exts.Len() as int;
        if err.IsNil() && n == 2 && exts[0i64] == string(".jpeg") && exts[1i64] == string(".jpg") {
            fmt::Println!("[ 1] ExtByType image/jpeg    PASS");
        } else {
            fmt::Println!("[ 1] ExtByType image/jpeg    FAIL n={}", n);
            failed += 1;
        }
    }

    // 2. ExtensionsByType for text/html (charset stripped on lookup).
    {
        let (exts, err) = mime::ExtensionsByType(string("text/html"));
        let n = exts.Len() as int;
        if err.IsNil() && n == 2 && exts[0i64] == string(".htm") && exts[1i64] == string(".html") {
            fmt::Println!("[ 2] ExtByType text/html     PASS");
        } else {
            fmt::Println!("[ 2] ExtByType text/html     FAIL n={}", n);
            failed += 1;
        }
    }

    // 3. ExtensionsByType for text/html with charset param: still matches.
    {
        let (exts, err) = mime::ExtensionsByType(string("text/html; charset=utf-8"));
        let n = exts.Len() as int;
        if err.IsNil() && n == 2 {
            fmt::Println!("[ 3] ExtByType w/ charset    PASS");
        } else {
            fmt::Println!("[ 3] ExtByType w/ charset    FAIL n={}", n);
            failed += 1;
        }
    }

    // 4. ExtensionsByType for unknown type → empty + nil error.
    {
        let (exts, err) = mime::ExtensionsByType(string("application/x-unknown-foo"));
        if err.IsNil() && exts.Len() == 0 {
            fmt::Println!("[ 4] ExtByType unknown       PASS");
        } else {
            fmt::Println!("[ 4] ExtByType unknown       FAIL");
            failed += 1;
        }
    }

    // 5. ExtensionsByType for invalid type → error.
    {
        let (_exts, err) = mime::ExtensionsByType(string("not a media type"));
        if !err.IsNil() {
            fmt::Println!("[ 5] ExtByType invalid       PASS");
        } else {
            fmt::Println!("[ 5] ExtByType invalid       FAIL");
            failed += 1;
        }
    }

    // 6. AddExtensionType: register a new extension and look it up.
    {
        let err = mime::AddExtensionType(string(".myext"), string("application/x-myext"));
        if !err.IsNil() {
            fmt::Println!("[ 6] Add new ext             FAIL err={}", err.Error());
            failed += 1;
        } else {
            let got = mime::TypeByExtension(string(".myext"));
            if got == string("application/x-myext") {
                fmt::Println!("[ 6] Add new ext             PASS");
            } else {
                fmt::Println!("[ 6] Add new ext             FAIL got {}", got);
                failed += 1;
            }
        }
    }

    // 7. AddExtensionType missing leading dot → error.
    {
        let err = mime::AddExtensionType(string("noLeadingDot"), string("text/plain"));
        if !err.IsNil() {
            fmt::Println!("[ 7] Add no leading dot      PASS");
        } else {
            fmt::Println!("[ 7] Add no leading dot      FAIL");
            failed += 1;
        }
    }

    // 8. AddExtensionType for text/* without charset auto-adds charset=utf-8.
    {
        let _ = mime::AddExtensionType(string(".mytxt"), string("text/x-my"));
        let got = mime::TypeByExtension(string(".mytxt"));
        // Should contain "charset=utf-8" because text/*.
        if goish::strings::Contains(got.clone(), string("charset=utf-8")) {
            fmt::Println!("[ 8] Add text/* + charset    PASS");
        } else {
            fmt::Println!("[ 8] Add text/* + charset    FAIL got {}", got);
            failed += 1;
        }
    }

    // 9. Registered ext flows through ExtensionsByType too.
    {
        let _ = mime::AddExtensionType(string(".myext2"), string("application/x-myext2"));
        let (exts, err) = mime::ExtensionsByType(string("application/x-myext2"));
        let n = exts.Len() as int;
        if err.IsNil() && n >= 1 && exts[0i64] == string(".myext2") {
            fmt::Println!("[ 9] Add flows to ExtByType  PASS");
        } else {
            fmt::Println!("[ 9] Add flows to ExtByType  FAIL n={}", n);
            failed += 1;
        }
    }

    // 10. TypeByExtension still works for builtin entries (regression).
    {
        let got = mime::TypeByExtension(string(".png"));
        if got == string("image/png") {
            fmt::Println!("[10] Builtin .png            PASS");
        } else {
            fmt::Println!("[10] Builtin .png            FAIL got {}", got);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 10");
        syscall::Exit(1);
    }
}
