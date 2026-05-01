// strings_bytes_totitle_smoke — exercise strings.ToTitle (strings.go:768)
// and bytes.ToTitle (bytes.go:757). Both are Map(unicode.ToTitle, s).
// Slim ASCII path: ToTitle == ToUpper for ASCII letters.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::convert::bytes as to_bytes;
use goish::strings;
use goish::string;
use goish::{syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. strings.ToTitle — basic ASCII letters titled to upper.
    {
        let out = strings::ToTitle(string("hello, world!"));
        if out == string("HELLO, WORLD!") {
            Println!("[ 1] strings.ToTitle ASCII     PASS");
        } else {
            Println!("[ 1] strings.ToTitle ASCII     FAIL");
            failed += 1;
        }
    }

    // 2. strings.ToTitle — already-upper passes through.
    {
        let out = strings::ToTitle(string("ALREADY UPPER"));
        if out == string("ALREADY UPPER") {
            Println!("[ 2] strings.ToTitle upper     PASS");
        } else {
            Println!("[ 2] strings.ToTitle upper     FAIL");
            failed += 1;
        }
    }

    // 3. strings.ToTitle — empty string.
    {
        let out = strings::ToTitle(string(""));
        if out == string("") {
            Println!("[ 3] strings.ToTitle empty     PASS");
        } else {
            Println!("[ 3] strings.ToTitle empty     FAIL");
            failed += 1;
        }
    }

    // 4. strings.ToTitle — digits / punct unchanged.
    {
        let out = strings::ToTitle(string("123 !@#"));
        if out == string("123 !@#") {
            Println!("[ 4] strings.ToTitle non-alpha PASS");
        } else {
            Println!("[ 4] strings.ToTitle non-alpha FAIL");
            failed += 1;
        }
    }

    // 5. bytes.ToTitle — basic ASCII bytes titled to upper.
    {
        let out = bytes::ToTitle(to_bytes("hello"));
        let want = to_bytes("HELLO");
        if bytes::Equal(out, want) {
            Println!("[ 5] bytes.ToTitle ASCII       PASS");
        } else {
            Println!("[ 5] bytes.ToTitle ASCII       FAIL");
            failed += 1;
        }
    }

    // 6. bytes.ToTitle — empty slice.
    {
        let out = bytes::ToTitle(to_bytes(""));
        let want = to_bytes("");
        if bytes::Equal(out, want) {
            Println!("[ 6] bytes.ToTitle empty       PASS");
        } else {
            Println!("[ 6] bytes.ToTitle empty       FAIL");
            failed += 1;
        }
    }

    // 7. bytes.ToTitle — mixed-case mapped to upper.
    {
        let out = bytes::ToTitle(to_bytes("MixedCase 123"));
        let want = to_bytes("MIXEDCASE 123");
        if bytes::Equal(out, want) {
            Println!("[ 7] bytes.ToTitle mixed       PASS");
        } else {
            Println!("[ 7] bytes.ToTitle mixed       FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 7");
        syscall::Exit(1);
    }
}
