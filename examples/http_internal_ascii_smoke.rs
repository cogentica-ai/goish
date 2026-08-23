// http_internal_ascii_smoke — exercise net/http/internal/ascii
// (EqualFold + IsPrint + Is + ToLower; print.go:14/36/46/56).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::net::http::internal::ascii;
use goish::string;
use goish::syscall;

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. EqualFold same length, mixed case.
    {
        if ascii::EqualFold(string("Content-Type"), string("CONTENT-TYPE"))
            && ascii::EqualFold(string("HoSt"), string("host"))
        {
            fmt::Println!("[ 1] EqualFold mixed case      PASS");
        } else {
            fmt::Println!("[ 1] EqualFold mixed case      FAIL");
            failed += 1;
        }
    }

    // 2. EqualFold different length → false.
    {
        if !ascii::EqualFold(string("abc"), string("abcd")) {
            fmt::Println!("[ 2] EqualFold len mismatch    PASS");
        } else {
            fmt::Println!("[ 2] EqualFold len mismatch    FAIL");
            failed += 1;
        }
    }

    // 3. EqualFold ASCII-only — non-ASCII bytes do NOT fold.
    //    Latin-1 'À' (0xC0) lower-equivalent in Unicode is 'à' (0xE0 in
    //    Latin-1, but UTF-8 'à' is two bytes 0xC3 0xA0). Either way, the
    //    ASCII fast path treats both halves as opaque bytes — they only
    //    match if the bytes are byte-equal, which they aren't here.
    {
        if !ascii::EqualFold(string("À"), string("à")) {
            fmt::Println!("[ 3] EqualFold ASCII-only      PASS");
        } else {
            fmt::Println!("[ 3] EqualFold ASCII-only      FAIL");
            failed += 1;
        }
    }

    // 4. EqualFold equal strings → true.
    {
        if ascii::EqualFold(string("hello"), string("hello"))
            && ascii::EqualFold(string(""), string(""))
        {
            fmt::Println!("[ 4] EqualFold equal           PASS");
        } else {
            fmt::Println!("[ 4] EqualFold equal           FAIL");
            failed += 1;
        }
    }

    // 5. IsPrint accepts space..tilde.
    {
        if ascii::IsPrint(string(" "))
            && ascii::IsPrint(string("~"))
            && ascii::IsPrint(string("Hello, World!"))
            && ascii::IsPrint(string(""))
        {
            fmt::Println!("[ 5] IsPrint printable         PASS");
        } else {
            fmt::Println!("[ 5] IsPrint printable         FAIL");
            failed += 1;
        }
    }

    // 6. IsPrint rejects control + DEL + non-ASCII.
    {
        if !ascii::IsPrint(string("\u{0001}"))      // SOH
            && !ascii::IsPrint(string("\u{007F}"))   // DEL
            && !ascii::IsPrint(string("\u{0080}"))   // first non-ASCII byte
            && !ascii::IsPrint(string("a\nb"))
        // embedded newline
        {
            fmt::Println!("[ 6] IsPrint rejects ctrl      PASS");
        } else {
            fmt::Println!("[ 6] IsPrint rejects ctrl      FAIL");
            failed += 1;
        }
    }

    // 7. Is accepts ASCII <= 0x7F including controls, rejects > 0x7F.
    {
        if ascii::Is(string("\u{0000}\u{0001}\u{007F}abc"))
            && !ascii::Is(string("\u{0080}"))
            && !ascii::Is(string("héllo"))
        // 'é' is >0x7F bytes
        {
            fmt::Println!("[ 7] Is ASCII boundary         PASS");
        } else {
            fmt::Println!("[ 7] Is ASCII boundary         FAIL");
            failed += 1;
        }
    }

    // 8. ToLower returns lowered + true on printable ASCII.
    {
        let (lo, ok) = ascii::ToLower(string("Content-Type"));
        if ok && lo == string("content-type") {
            fmt::Println!("[ 8] ToLower printable         PASS");
        } else {
            fmt::Println!("[ 8] ToLower printable         FAIL");
            failed += 1;
        }
    }

    // 9. ToLower returns "" + false on non-printable.
    {
        let (lo, ok) = ascii::ToLower(string("héllo"));
        if !ok && lo == string("") {
            fmt::Println!("[ 9] ToLower non-printable     PASS");
        } else {
            fmt::Println!("[ 9] ToLower non-printable     FAIL");
            failed += 1;
        }
    }

    // 10. ToLower handles empty + already-lower inputs.
    {
        let (a, oka) = ascii::ToLower(string(""));
        let (b, okb) = ascii::ToLower(string("already-lower"));
        if oka && a == string("") && okb && b == string("already-lower") {
            fmt::Println!("[10] ToLower edge inputs       PASS");
        } else {
            fmt::Println!("[10] ToLower edge inputs       FAIL");
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
